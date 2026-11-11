#include "aowis/network/qt_http_client.h"
#include "aowis/network/wireguard_client.h"
#include "aowis/network/wireguard_conf.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkReply>
#include <QProcess>
#include <QTimer>

#include <cstdio>
#include <stdexcept>
#include <string>

using aowis::network::QtSocks5HttpClient;
using aowis::network::WireGuardClient;
using aowis::network::WireGuardConfig;

namespace {

void require(bool condition, const char* message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

struct HttpResult {
    QNetworkReply::NetworkError error = QNetworkReply::UnknownNetworkError;
    int status = 0;
    QByteArray body;
    bool timedOut = false;
};

HttpResult receive(QNetworkReply* reply, int timeoutMs)
{
    require(reply != nullptr, "Qt adapter returned a null reply");
    HttpResult result;
    if (!reply->isFinished()) {
        QEventLoop loop;
        QTimer timeout;
        timeout.setSingleShot(true);
        QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
        QObject::connect(&timeout, &QTimer::timeout, &loop, [&]() {
            result.timedOut = true;
            reply->abort();
            loop.quit();
        });
        timeout.start(timeoutMs);
        loop.exec();
    }
    result.error = reply->error();
    result.status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    result.body = reply->readAll();
    reply->deleteLater();
    return result;
}

QJsonObject startTestPeer(QProcess& process, const QString& executable)
{
    process.setProgram(executable);
    process.setProcessChannelMode(QProcess::SeparateChannels);
    process.start();
    require(process.waitForStarted(10000), "Could not start test-only WireGuard peer");
    QElapsedTimer timer;
    timer.start();
    QByteArray output = process.readAllStandardOutput();
    while (!output.contains('\n') && timer.elapsed() < 15000) {
        const int remaining = 15000 - static_cast<int>(timer.elapsed());
        require(process.waitForReadyRead(remaining), "WireGuard peer did not report readiness");
        output += process.readAllStandardOutput();
    }
    require(output.contains('\n'), "Incomplete test peer readiness message");
    QJsonParseError parseError;
    const QJsonDocument data = QJsonDocument::fromJson(output.left(output.indexOf('\n')), &parseError);
    require(parseError.error == QJsonParseError::NoError && data.isObject(),
            "Invalid JSON from test peer");
    const QJsonObject ready = data.object();
    require(!ready.value(QStringLiteral("endpoint")).toString().isEmpty()
            && !ready.value(QStringLiteral("server_public_key")).toString().isEmpty()
            && !ready.value(QStringLiteral("client_private_key")).toString().isEmpty(),
            "Test peer returned incomplete WireGuard configuration");
    return ready;
}

void testFullStack(const QString& testPeerExecutable)
{
    QProcess peer;
    const QJsonObject ready = startTestPeer(peer, testPeerExecutable);

    // Go through the real .conf parser, as the GUI does, so the parser's
    // output is proven against the actual engine and not only in isolation.
    const std::string conf =
        "[Interface]\n"
        "PrivateKey = " + ready.value(QStringLiteral("client_private_key")).toString().toStdString() + "\n"
        "Address = 10.173.91.2/32\n"
        "[Peer]\n"
        "PublicKey = " + ready.value(QStringLiteral("server_public_key")).toString().toStdString() + "\n"
        "Endpoint = " + ready.value(QStringLiteral("endpoint")).toString().toStdString() + "\n"
        "AllowedIPs = 10.173.91.1/32\n"
        "PersistentKeepalive = 0\n";
    const aowis::network::WireGuardConfParse parsed = aowis::network::parseWireGuardConf(conf);
    require(parsed.ok(), "Generated test profile rejected by parseWireGuardConf()");
    const WireGuardConfig config = parsed.config;

    const QUrl origin(QStringLiteral("http://10.173.91.1:18080"));
    const QNetworkRequest getRequest(QUrl(QStringLiteral("http://10.173.91.1:18080/probe")));
    const QNetworkRequest postRequest(QUrl(QStringLiteral("http://10.173.91.1:18080/post")));
    std::string error;
    WireGuardClient tunnel;
    require(tunnel.start(config, &error), "Embedded C++/Go WireGuard startup failed");
    require(tunnel.isRunning() && tunnel.proxy().port != 0,
            "Embedded tunnel did not create an authenticated local proxy");
    const aowis::network::Socks5Proxy initialProxy = tunnel.proxy();

    {
        QtSocks5HttpClient http(tunnel.proxy(), origin);
        require(http.isConfigured(), "Qt adapter rejected the private WireGuard service endpoint");

        const HttpResult get = receive(http.get(getRequest), 12000);
        require(!get.timedOut && get.error == QNetworkReply::NoError && get.status == 200
                && get.body == "aowis-qt-wireguard-e2e",
                "Qt GET failed across C++ ABI, Go WireGuard and remote gVisor HTTP");

        const HttpResult post = receive(http.post(postRequest, QByteArray("aowis-post-test")), 5000);
        require(!post.timedOut && post.error == QNetworkReply::NoError && post.status == 200
                && post.body == "posted-via-wireguard",
                "Qt POST failed across real encrypted tunnel");

        aowis::network::WireGuardPeerStats stats;
        require(tunnel.peerStats(&stats, &error), "Failed to read live peer counters from C++ ABI");
        require(stats.lastHandshakeUnixSeconds > 0 && stats.receivedBytes > 0
                && stats.transmittedBytes > 0 && !stats.endpoint.empty(),
                "Peer statistics were empty after encrypted HTTP traffic");

        const HttpResult forbidden = receive(http.get(QNetworkRequest(
            QUrl(QStringLiteral("http://127.0.0.1:18080/probe")))), 1000);
        require(forbidden.error == QNetworkReply::ContentAccessDenied,
                "Qt service-origin guard permitted a loopback proxy bypass");
    }
    tunnel.stop();
    require(!tunnel.isRunning(), "Stopped WireGuard tunnel still reports running");
    aowis::network::WireGuardPeerStats stoppedStats;
    require(!tunnel.peerStats(&stoppedStats, &error), "Stopped tunnel reported live peer statistics");


    // A stale proxy configuration must fail, not become a direct host route.
    {
        QtSocks5HttpClient stale(initialProxy, origin);
        const HttpResult stopped = receive(stale.get(getRequest), 2500);
        require(stopped.error != QNetworkReply::NoError,
                "Stopped tunnel unexpectedly sent HTTP over a direct connection");
    }

    // The client may start with an incorrect peer key, but no HTTP connection
    // may succeed; this uses a fresh instance and independent SOCKS5 proxy.
    WireGuardConfig wrongKey = config;
    wrongKey.peerPublicKey[0] = wrongKey.peerPublicKey[0] == 'A' ? 'B' : 'A';
    WireGuardClient invalidPeer;
    require(invalidPeer.start(wrongKey, &error), "Wrong-key tunnel should initialize locally");
    {
        QtSocks5HttpClient invalidHttp(invalidPeer.proxy(), origin);
        require(invalidHttp.isConfigured(), "Wrong-key Qt adapter could not be configured");
        const HttpResult rejected = receive(invalidHttp.get(getRequest), 1800);
        require(rejected.error != QNetworkReply::NoError,
                "Invalid WireGuard peer public key unexpectedly reached private HTTP");
    }
    invalidPeer.stop();

    // Request graceful shutdown of the test-only peer. There is no kernel VPN
    // interface and no remotely accessible HTTP service to clean up.
    require(peer.write("quit\n") == 5, "Could not send shutdown to test peer");
    peer.closeWriteChannel();
    require(peer.waitForFinished(5000), "Test peer failed to shut down cleanly");
    require(peer.exitStatus() == QProcess::NormalExit && peer.exitCode() == 0,
            "Test peer exited with an error");
}

} // namespace

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    if (argc != 2) {
        std::fprintf(stderr, "Usage: aowis-network-qt-wireguard-tests /path/to/testpeer\n");
        return 2;
    }
    try {
        testFullStack(QString::fromLocal8Bit(argv[1]));
        return 0;
    } catch (const std::exception& exception) {
        std::fprintf(stderr, "Qt-to-WireGuard integration test failed: %s\n", exception.what());
        return 1;
    }
}
