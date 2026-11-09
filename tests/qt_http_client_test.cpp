#include "aowis/network/qt_http_client.h"

#include <QCoreApplication>
#include <QEventLoop>
#include <QHostAddress>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>
#include <QDebug>

#include <cstdlib>

using aowis::network::QtSocks5HttpClient;
using aowis::network::Socks5Proxy;

namespace {

void check(bool condition, const char* description)
{
    if (!condition) {
        qCritical() << "Qt SOCKS5 adapter test failed:" << description;
        std::exit(EXIT_FAILURE);
    }
}

// A tiny deterministic SOCKS5 endpoint. It never opens a TCP connection to
// the requested host, so a successful response proves the Qt request entered
// the authenticated SOCKS5 path, including its proxy-side DNS domain name.
class StubSocks5 final : public QObject {
public:
    StubSocks5()
    {
        QObject::connect(&this->listener_, &QTcpServer::newConnection, this, [this]() {
            while (this->listener_.hasPendingConnections()) {
                QTcpSocket* socket = this->listener_.nextPendingConnection();
                ++this->connections;
                QObject::connect(socket, &QTcpSocket::readyRead, this, [this, socket]() {
                    this->consume(socket);
                });
                QObject::connect(socket, &QTcpSocket::disconnected,
                                 socket, &QTcpSocket::deleteLater);
            }
        });
        check(this->listener_.listen(QHostAddress::LocalHost, 0), "SOCKS listener startup");
    }

    quint16 port() const { return this->listener_.serverPort(); }
    int connections = 0;
    int connectRequests = 0;
    QString lastTarget;
    QByteArray lastHttpRequest;
    bool redirect = false;

private:
    void consume(QTcpSocket* socket)
    {
        // Separate per-socket state is held on Qt properties to support more
        // than one request/connection without a global state machine.
        QByteArray bytes = socket->property("aowis-buffer").toByteArray();
        bytes += socket->readAll();
        int state = socket->property("aowis-state").toInt();
        while (true) {
            if (state == 0) {
                if (bytes.size() < 2) { break; }
                const int methodCount = static_cast<unsigned char>(bytes[1]);
                if (bytes.size() < 2 + methodCount) { break; }
                check(static_cast<unsigned char>(bytes[0]) == 5, "SOCKS greeting version");
                check(bytes.mid(2, methodCount).contains(char(2)), "username/password method offered");
                bytes.remove(0, 2 + methodCount);
                socket->write(QByteArray::fromHex("0502"));
                state = 1;
            } else if (state == 1) {
                if (bytes.size() < 2) { break; }
                const int nameLength = static_cast<unsigned char>(bytes[1]);
                if (bytes.size() < 2 + nameLength + 1) { break; }
                const int passLength = static_cast<unsigned char>(bytes[2 + nameLength]);
                const int length = 3 + nameLength + passLength;
                if (bytes.size() < length) { break; }
                const QByteArray name = bytes.mid(2, nameLength);
                const QByteArray pass = bytes.mid(3 + nameLength, passLength);
                bytes.remove(0, length);
                if (name != "aowis-user" || pass != "aowis-password") {
                    socket->write(QByteArray::fromHex("0101"));
                    socket->disconnectFromHost();
                    state = 4;
                    break;
                }
                socket->write(QByteArray::fromHex("0100"));
                state = 2;
            } else if (state == 2) {
                if (bytes.size() < 5) { break; }
                check(static_cast<unsigned char>(bytes[0]) == 5 &&
                      static_cast<unsigned char>(bytes[1]) == 1, "SOCKS TCP CONNECT");
                const int type = static_cast<unsigned char>(bytes[3]);
                check(type == 3, "SOCKS must pass domain to tunnel DNS, not resolve locally");
                const int nameLength = static_cast<unsigned char>(bytes[4]);
                const int length = 5 + nameLength + 2;
                if (bytes.size() < length) { break; }
                this->lastTarget = QString::fromUtf8(bytes.mid(5, nameLength));
                const int destPort =
                    (static_cast<unsigned char>(bytes[length - 2]) << 8) |
                     static_cast<unsigned char>(bytes[length - 1]);
                check(destPort == 18080, "service port remains fixed");
                ++this->connectRequests;
                bytes.remove(0, length);
                socket->write(QByteArray::fromHex("05000001000000000000"));
                state = 3;
            } else if (state == 3) {
                if (!bytes.contains("\r\n\r\n")) { break; }
                this->lastHttpRequest = bytes;
                bytes.clear();
                if (this->redirect) {
                    socket->write("HTTP/1.1 302 Found\r\n"
                                  "Location: http://outside.invalid/escape\r\n"
                                  "Content-Length: 0\r\nConnection: close\r\n\r\n");
                } else {
                    socket->write("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n"
                                  "Connection: close\r\n\r\nok-qt!!");
                }
                socket->disconnectFromHost();
                state = 4;
                break;
            } else {
                break;
            }
        }
        socket->setProperty("aowis-buffer", bytes);
        socket->setProperty("aowis-state", state);
    }

    QTcpServer listener_;
};

void waitFor(QNetworkReply* reply)
{
    if (!reply->isFinished()) {
        QEventLoop loop;
        QTimer timer;
        timer.setSingleShot(true);
        QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
        QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
        timer.start(8000);
        loop.exec();
    }
    check(reply->isFinished(), "Qt reply completed before timeout");
}

} // namespace

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    StubSocks5 socks;
    Socks5Proxy proxy;
    proxy.port = socks.port();
    proxy.username = "aowis-user";
    proxy.password = "aowis-password";
    const QUrl endpoint(QStringLiteral("http://aowis.private.invalid:18080"));
    QtSocks5HttpClient client(proxy, endpoint);
    check(client.isConfigured(), "valid per-server proxy configuration");

    QNetworkRequest allowed(QUrl(QStringLiteral("http://aowis.private.invalid:18080/probe")));
    allowed.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QNetworkRequest::NoLessSafeRedirectPolicy);
    QNetworkReply* reply = client.get(allowed);
    waitFor(reply);
    check(reply->error() == QNetworkReply::NoError, "SOCKS proxied HTTP GET");
    check(reply->readAll() == "ok-qt!!", "response body via SOCKS5");
    check(socks.lastTarget == "aowis.private.invalid", "remote DNS hostname forwarded");
    check(socks.connectRequests == 1, "proxy received CONNECT");
    reply->deleteLater();

    const int before = socks.connectRequests;
    for (const QString& url : {
             QStringLiteral("http://127.0.0.1:18080/probe"),
             QStringLiteral("http://other.private.invalid:18080/probe"),
             QStringLiteral("https://aowis.private.invalid:18080/probe"),
             QStringLiteral("http://aowis.private.invalid:18081/probe")}) {
        reply = client.get(QNetworkRequest(QUrl(url)));
        waitFor(reply);
        check(reply->error() == QNetworkReply::ContentAccessDenied,
              "cross-origin, loopback, protocol or port requests denied");
        reply->deleteLater();
    }
    check(socks.connectRequests == before, "rejected requests never entered SOCKS5");

    socks.redirect = true;
    reply = client.get(allowed);
    waitFor(reply);
    check(reply->error() == QNetworkReply::NoError, "HTTP redirect returned as response");
    check(reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt() == 302,
          "redirect was not automatically followed");
    check(socks.connectRequests == before + 1, "exactly one request for redirect");
    reply->deleteLater();

    socks.redirect = false;
    reply = client.post(allowed, QByteArray("test"));
    waitFor(reply);
    check(reply->error() == QNetworkReply::NoError, "SOCKS proxied HTTP POST");
    check(socks.lastHttpRequest.startsWith("POST "), "POST method forwarded");
    reply->deleteLater();

    Socks5Proxy wrongCredentials = proxy;
    wrongCredentials.password = "wrong";
    QtSocks5HttpClient rejectedAuthentication(wrongCredentials, endpoint);
    reply = rejectedAuthentication.get(allowed);
    waitFor(reply);
    check(reply->error() != QNetworkReply::NoError, "incorrect SOCKS credentials rejected");
    reply->deleteLater();

    for (const QString& badEndpoint : {
             QStringLiteral("http://localhost:18080"),
             QStringLiteral("http://a.localhost:18080"),
             QStringLiteral("http://localhost.:18080"),
             QStringLiteral("http://2130706433:18080"),
             QStringLiteral("http://127.0.0.2:18080"),
             QStringLiteral("http://[::1]:18080"),
             QStringLiteral("http://0.0.0.0:18080")}) {
        QtSocks5HttpClient denied(proxy, QUrl(badEndpoint));
        check(!denied.isConfigured(), "loopback and wildcard service endpoint denied");
        reply = denied.get(QNetworkRequest(QUrl(badEndpoint)));
        waitFor(reply);
        check(reply->error() == QNetworkReply::ContentAccessDenied,
              "no bypass for loopback endpoint");
        reply->deleteLater();
    }

    Socks5Proxy stopped;
    QtSocks5HttpClient noTunnel(stopped, endpoint);
    check(!noTunnel.isConfigured(), "absent tunnel credentials rejected");
    reply = noTunnel.get(allowed);
    waitFor(reply);
    check(reply->error() == QNetworkReply::ContentAccessDenied,
          "missing tunnel fails closed");
    reply->deleteLater();

    return EXIT_SUCCESS;
}
