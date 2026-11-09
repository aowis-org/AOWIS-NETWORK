#include "aowis/network/qt_http_client.h"

#include <QHostAddress>
#include <QIODevice>
#include <QNetworkAccessManager>
#include <QNetworkProxy>
#include <QNetworkReply>
#include <QTimer>

namespace aowis::network {
namespace {

bool isForbiddenHost(const QString& host)
{
    QString normalized(host);
    if (normalized.endsWith(QLatin1Char('.'))) {
        normalized.chop(1);
    }
    if (normalized.isEmpty() || normalized == QLatin1String("localhost")
        || normalized == QLatin1String("localhost.localdomain")
        || normalized.endsWith(QLatin1String(".localhost"))) {
        return true;
    }
    QHostAddress address;
    if (!address.setAddress(normalized)) {
        // Numeric-looking host strings that Qt does not recognize as IPv4
        // literals must not reach a host resolver that might interpret them
        // as an alternate representation of loopback (e.g. 2130706433).
        bool numericHost = true;
        for (const QChar character : normalized) {
            if (!character.isDigit() && character != QLatin1Char('.')) {
                numericHost = false;
                break;
            }
        }
        return numericHost;
    }
    if (address.isLoopback() || address.isNull()) {
        return true;
    }
    // Reject the whole IPv4 127/8 loopback range, including IPv4-mapped IPv6.
    bool hasIPv4 = false;
    const quint32 ipv4 = address.toIPv4Address(&hasIPv4);
    return hasIPv4 && ((ipv4 & 0xff000000U) == 0x7f000000U || ipv4 == 0);
}

int effectivePort(const QUrl& url)
{
    return url.port(url.scheme() == QLatin1String("https") ? 443 : 80);
}

// An immediately failed QNetworkReply. Signals are emitted asynchronously to
// match QNetworkAccessManager behavior and let callers attach handlers first.
class RejectedReply final : public QNetworkReply {
public:
    RejectedReply(const QNetworkRequest& request, QObject* parent)
        : QNetworkReply(parent)
    {
        this->setRequest(request);
        this->setUrl(request.url());
        this->setOperation(QNetworkAccessManager::UnknownOperation);
        this->open(QIODevice::ReadOnly | QIODevice::Unbuffered);
        this->setError(QNetworkReply::ContentAccessDenied,
                       QStringLiteral("AOWIS-Network rejected the request: destination is not allowed by this tunnel"));
        this->setFinished(true);
        QTimer::singleShot(0, this, [this]() {
            emit this->errorOccurred(this->error());
            emit this->finished();
        });
    }

    void abort() override {}
    bool isSequential() const override { return true; }

protected:
    qint64 readData(char*, qint64) override { return -1; }
};

} // namespace

QtSocks5HttpClient::QtSocks5HttpClient(const Socks5Proxy& proxy,
                                     const QUrl& serverEndpoint,
                                     QObject* parent)
    : QObject(parent), manager_(std::make_unique<QNetworkAccessManager>())
{
    this->scheme_ = serverEndpoint.scheme().toLower();
    this->host_ = serverEndpoint.host().toLower();
    this->port_ = effectivePort(serverEndpoint);

    if (!serverEndpoint.isValid()
        || (this->scheme_ != QLatin1String("http") && this->scheme_ != QLatin1String("https"))
        || isForbiddenHost(this->host_) || this->port_ < 1 || this->port_ > 65535
        || !serverEndpoint.userInfo().isEmpty()) {
        this->error_ = QStringLiteral("Invalid or loopback AOWIS service endpoint");
        return;
    }
    if (proxy.host != "127.0.0.1" || proxy.port == 0
        || proxy.username.empty() || proxy.password.empty()) {
        this->error_ = QStringLiteral("WireGuard's authenticated loopback SOCKS5 proxy is unavailable");
        return;
    }
    QNetworkProxy qtProxy(QNetworkProxy::Socks5Proxy,
                          QStringLiteral("127.0.0.1"), proxy.port,
                          QString::fromStdString(proxy.username),
                          QString::fromStdString(proxy.password));
    // Resolve the target service hostname in the userspace network stack,
    // never using the OS resolver. Only the peer's outer UDP endpoint may
    // require host-side DNS resolution.
    qtProxy.setCapabilities(QNetworkProxy::TunnelingCapability |
                            QNetworkProxy::HostNameLookupCapability);
    this->manager_->setProxy(qtProxy);
    this->manager_->setRedirectPolicy(QNetworkRequest::ManualRedirectPolicy);
}

QtSocks5HttpClient::~QtSocks5HttpClient() = default;

bool QtSocks5HttpClient::isConfigured() const
{
    return this->error_.isEmpty();
}

QString QtSocks5HttpClient::configurationError() const
{
    return this->error_;
}

bool QtSocks5HttpClient::permits(const QUrl& url) const
{
    return this->isConfigured() && url.isValid()
        && url.scheme().toLower() == this->scheme_
        && url.host().toLower() == this->host_
        && effectivePort(url) == this->port_
        && url.userInfo().isEmpty();
}

QNetworkRequest QtSocks5HttpClient::checkedRequest(const QNetworkRequest& request) const
{
    QNetworkRequest safe(request);
    // Qt 6 automatically follows redirects by default. Always force manual
    // redirection so an HTTP 3xx cannot escape the approved server endpoint.
    safe.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                      QNetworkRequest::ManualRedirectPolicy);
    return safe;
}

QNetworkReply* QtSocks5HttpClient::rejected(const QNetworkRequest& request)
{
    return new RejectedReply(request, this);
}

QNetworkReply* QtSocks5HttpClient::get(const QNetworkRequest& request)
{
    if (!this->permits(request.url())) { return this->rejected(request); }
    return this->manager_->get(this->checkedRequest(request));
}

QNetworkReply* QtSocks5HttpClient::head(const QNetworkRequest& request)
{
    if (!this->permits(request.url())) { return this->rejected(request); }
    return this->manager_->head(this->checkedRequest(request));
}

QNetworkReply* QtSocks5HttpClient::post(const QNetworkRequest& request, const QByteArray& data)
{
    if (!this->permits(request.url())) { return this->rejected(request); }
    return this->manager_->post(this->checkedRequest(request), data);
}

QNetworkReply* QtSocks5HttpClient::post(const QNetworkRequest& request, QIODevice* data)
{
    if (!this->permits(request.url())) { return this->rejected(request); }
    return this->manager_->post(this->checkedRequest(request), data);
}

QNetworkReply* QtSocks5HttpClient::put(const QNetworkRequest& request, const QByteArray& data)
{
    if (!this->permits(request.url())) { return this->rejected(request); }
    return this->manager_->put(this->checkedRequest(request), data);
}

QNetworkReply* QtSocks5HttpClient::put(const QNetworkRequest& request, QIODevice* data)
{
    if (!this->permits(request.url())) { return this->rejected(request); }
    return this->manager_->put(this->checkedRequest(request), data);
}

QNetworkReply* QtSocks5HttpClient::deleteResource(const QNetworkRequest& request)
{
    if (!this->permits(request.url())) { return this->rejected(request); }
    return this->manager_->deleteResource(this->checkedRequest(request));
}

QNetworkReply* QtSocks5HttpClient::sendCustomRequest(const QNetworkRequest& request,
                                                     const QByteArray& verb,
                                                     const QByteArray& data)
{
    if (!this->permits(request.url())) { return this->rejected(request); }
    return this->manager_->sendCustomRequest(this->checkedRequest(request), verb, data);
}

} // namespace aowis::network
