#pragma once

#include "aowis/network/wireguard_client.h"

#include <QByteArray>
#include <QNetworkRequest>
#include <QObject>
#include <QString>
#include <QUrl>

#include <memory>

class QNetworkAccessManager;
class QNetworkReply;
class QIODevice;

namespace aowis::network {

// Per-server, fail-closed Qt HTTP transport for the authenticated SOCKS5
// listener exposed by WireGuardClient::proxy(). It does NOT start a tunnel.
// The manager is private so callers cannot accidentally change its proxy,
// enable automatic cross-origin redirects, or reuse it for direct requests.
//
// Create after WireGuardClient::start() and destroy before stopping/restarting
// the tunnel. Recreate when SOCKS credentials/port change. Qt objects must be
// used from their owning thread.
class QtSocks5HttpClient final : public QObject {
public:
    QtSocks5HttpClient(const Socks5Proxy& proxy, const QUrl& serverEndpoint,
                       QObject* parent = nullptr);
    ~QtSocks5HttpClient() override;

    QtSocks5HttpClient(const QtSocks5HttpClient&) = delete;
    QtSocks5HttpClient& operator=(const QtSocks5HttpClient&) = delete;

    bool isConfigured() const;
    QString configurationError() const;
    bool permits(const QUrl& url) const;

    QNetworkReply* get(const QNetworkRequest& request);
    QNetworkReply* head(const QNetworkRequest& request);
    QNetworkReply* post(const QNetworkRequest& request, const QByteArray& data);
    QNetworkReply* post(const QNetworkRequest& request, QIODevice* data);
    QNetworkReply* put(const QNetworkRequest& request, const QByteArray& data);
    QNetworkReply* put(const QNetworkRequest& request, QIODevice* data);
    QNetworkReply* deleteResource(const QNetworkRequest& request);
    QNetworkReply* sendCustomRequest(const QNetworkRequest& request,
                                     const QByteArray& verb,
                                     const QByteArray& data = {});

private:
    QNetworkRequest checkedRequest(const QNetworkRequest& request) const;
    QNetworkReply* rejected(const QNetworkRequest& request);

    std::unique_ptr<QNetworkAccessManager> manager_;
    QString scheme_;
    QString host_;
    int port_ = 0;
    QString error_;
};

} // namespace aowis::network
