#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string>
#include <poll.h>
#include <sys/epoll.h>
#include <signal.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <map>

#include "tun.h"
#include "protocol.h"
#include "cJSON.h"
#include "print.h"
#include "proxy.h"

using namespace std;

#define log(...)             \
    do                       \
    {                        \
        printf(__VA_ARGS__); \
        fflush(stdout);      \
    } while (0)
#define check0(x, ...)        \
    if (x)                    \
        do                    \
        {                     \
            log(__VA_ARGS__); \
            exit(1);          \
    } while (0)
#define check1(x, ...)        \
    if (!x)                   \
        do                    \
        {                     \
            log(__VA_ARGS__); \
            exit(1);          \
    } while (0)

static const int MAX_BUF_LEN = 20480;
static const int MTU = 1500;
static const bool GLOBAL_MODE = false;
static const bool OPEN_PROXY = true;

typedef struct
{
    bool used;
    char vip[64];
} VIP_CONFIG_T;

typedef struct
{
    char ipv4_net[64];
    int netIP;        // 网络地址
    int broadcastIp;  // 广播地址
    int ipCount;      // ip数量
    int sVip;         // 服务端虚拟ip
    int vipPoolStart; // ip池开始地址
    int vipPoolEnd;   // ip池结束地址
    int vipPoolCap;   // ip池容量
} vip_pool;

map<string, SSL *> maps;
map<int, int> proxyMap; // ssl fd <-> proxy fd
map<string, VIP_CONFIG_T *> vipConfMap;

static vip_pool vipPool;

int vipCycleIndex = 0;

BIO *errBio;
SSL_CTX *g_sslCtx;

int epollfd, listenfd;

// 虚拟网卡设备fd
int tunfd;

struct Channel
{
    int fd_;
    SSL *ssl_;
    bool tcpConnected_;
    bool sslConnected_;
    int events_;

    unsigned char buf[4096 + 8];

    /*作为vpn服务端使用*/
    char vip_[64];
    unsigned char *next;
    unsigned int next_len;

    Channel *proxyCh_;
    /*作为vpn服务端使用*/

    /*作为proxy客户端使用*/
    bool isproxy_;
    /*作为proxy客户端使用*/

    Channel(int fd, int events, bool isproxy)
    {
        memset(this, 0, sizeof *this);
        fd_ = fd;
        events_ = events;
        next = NULL;
        next_len = 0;
        memset(vip_, 0, sizeof(vip_));
        isproxy_ = isproxy;
        proxyCh_ = NULL;
    }
    void update()
    {
        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.events = events_;
        ev.data.ptr = this;
        // log("modifying fd %d events read %d write %d\n", fd_, ev.events & EPOLLIN, ev.events & EPOLLOUT);
        int r = epoll_ctl(epollfd, EPOLL_CTL_MOD, fd_, &ev);
        check0(r, "epoll_ctl mod failed %d %s", errno, strerror(errno));
    }
    void setVip(char *vip)
    {
        memcpy(vip_, vip, strlen(vip));
    }
    ~Channel()
    {
        log("deleting fd %d\n", fd_);
        epoll_ctl(epollfd, EPOLL_CTL_DEL, fd_, NULL);
        close(fd_);
        if (ssl_ && !isproxy_) // 代理channel中的ssl复用主服务里的ssl，因此这里需要进行判断，避免重复释放ssl
        {
            log("release ssl: %p\n", ssl_);
            SSL_shutdown(ssl_);
            SSL_free(ssl_);
        }
        if (strlen(vip_) > 0)
        {
            log("释放vip: %s\n", vip_);
            vipConfMap.erase(vip_);
            log("删除SSL记录: %p\n", ssl_);
            maps.erase(vip_);
        }
        if (proxyCh_ != NULL)
        {
            log("删除代理Channel\n");
            epoll_ctl(epollfd, EPOLL_CTL_DEL, proxyCh_->fd_, NULL);
            close(proxyCh_->fd_);
            delete proxyCh_;
            proxyCh_ = NULL;
        }
    }
};

int pushTunConf(Channel *ch);

int setNonBlock(int fd, bool value)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
    {
        return errno;
    }
    if (value)
    {
        return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
    return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

void addEpollFd(int epollfd, Channel *ch)
{
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = ch->events_;
    ev.data.ptr = ch;
    // log("adding fd %d events %d\n", ch->fd_, ev.events);
    int r = epoll_ctl(epollfd, EPOLL_CTL_ADD, ch->fd_, &ev);
    check0(r, "epoll_ctl add failed[%d], %s", errno, strerror(errno));
}

int createServer(short port)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int enable = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
    setNonBlock(fd, 1);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    int r = ::bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr));
    check0(r, "bind to 0.0.0.0:%d failed %d %s", port, errno, strerror(errno));
    r = listen(fd, 20);
    check0(r, "listen failed %d %s", errno, strerror(errno));
    log("create server fd[%d] listening at %d\n", fd, port);
    return fd;
}

void handleAccept()
{
    struct sockaddr_in raddr;
    socklen_t rsz = sizeof(raddr);
    int cfd;
    while ((cfd = accept4(listenfd, (struct sockaddr *)&raddr, &rsz, SOCK_CLOEXEC)) >= 0)
    {
        sockaddr_in peer, local;
        socklen_t alen = sizeof(peer);
        int r = getpeername(cfd, (sockaddr *)&peer, &alen);
        if (r < 0)
        {
            // log("get peer name failed %d %s\n", errno, strerror(errno));
            continue;
        }
        r = getsockname(cfd, (sockaddr *)&local, &alen);
        if (r < 0)
        {
            // log("getsockname failed %d %s\n", errno, strerror(errno));
            continue;
        }
        setNonBlock(cfd, 1);
        Channel *ch = new Channel(cfd, EPOLLIN | EPOLLOUT, false);
        addEpollFd(epollfd, ch);
    }
}

void showClientCerts(SSL *ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL)
    {
        printf("SSL[%p]客户端证书信息:\n", ssl);
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("使用者: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("颁发者: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
    {
        printf("SSL[%p]无证书信息！\n", ssl);
    }
}

void handleHandshake(Channel *ch)
{
    if (!ch->tcpConnected_)
    {
        struct pollfd pfd;
        pfd.fd = ch->fd_;
        pfd.events = POLLOUT | POLLERR;
        int r = poll(&pfd, 1, 0);
        if (r == 1 && pfd.revents == POLLOUT)
        {
            // log("tcp connected fd %d\n", ch->fd_);
            ch->tcpConnected_ = true;
            ch->events_ = EPOLLIN | EPOLLOUT | EPOLLERR;
            ch->update();
        }
        else
        {
            log("poll fd %d return %d revents %d\n", ch->fd_, r, pfd.revents);
            delete ch;
            return;
        }
    }
    if (ch->ssl_ == NULL)
    {
        ch->ssl_ = SSL_new(g_sslCtx);
        check0(ch->ssl_ == NULL, "SSL_new failed");
        int r = SSL_set_fd(ch->ssl_, ch->fd_);
        check0(!r, "SSL_set_fd failed");
        // log("SSL_set_accept_state for fd %d\n", ch->fd_);
        // SSL_enable_ntls(ch->ssl_);
        SSL_set_accept_state(ch->ssl_);
    }
    int r = SSL_do_handshake(ch->ssl_);
    if (r == 1)
    {
        showClientCerts(ch->ssl_);
        ch->sslConnected_ = true;
        log("new ssl: %p\n", ch->ssl_);
        // 建立和上游的tcp连接
        if (OPEN_PROXY)
        {
            int proxyFd = connect_proxy("127.0.0.1", 9112);
            if (proxyFd > 0)
            {
                int fd = SSL_get_fd(ch->ssl_);
                proxyMap.insert(pair<int, int>(fd, proxyFd));
                // 添加到epoll列表中
                Channel *proxyCh = new Channel(proxyFd, EPOLLIN | EPOLLET, true);
                proxyCh->ssl_ = ch->ssl_;
                addEpollFd(epollfd, proxyCh);
                ch->proxyCh_ = proxyCh;
            }
            else
            {
                log("连接代理服务失败: %d\n", proxyFd);
                // TODO
            }
        }

        return;
    }
    int err = SSL_get_error(ch->ssl_, r);
    int oldev = ch->events_;
    if (err == SSL_ERROR_WANT_WRITE)
    {
        ch->events_ |= EPOLLOUT;
        ch->events_ &= ~EPOLLIN;
        // log("return want write set events %d\n", ch->events_);
        if (oldev == ch->events_)
            return;
        ch->update();
    }
    else if (err == SSL_ERROR_WANT_READ)
    {
        ch->events_ |= EPOLLIN;
        ch->events_ &= ~EPOLLOUT;
        // log("return want read set events %d\n", ch->events_);
        if (oldev == ch->events_)
            return;
        ch->update();
    }
    else
    {
        // log("SSL_do_handshake return %d error %d errno %d msg %s\n", r, err, errno, strerror(errno));
        ERR_print_errors(errBio);
        delete ch;
    }
}

void proxyDataRead(Channel *ch)
{
    int readlen = 0;

    readlen = recv(ch->fd_, ch->buf, sizeof(ch->buf), 0);
    if (readlen > 0)
    {
        int writelen = SSL_write(ch->ssl_, ch->buf, readlen);
        if (writelen < readlen)
        {
            log("SSL[%p]写入代理响应数据长度过小 -> proxy resp len: %d, write len: %d\n", ch->ssl_, readlen, writelen);
        }
    }
    else
    {
        log("read proxy data fail: %d\n", readlen);
    }
}

void SslDataRead(Channel *ch)
{
    int ret = 0;
    unsigned char packet[4096];
    unsigned int depack_len = 0;

    if (ch->next == NULL)
    {
        ch->next = ch->buf;
        ch->next_len = 0;
    }
    int len = SSL_read(ch->ssl_, ch->next + ch->next_len, 4096 + HEADER_LEN - ch->next_len);
    int ssle = SSL_get_error(ch->ssl_, len);
    if (len > 0)
    {
        // log("ssl read len: %d\n", len);
        int count = 0;
        // 2、解包处理
        depack_len = sizeof(packet);
        while ((ret = depack(ch->next, len, packet, &depack_len, &ch->next, &ch->next_len)) > 0)
        {
            // log("count: %d, depack data len: %d\n", count, depack_len);
            len = ch->next_len;
            int datalen = depack_len - RECORD_HEADER_LEN;

            // 判定数据类型
            if (memcmp(packet, RECORD_TYPE_DATA, RECORD_TYPE_LABEL_LEN) == 0) // 数据类型
            {
                /* 3、写入到虚拟网卡 */
                int wlen = write(tunfd, packet + RECORD_HEADER_LEN, datalen);
                if (wlen < datalen)
                {
                    log("虚拟网卡写入数据长度小于预期长度, write len: %d, buffer len: %d\n", wlen, len);
                }
            }
            else if (memcmp(packet, RECORD_TYPE_AUTH, RECORD_TYPE_LABEL_LEN) == 0) // 数据类型
            {
                log("客户端认证消息:\n");
                // TODO 判断认证消息类型

                // 认证成功后推送tun配置
                pushTunConf(ch);
            }
            else
            {
                log("未定义协议类型:\n");
                dump_hex(packet, depack_len, 32);
            }

            depack_len = sizeof(packet);
        }
        if (ret < 0)
        {
            log("非vpn协议数据\n");
            dump_hex(ch->next, len, 32);
            log("---------------\n");
            if (OPEN_PROXY)
            {
                // 打开了代理服务，进行转发
                map<int, int>::iterator iter = proxyMap.find(SSL_get_fd(ch->ssl_));
                if (iter == proxyMap.end())
                {
                    log("SSL[%p]未查询到代理链接\n", ch->ssl_);
                    return;
                }
                int proxyFd = iter->second;
                log("SSL[%p] find proxy fd: %d\n", ch->ssl_, proxyFd);
                ret = send(proxyFd, ch->next, len, 0);
                if (ret != len)
                {
                    log("SSL[%p]发送代理数据失败, ret: %d\n", ch->ssl_, ret);
                    return;
                }
                ch->next_len = 0;
            }
        }
        return;
    }
    if (len < 0 && ssle != SSL_ERROR_WANT_READ)
    {
        if (errno != EAGAIN)
        {
            log("SSL_read return %d, error: %d, errno: %d, msg: %s\n", len, ssle, errno, strerror(errno));
            delete ch;
        }
        return;
    }
    if (len == 0)
    {
        if (ssle == SSL_ERROR_ZERO_RETURN)
            log("SSL has been shutdown.\n");
        else
            log("Connection has been aborted.\n");
        delete ch;
    }
}

void handleRead(Channel *ch)
{
    if (ch->fd_ == listenfd)
    {
        return handleAccept();
    }
    if (!ch->isproxy_)
    {
        if (ch->sslConnected_)
        {
            return SslDataRead(ch);
        }
        handleHandshake(ch);
    }
    else
    {
        proxyDataRead(ch);
    }
}

void handleWrite(Channel *ch)
{
    if (!ch->sslConnected_)
    {
        return handleHandshake(ch);
    }
    // log("handle write fd %d\n", ch->fd_);
    ch->events_ &= ~EPOLLOUT;
    ch->update();
}

static int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    SSL *ssl;
    X509 *cert;
    char *line;
    log("verify_callback -> preverify_ok: %d\n", preverify_ok);

    cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    if (cert != NULL)
    {
        printf("客户端证书:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("使用者: %s\n", line);
        OPENSSL_free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("颁发者: %s\n", line);
        OPENSSL_free(line);
        X509_free(cert);
    }

    return preverify_ok;
}

void initSSL()
{
    int r;
    bool verifyClient = false;
    bool useTLS13 = false;
    string ca = "certs/ca.crt", signcert = "certs/signcert.crt", singkey = "certs/signkey.key", enccert = "certs/enccert.crt", enckey = "certs/enckey.key";
    string cert = "certs/server.pem", key = "certs/server.pem", crl = "";
    SSL_load_error_strings();
    r = SSL_library_init();
    check0(!r, "SSL_library_init failed");
    errBio = BIO_new_fd(2, BIO_NOCLOSE);

    // 使用SSLv23_method可以同时支持客户同时支持rsa证书和sm2证书，支持普通浏览器和国密浏览器的访问
    // g_sslCtx = SSL_CTX_new(SSLv23_method());
    // 双证书相关server的各种定义
    const SSL_METHOD *meth = NTLS_server_method();
    g_sslCtx = SSL_CTX_new(meth);
    check0(g_sslCtx == NULL, "SSL_CTX_new failed");

    // 允许使用国密双证书功能
    SSL_CTX_enable_ntls(g_sslCtx);

    if (useTLS13)
    {
        printf("enable tls13 sm2 sign");
        // tongsuo中tls1.3不强制签名使用sm2签名，使用开关控制，对应客户端指定密码套件SSL_CTX_set_ciphersuites(ctx, "TLS_SM4_GCM_SM3");
        SSL_CTX_enable_sm_tls13_strict(g_sslCtx);
        SSL_CTX_set1_curves_list(g_sslCtx, "SM2:X25519:prime256v1");
    }

    // 设置密码套件
    SSL_CTX_set_cipher_list(g_sslCtx, "ECC-SM2-SM4-CBC-SM3:ECDHE-SM2-WITH-SM4-SM3:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA:AES128-GCM-SHA256:AES128-SHA256:AES128-SHA:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:AES256-GCM-SHA384:AES256-SHA256:AES256-SHA:ECDHE-RSA-AES128-SHA256:!aNULL:!eNULL:!RC4:!EXPORT:!DES:!3DES:!MD5:!DSS:!PKS");
    SSL_CTX_set_options(g_sslCtx, SSL_OP_CIPHER_SERVER_PREFERENCE);

    // 是否校验客户端
    if (verifyClient)
    {
        printf("need verify client\n");
        SSL_CTX_set_verify(g_sslCtx, SSL_VERIFY_PEER, verify_callback); // 验证客户端证书回调；
        // SSL_CTX_set_verify_depth(g_sslCtx, 0);
        r = SSL_CTX_load_verify_locations(g_sslCtx, ca.c_str(), NULL);
        check0(r <= 0, "SSL_CTX_load_verify_locations %s failed", ca.c_str());
        ERR_clear_error();
        STACK_OF(X509_NAME) *list = SSL_load_client_CA_file(ca.c_str());
        check0(list == NULL, "SSL_load_client_CA_file %s failed", ca.c_str());
        SSL_CTX_set_client_CA_list(g_sslCtx, list);
    }
    else
    {
        printf("not need verify client\n");
        SSL_CTX_set_verify(g_sslCtx, SSL_VERIFY_NONE, NULL); // 不验证客户端；
    }

    if (!crl.empty())
    {
        X509_STORE *store = NULL;
        X509_LOOKUP *lookup = NULL;

        store = SSL_CTX_get_cert_store(g_sslCtx);
        check0(store == NULL, "SSL_CTX_get_cert_store() failed");

        lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
        check0(store == NULL, "X509_STORE_add_lookup() failed");

        r = X509_LOOKUP_load_file(lookup, crl.c_str(), X509_FILETYPE_PEM);
        check0(store == NULL, "X509_LOOKUP_load_file(\"%s\") failed", crl.c_str());

        X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
        printf("local crl finish\n");
    }

    // 加载sm2证书
    r = SSL_CTX_use_sign_PrivateKey_file(g_sslCtx, singkey.c_str(), SSL_FILETYPE_PEM);
    check0(r <= 0, "SSL_CTX_use_sign_PrivateKey_file %s failed", singkey.c_str());
    r = SSL_CTX_use_sign_certificate_file(g_sslCtx, signcert.c_str(), SSL_FILETYPE_PEM);
    check0(r <= 0, "SSL_CTX_use_sign_certificate_file %s failed", signcert.c_str());
    r = SSL_CTX_use_enc_PrivateKey_file(g_sslCtx, enckey.c_str(), SSL_FILETYPE_PEM);
    check0(r <= 0, "SSL_CTX_use_enc_PrivateKey_file %s failed", enckey.c_str());
    r = SSL_CTX_use_enc_certificate_file(g_sslCtx, enccert.c_str(), SSL_FILETYPE_PEM);
    check0(r <= 0, "SSL_CTX_use_enc_certificate_file %s failed", enccert.c_str());
    printf("load sm2 cert key finish\n");

    // 加载rsa证书
    r = SSL_CTX_use_certificate_file(g_sslCtx, cert.c_str(), SSL_FILETYPE_PEM);
    check0(r <= 0, "SSL_CTX_use_certificate_file %s failed", cert.c_str());
    r = SSL_CTX_use_PrivateKey_file(g_sslCtx, key.c_str(), SSL_FILETYPE_PEM);
    check0(r <= 0, "SSL_CTX_use_PrivateKey_file %s failed", key.c_str());
    printf("load rsa cert key finish\n");

    r = SSL_CTX_check_private_key(g_sslCtx);
    check0(!r, "SSL_CTX_check_private_key failed");
    log("SSL inited\n");
}

int g_stop = 0;

void loop_once(int epollfd, int waitms)
{
    const int kMaxEvents = 20;
    struct epoll_event activeEvs[kMaxEvents];
    int n = epoll_wait(epollfd, activeEvs, kMaxEvents, waitms);
    for (int i = n - 1; i >= 0; i--)
    {
        Channel *ch = (Channel *)activeEvs[i].data.ptr;
        int events = activeEvs[i].events;
        if (events & (EPOLLIN | EPOLLERR))
        {
            // log("fd %d handle read\n", ch->fd_);
            handleRead(ch);
        }
        else if (events & EPOLLOUT)
        {
            // log("fd %d handle write\n", ch->fd_);
            handleWrite(ch);
        }
        else
        {
            log("unknown event %d\n", events);
        }
    }
}

void handleInterrupt(int sig)
{
    g_stop = true;
}

void *server_tun_thread(void *arg)
{
    size_t ret_length = 0;
    unsigned char buf[MAX_BUF_LEN];
    unsigned char packet[MAX_BUF_LEN + HEADER_LEN];
    unsigned int enpack_len = 0;

    // 2、读取虚拟网卡数据
    while (1)
    {
        // 1、读取数据
        ret_length = read(tunfd, buf, sizeof(buf));
        if (ret_length < 0)
        {
            log("tun read len < 0\n");
            break;
        }
        // 2、分析报文
        unsigned char src_ip[4];
        unsigned char dst_ip[4];
        memcpy(dst_ip, &buf[16], 4);
        memcpy(src_ip, &buf[12], 4);
        // printf("read tun data: %d.%d.%d.%d -> %d.%d.%d.%d (%d)\n", dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3], src_ip[0], src_ip[1], src_ip[2], src_ip[3], ret_length);

        // 3、查询客户端
        char ip[MAX_IPV4_STR_LEN] = {0};
        bzero(ip, MAX_IPV4_STR_LEN);
        sprintf(ip, "%d.%d.%d.%d", dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]);

        map<string, SSL *>::iterator iter = maps.find(ip);
        if (iter == maps.end())
        {
            continue;
        }
        SSL *ssl = iter->second;

        // 4、对数据进行封包处理
        enpack_len = sizeof(packet);
        enpack(RECORD_TYPE_DATA, buf, ret_length, packet, &enpack_len);

        // 5、发消息给客户端
        // int len = SSL_write(session->clientSslCache->ssl, buf, ret_length);
        int len = SSL_write(ssl, packet, enpack_len);
        if (len <= 0)
        {
            log("消息'%s'发送失败! 错误代码是%d, 错误信息是'%s'\n", buf, errno, strerror(errno));
        }
        bzero(buf, MAX_BUF_LEN);
    }
    return NULL;
}

char *ipInt2String(int ip_addr)
{
    struct in_addr var_ip;

    var_ip.s_addr = htonl(ip_addr);
    return inet_ntoa(var_ip);
}

int parseVipPool(const char *netIp, const char *netMask, vip_pool *vp)
{
    unsigned long ip, mask, mask2;

    if (netIp == NULL || netMask == NULL || vp == NULL)
    {
        return -1;
    }

    ip = inet_addr(netIp);
    mask = inet_addr(netMask);
    mask2 = inet_addr("255.255.255.255");

    if (ip == INADDR_NONE || mask == INADDR_NONE)
    {
        printf("parse ip and mask error");
        return -1;
    }

    vp->netIP = ntohl(ip & mask);
    vp->ipCount = ntohl(mask2 - mask);
    vp->broadcastIp = vp->netIP + vp->ipCount;

    vp->sVip = vp->netIP + 1;
    vp->vipPoolStart = vp->sVip + 1;
    vp->vipPoolEnd = vp->broadcastIp - 1;
    vp->vipPoolCap = vp->vipPoolEnd - vp->vipPoolStart + 1;

    printf("<<<<<<<<<<<<< vip net config >>>>>>>>>>>>>\n");
    printf("net ip: %s,\n", ipInt2String(vp->netIP));
    printf("broadcast ip: %s,\n", ipInt2String(vp->broadcastIp));
    printf("svip: %s,\n", ipInt2String(vp->sVip));
    printf("vip pool start: %s\n", ipInt2String(vp->vipPoolStart));
    printf("vip pool end: %s\n", ipInt2String(vp->vipPoolEnd));
    printf("vip pool size: %d\n", vp->vipPoolCap);
    printf("<<<<<<<<<<<<< vip net config >>>>>>>>>>>>>\n");
    return 0;
}

int netmask2prefixlen(const char *ip_str)
{
    int ret = 0;
    unsigned int ip_num = 0;
    unsigned char c1, c2, c3, c4;
    int cnt = 0;

    ret = sscanf(ip_str, "%hhu.%hhu.%hhu.%hhu", &c1, &c2, &c3, &c4);
    ip_num = c1 << 24 | c2 << 16 | c3 << 8 | c4;
    if (ip_num == 0xffffffff)
        return 32;
    if (ip_num == 0xffffff00)
        return 24;
    if (ip_num == 0xffff0000)
        return 16;
    if (ip_num == 0xff000000)
        return 6;
    for (int i = 0; i < 32; i++)
    {
        if ((ip_num << i) & 0x80000000)
            cnt++;
        else
            break;
    }
    return cnt;
}

void initTun(unsigned int mtu, const char *ipv4, const char *netmask)
{
    int ret = 0;
    TUNCONFIG_T tunCfg = {0};
    struct in_addr var_ip;

    // 解析虚拟ip池
    memset(&vipPool, 0, sizeof(vip_pool));
    ret = parseVipPool(ipv4, netmask, &vipPool);
    check0(ret != 0, "parse vip pool fail: %d", ret);

    sprintf(vipPool.ipv4_net, "%s/%d", ipv4, netmask2prefixlen(netmask));
    var_ip.s_addr = htonl(vipPool.sVip);

    memset(&tunCfg, 0, sizeof(TUNCONFIG_T));
    tunCfg.mtu = mtu;
    strcpy(tunCfg.ipv4, inet_ntoa(var_ip));
    strcpy(tunCfg.ipv4_net, vipPool.ipv4_net);

    // 创建虚拟网卡
    tunfd = tun_create(&tunCfg);
    check0(tunfd <= 0, "create tun fd fail: %d", tunfd);

    // 创建server tun读取线程
    pthread_t serverTunThread;
    ret = pthread_create(&serverTunThread, NULL, server_tun_thread, &tunfd);
    check0(ret != 0, "create server tun thread fail: %d", ret);
}

/**
 * @brief
 *
 * @param ip
 * @param ipLen
 * @return int 1 success
 */
int allocateVip(char *ip, unsigned int *ipLen)
{
    int i;
    int index = vipCycleIndex;
    char vip[64] = {0};

    while (vipCycleIndex < vipPool.vipPoolCap)
    {
        if (vipCycleIndex == index - 1)
        {
            return 0;
        }
        if (vipCycleIndex == vipPool.vipPoolCap - 1)
        {
            vipCycleIndex = 0;
            continue;
        }

        memset(vip, 0, sizeof(vip));
        strcpy(vip, ipInt2String(vipPool.vipPoolStart + vipCycleIndex));

        map<string, VIP_CONFIG_T *>::iterator iter = vipConfMap.find(vip);
        if (iter == vipConfMap.end())
        {
            VIP_CONFIG_T *tmp = (VIP_CONFIG_T *)malloc(sizeof(VIP_CONFIG_T));
            if (tmp == NULL)
            {
                return -1;
            }
            memset(tmp, 0, sizeof(VIP_CONFIG_T));

            memcpy(ip, vip, strlen(vip));
            *ipLen = strlen(vip);

            memcpy(tmp, vip, strlen(vip));
            tmp->used = true;
            vipConfMap.insert(pair<string, VIP_CONFIG_T *>(vip, tmp));
            return 1;
        }
        VIP_CONFIG_T *vipConf = iter->second;
        if (!vipConf->used)
        {
            vipConf->used = true;
            memcpy(ip, vip, strlen(vip));
            *ipLen = strlen(vip);
            return 1;
        }
        vipCycleIndex++;
    }
}

int pushTunConf(Channel *ch)
{
    int ret, writeLen = 0;
    char vip[128] = {0};
    unsigned char conf[512] = {0};
    unsigned char packet[514] = {0};
    unsigned int vipLen = sizeof(vip);
    unsigned int enpackLen = sizeof(packet);
    cJSON *root = NULL;
    SSL *ssl = ch->ssl_;

    // 分配虚拟ip
    memset(vip, 0, sizeof(vip));
    ret = allocateVip(vip, &vipLen);
    if (ret != 1)
    {
        log("allocate vip fail\n");
        return -1;
    }
    *(vip + vipLen) = '\0';
    ch->setVip(vip);

    // 记录分配的虚拟ip与ssl对应关系
    maps.insert(pair<string, SSL *>(vip, ssl));

    // 创建配置json
    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "global", GLOBAL_MODE);
    cJSON_AddNumberToObject(root, "mtu", MTU);
    cJSON_AddStringToObject(root, "svip", ipInt2String(vipPool.sVip));
    cJSON_AddStringToObject(root, "cvip", vip);
    cJSON_AddStringToObject(root, "cidr", vipPool.ipv4_net);
    char *str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    printf("push tun config to client[%p] -> %s\n", ssl, str);

    // 封装数据
    memset(conf, 0, sizeof(conf));
    memcpy(conf, RECORD_TYPE_CONTROL_TUN_CONFIG, RECORD_TYPE_LABEL_LEN);
    memcpy(conf + RECORD_TYPE_LABEL_LEN, str, strlen(str));

    enpack(RECORD_TYPE_CONTROL, conf, strlen(str) + RECORD_TYPE_LABEL_LEN, packet, &enpackLen);
    // dump_hex(packet + 2, enpackLen - 2, 32);

    // 推送数据 TODO 发送数据不全需要处理
    writeLen = SSL_write(ssl, packet, enpackLen);
    if (writeLen <= 0)
    {
        log("网卡配置[%s]推送失败! 错误码: %d, 错误信息: '%s'\n", conf, errno, strerror(errno));
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    int port = 1443;
    const char *ip = "10.12.9.0";
    const char *mask = "255.255.255.0";

    signal(SIGINT, handleInterrupt);

    initSSL();

    initTun(MTU, ip, mask);

    epollfd = epoll_create1(EPOLL_CLOEXEC);

    if (argc > 2)
    {
        port = atoi(argv[1]);
        if (port <= 0 || port > 65535)
            port = 1443;
    }

    listenfd = createServer(port);
    Channel *cl = new Channel(listenfd, EPOLLIN | EPOLLET, false);
    addEpollFd(epollfd, cl);
    while (!g_stop)
    {
        loop_once(epollfd, 100);
    }
    delete cl;
    ::close(epollfd);
    BIO_free(errBio);
    SSL_CTX_free(g_sslCtx);
    ERR_free_strings();
    log("program exited\n");
    return 0;
}
