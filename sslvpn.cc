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
#include "engine/ssl_engine.h"

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

//  全局引擎
static ENGINE *e;

char tunname[32];
static const int MAX_BUF_LEN = 20480;
static const int MTU = 1500;
static const char *TUN_DEV = "tun21";
static const int IPV4_ROUTE_LEN = 20;
int route4Count = 0;
char route4[IPV4_ROUTE_LEN * 48];
int tunmtu = MTU;
char ca[512];
char crl[512];
bool verifyClient = false;

static const int MAX_TUN_QUEUE_SIZE = 8;
int tunQueueSize = 1;
int fds[MAX_TUN_QUEUE_SIZE];

static bool USE_ENGINE = false; // 使用engine
static bool DEBUG_MODE = false; // debug模式
static bool GLOBAL_MODE = false;
static bool OPEN_PROXY = false;
char proxyaddr[24];
char PROXY_IP[15];
int PROXY_PORT = 0;

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

// 默认虚拟网卡设备fd
int tunfd;
int tunfd2;
int tunEpollFd;

void log_debug(const char *msg, ...)
{
    va_list argp;

    if (DEBUG_MODE)
    {
        va_start(argp, msg);
        vfprintf(stdout, msg, argp);
        va_end(argp);
    }
}

struct Channel
{
    int fd_;
    int tfd_;
    SSL *ssl_;
    bool tcpConnected_;
    bool sslConnected_;
    int events_;

    unsigned char buf[MAX_BUF_LEN];

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
        tfd_ = 0;
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
    void setTFd(int tfd)
    {
        this->tfd_ = tfd;
    }
    ~Channel()
    {
        log("Channel[%p]删除 -> deleting fd %d\n", this, fd_);
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
            log("删除代理Channel: %p\n", proxyCh_);
            epoll_ctl(epollfd, EPOLL_CTL_DEL, proxyCh_->fd_, NULL);
            close(proxyCh_->fd_);
            delete proxyCh_;
            proxyCh_ = NULL;
        }
    }
};

int pushTunConf(Channel *ch);

int pushRouteConf(Channel *ch);

/**
 * @brief 设置fd为非阻塞fd
 *
 * @param fd
 * @param value
 * @return int
 */
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

/**
 * @brief 向epoll fd中添加监听事件
 *
 * @param epollfd
 * @param ch
 */
void addEpollFd(int epollfd, Channel *ch)
{
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = ch->events_;
    ev.data.ptr = ch;
    log_debug("adding fd %d events %d\n", ch->fd_, ev.events);
    int r = epoll_ctl(epollfd, EPOLL_CTL_ADD, ch->fd_, &ev);
    check0(r, "epoll_ctl add failed[%d], %s", errno, strerror(errno));
}

/**
 * @brief 创建服务端fd（入口fd）
 *
 * @param port
 * @return int
 */
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

/**
 * @brief 接收tcp连接
 *
 */
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
            log_debug("get peer name failed %d %s\n", errno, strerror(errno));
            continue;
        }
        r = getsockname(cfd, (sockaddr *)&local, &alen);
        if (r < 0)
        {
            log_debug("getsockname failed %d %s\n", errno, strerror(errno));
            continue;
        }
        setNonBlock(cfd, 1);
        Channel *ch = new Channel(cfd, EPOLLIN | EPOLLOUT, false);
        addEpollFd(epollfd, ch);
    }
}

/**
 * @brief 打印客户端证书
 *
 * @param ssl
 */
void showClientCerts(SSL *ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL)
    {
        log("SSL[%p]客户端证书信息:\n", ssl);
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        log("使用者: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        log("颁发者: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
    {
        printf("SSL[%p]无证书信息！\n", ssl);
    }
}

/**
 * @brief ssl握手处理
 *
 * @param ch
 */
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
        // 网卡多队列模式下为每一个客户端分配一个tunfd
        if (tunQueueSize > 1)
        {
            int mod = ch->fd_ % tunQueueSize;
            ch->tfd_ = fds[mod];
        }
        else
        {
            ch->tfd_ = tunfd;
        }
        log("new ssl: %p for fd: %d\n", ch->ssl_, ch->fd_);
        // 建立和上游的tcp连接
        if (OPEN_PROXY)
        {
            int fd = SSL_get_fd(ch->ssl_);
            map<int, int>::iterator iter = proxyMap.find(fd);
            if (iter == proxyMap.end()) // 防止一个连接多次握手（更新密钥）导致重复创建代理
            {
                int proxyFd = connect_proxy(PROXY_IP, PROXY_PORT);
                if (proxyFd > 0)
                {
                    proxyMap.insert(pair<int, int>(fd, proxyFd));
                    // 添加到epoll列表中
                    Channel *proxyCh = new Channel(proxyFd, EPOLLIN | EPOLLET, true);
                    log("SSL[%p]新建代理Channel\n", ch->ssl_);
                    proxyCh->ssl_ = ch->ssl_;
                    addEpollFd(epollfd, proxyCh);
                    ch->proxyCh_ = proxyCh;
                }
                else
                {
                    log("连接代理服务失败: %d\n", proxyFd);
                    // TODO 指定策略
                }
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

/**
 * @brief 读取代理数据
 *
 * @param ch
 */
void proxyDataRead(Channel *ch)
{
    int readlen = 0;

    // 读取上游发送的数据
    readlen = recv(ch->fd_, ch->buf, sizeof(ch->buf), 0);
    if (readlen > 0)
    {
        // 向下游客户端发送
        int writelen = SSL_write(ch->ssl_, ch->buf, readlen);
        if (writelen < readlen)
        {
            log("SSL[%p]写入代理响应数据长度过小 -> proxy resp len: %d, write len: %d\n", ch->ssl_, readlen, writelen);
            // TODO 需要重新发送
        }
    }
    else
    {
        log("read proxy data fail: %d\n", readlen);
    }
}

/**
 * @brief 读取ssl数据
 *
 * @param ch
 */
void SslDataRead(Channel *ch)
{
    int ret = 0;
    unsigned char packet[MAX_BUF_LEN];
    unsigned int depack_len = 0;

    if (ch->next == NULL)
    {
        ch->next = ch->buf;
        ch->next_len = 0;
    }
    int len = SSL_read(ch->ssl_, ch->next + ch->next_len, MAX_BUF_LEN - ch->next_len);
    int ssle = SSL_get_error(ch->ssl_, len);
    if (len > 0)
    {
        log_debug("ssl read len: %d\n", len);
        int count = 0;
        // 2、解包处理
        depack_len = sizeof(packet);
        while ((ret = depack(ch->next, len, packet, &depack_len, &ch->next, &ch->next_len)) > 0)
        {
            log_debug("count: %d, depack data len: %d\n", count, depack_len);
            len = ch->next_len;
            int datalen = depack_len - RECORD_HEADER_LEN;

            // 判定数据类型
            if (memcmp(packet, RECORD_TYPE_DATA, RECORD_TYPE_LABEL_LEN) == 0) // vpn数据
            {
                /* 3、写入到虚拟网卡 */
                int wlen = write(ch->tfd_, packet + RECORD_HEADER_LEN, datalen);
                if (wlen < datalen)
                {
                    log("虚拟网卡写入数据长度小于预期长度, write len: %d, buffer len: %d\n", wlen, len);
                    // TODO 网卡数据写失败处理
                }
            }
            else if (memcmp(packet, RECORD_TYPE_AUTH, RECORD_TYPE_LABEL_LEN) == 0) // 认证数据
            {
                log("客户端认证消息:\n");
                // TODO 判断认证消息类型

                // 认证成功后推送tun配置
                pushTunConf(ch);
                // 推送路由配置
                pushRouteConf(ch);
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
            log_debug("非vpn协议数据\n");
            if (DEBUG_MODE)
            {
                dump_hex(ch->next, len, 32);
            }
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

/**
 * @brief 服务端socket数据读取处理逻辑
 *
 * @param ch
 */
void handleRead(Channel *ch)
{
    if (ch->fd_ == listenfd)
    {
        // fd为主程序fd，则进行tcp连接握手处理
        return handleAccept();
    }
    if (!ch->isproxy_)
    {
        if (ch->sslConnected_)
        {
            // 已完成ssl握手，读取ssl数
            return SslDataRead(ch);
        }
        // 未完成ssl握手，继续进行ssl握手处理
        handleHandshake(ch);
    }
    else
    {
        // 是代理fd，这进行代理fd数据读取
        proxyDataRead(ch);
    }
}

/**
 * @brief 服务端socket数据写入处理逻辑
 *
 * @param ch
 */
void handleWrite(Channel *ch)
{
    if (!ch->sslConnected_)
    {
        // 这里主要在ssl握手未完成前由服务端主动处理ssl握手逻辑
        return handleHandshake(ch);
    }
    // 握手完成后不在监听数据可写入事件（频繁触发影响性能）
    ch->events_ &= ~EPOLLOUT;
    ch->update();
}

/**
 * @brief ssl证书校验回调
 *
 * @param preverify_ok
 * @param x509_ctx
 * @return int
 */
static int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    SSL *ssl;
    X509 *cert;
    char *line;
    log("verify_callback -> preverify_ok: %d\n", preverify_ok);

    cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    if (cert != NULL)
    {
        log("客户端证书:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        log("使用者: %s\n", line);
        OPENSSL_free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        log("颁发者: %s\n", line);
        OPENSSL_free(line);
        X509_free(cert);
    }

    return preverify_ok;
}

/**
 * @brief 初始化ssl
 *
 */
void initSSL()
{
    int r;
    bool useTLS13 = false;
    string signcert = "certs/signcert.crt", singkey = "certs/signkey.key", enccert = "certs/enccert.crt", enckey = "certs/enckey.key";
    string cert = "certs/server.pem", key = "certs/server.pem";
    SSL_load_error_strings();
    r = SSL_library_init();
    check0(!r, "SSL_library_init failed");
    errBio = BIO_new_fd(2, BIO_NOCLOSE);

    if (USE_ENGINE)
    {
        log("register engine...\n");
        e = register_engine();
        if (e == NULL)
        {
            log("register engine fail\n");
        }
    }

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
        log("enable tls13 sm2 sign\n");
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
        log("need verify client\n");
        SSL_CTX_set_verify(g_sslCtx, SSL_VERIFY_PEER, verify_callback); // 验证客户端证书回调；
        // SSL_CTX_set_verify_depth(g_sslCtx, 0);
        r = SSL_CTX_load_verify_locations(g_sslCtx, ca, NULL);
        check0(r <= 0, "SSL_CTX_load_verify_locations %s failed", ca);
        ERR_clear_error();
        STACK_OF(X509_NAME) *list = SSL_load_client_CA_file(ca);
        check0(list == NULL, "SSL_load_client_CA_file %s failed", ca);
        SSL_CTX_set_client_CA_list(g_sslCtx, list);
    }
    else
    {
        log("not need verify client\n");
        SSL_CTX_set_verify(g_sslCtx, SSL_VERIFY_NONE, NULL); // 不验证客户端；
    }

    if (strlen(crl) > 0)
    {
        X509_STORE *store = NULL;
        X509_LOOKUP *lookup = NULL;

        store = SSL_CTX_get_cert_store(g_sslCtx);
        check0(store == NULL, "SSL_CTX_get_cert_store() failed");

        lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
        check0(store == NULL, "X509_STORE_add_lookup() failed");

        r = X509_LOOKUP_load_file(lookup, crl, X509_FILETYPE_PEM);
        check0(store == NULL, "X509_LOOKUP_load_file(\"%s\") failed", crl);

        X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
        log("load crl finish\n");
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

/**
 * @brief 服务端主循环处理逻辑（进行ssl握手或者读取ssl数据）
 *
 * @param epollfd
 * @param waitms
 */
void loop_once(int epollfd, int waitms)
{
    const int kMaxEvents = 10240;
    struct epoll_event activeEvs[kMaxEvents];
    int n = epoll_wait(epollfd, activeEvs, kMaxEvents, waitms);
    for (int i = n - 1; i >= 0; i--)
    {
        Channel *ch = (Channel *)activeEvs[i].data.ptr;
        int events = activeEvs[i].events;
        if (events & (EPOLLIN | EPOLLERR))
        {
            handleRead(ch);
        }
        else if (events & EPOLLOUT)
        {
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

/**
 * @brief 服务端虚拟网卡数据读取线程
 *
 * @param arg
 * @return void*
 */
void *server_tun_thread(void *arg)
{
    int *tfd = (int *)arg;
    size_t ret_length = 0;
    unsigned char buf[MAX_BUF_LEN];
    unsigned char packet[MAX_BUF_LEN + HEADER_LEN];
    unsigned int enpack_len = 0;

    // 2、读取虚拟网卡数据
    while (1)
    {
        // 1、读取数据
        ret_length = read(*tfd, buf, sizeof(buf));
        if (ret_length < 0)
        {
            log("tun read len < 0\n");
            break;
        }
        // 2、分析报文
        // unsigned char src_ip[4];
        // unsigned char dst_ip[4];
        // memcpy(dst_ip, &buf[16], 4);
        // memcpy(src_ip, &buf[12], 4);
        log_debug("PID[%d] tun[%d] read tun data: %d.%d.%d.%d -> %d.%d.%d.%d (%d)\n", getpid(), *tfd, buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19], ret_length);

        // 3、查询客户端
        char ip[MAX_IPV4_STR_LEN] = {0};
        bzero(ip, MAX_IPV4_STR_LEN);
        sprintf(ip, "%d.%d.%d.%d", buf[16], buf[17], buf[18], buf[19]);

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

/**
 * @brief 服务端多队列网卡读取（功能暂时不可用）
 *
 * @param arg
 * @return void*
 */
void *server_multi_queue_tun_thread(void *arg)
{
    size_t ret_length = 0;
    unsigned char buf[MAX_BUF_LEN];
    unsigned char packet[MAX_BUF_LEN + HEADER_LEN];
    unsigned int enpack_len = 0;

    struct epoll_event events[10240];
    while (1)
    {
        int num_events = epoll_wait(tunEpollFd, events, 1024, 100);
        int i;
        for (i = 0; i < num_events; i++)
        {
            if (events[i].events & EPOLLIN)
            {
                int fd = events[i].data.fd;
                // 1、读取数据
                ret_length = read(fd, buf, sizeof(buf));
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
                log_debug("read tun data: %d.%d.%d.%d -> %d.%d.%d.%d (%d)\n", dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3], src_ip[0], src_ip[1], src_ip[2], src_ip[3], ret_length);

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
                int len = SSL_write(ssl, packet, enpack_len);
                if (len <= 0)
                {
                    log("消息'%s'发送失败! 错误代码是%d, 错误信息是'%s'\n", buf, errno, strerror(errno));
                }
                bzero(buf, MAX_BUF_LEN);
            }
        }
    }
    return NULL;
}

char *ipInt2String(int ip_addr)
{
    struct in_addr var_ip;

    var_ip.s_addr = htonl(ip_addr);
    return inet_ntoa(var_ip);
}

/**
 * @brief 解析虚拟ip池参数配置
 *
 * @param netIp     ip网络地址
 * @param netMask   子网掩码
 * @param vp        解析后ip参数
 * @return int
 */
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
        log("parse ip and mask error");
        return -1;
    }

    vp->netIP = ntohl(ip & mask);
    vp->ipCount = ntohl(mask2 - mask);
    vp->broadcastIp = vp->netIP + vp->ipCount;

    vp->sVip = vp->netIP + 1;
    vp->vipPoolStart = vp->sVip + 1;
    vp->vipPoolEnd = vp->broadcastIp - 1;
    vp->vipPoolCap = vp->vipPoolEnd - vp->vipPoolStart + 1;

    log("<<<<<<<<<<<<< vip net config >>>>>>>>>>>>>\n");
    log("net ip: %s,\n", ipInt2String(vp->netIP));
    log("broadcast ip: %s,\n", ipInt2String(vp->broadcastIp));
    log("svip: %s,\n", ipInt2String(vp->sVip));
    log("vip pool start: %s\n", ipInt2String(vp->vipPoolStart));
    log("vip pool end: %s\n", ipInt2String(vp->vipPoolEnd));
    log("vip pool size: %d\n", vp->vipPoolCap);
    log("<<<<<<<<<<<<< vip net config >>>>>>>>>>>>>\n");
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

/**
 * @brief 自动nat转换配置
 *
 */
void autoNatConfig()
{
    char buf[512] = {0};

    if (route4Count == 0)
    {
        log("ipv4推送路由为空,忽略配置自动nat转换\n");
        return;
    }
    for (size_t i = 0; i < route4Count; i++)
    {
        /* code */
        memset(buf, 0, sizeof(buf));
        sprintf(buf, "iptables -t nat -A POSTROUTING -s %s -d %s -j MASQUERADE", vipPool.ipv4_net, route4 + i * IPV4_ROUTE_LEN);
        log("设置auto nat: %s\n", buf);
        system(buf);
    }
}

/**
 * @brief 清除配置的自动nat转换
 *
 */
void releaseAutoNat()
{
    char buf[512] = {0};

    if (route4Count == 0)
    {
        log("ipv4推送路由为空,忽略释放自动nat转换配置\n");
        return;
    }
    for (size_t i = 0; i < route4Count; i++)
    {
        /* code */
        memset(buf, 0, sizeof(buf));
        sprintf(buf, "iptables -t nat -D POSTROUTING -s %s -d %s -j MASQUERADE", vipPool.ipv4_net, route4 + i * IPV4_ROUTE_LEN);
        log("删除auto nat: %s\n", buf);
        system(buf);
    }
}

/**
 * @brief 初始化虚拟网卡
 *
 * @param mtu
 * @param ipv4
 * @param netmask
 */
void initTun(unsigned int mtu, const char *ipv4, const char *netmask)
{
    int i, ret = 0;
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
    strncpy(tunCfg.dev, tunname, sizeof(tunCfg.dev));
    strcpy(tunCfg.ipv4, inet_ntoa(var_ip));
    strcpy(tunCfg.ipv4_net, vipPool.ipv4_net);

    // // 创建单队列虚拟网卡
    // tunfd = tun_create(&tunCfg);
    // check0(tunfd <= 0, "create tun fd fail: %d", tunfd);
    // // 创建server tun读取线程
    // pthread_t serverTunThread;
    // ret = pthread_create(&serverTunThread, NULL, server_tun_thread, &tunfd);
    // check0(ret != 0, "create server tun thread fail: %d", ret);

    // 创建多队列虚拟网卡
    // 指明虚拟网卡名称
    strncpy(tunCfg.dev, tunname, sizeof(tunCfg.dev));
    ret = tun_create_mq(&tunCfg, tunQueueSize, fds);
    check0(ret != 0, "create multi queue tun fail: %d", ret);
    for (i = 0; i < tunQueueSize; i++)
    {
        tun_set_queue(fds[i], 1);
    }
    tunfd = fds[0];

    // 为每个tunfd创建server tun读取线程
    pthread_t serverTunThread;
    ret = pthread_create(&serverTunThread, NULL, server_tun_thread, &tunfd);
    check0(ret != 0, "create server tun thread fail: %d", ret);
    // ret = pthread_create(&serverTunThread, NULL, server_tun_thread, &tunfd2);
    // check0(ret != 0, "create server tun thread2 fail: %d", ret);

    // // 使用epoll模式读取多队列网卡数据
    // struct epoll_event ev;
    // tunEpollFd = epoll_create1(EPOLL_CLOEXEC);
    // memset(&ev, 0, sizeof(ev));
    // ev.events = EPOLLIN | EPOLLET; // Read events with edge-triggered mode;

    // for (i = 0; i < size; i++)
    // {
    //     // 把队列fd添加到epoll中
    //     ev.data.fd = fds[i];
    //     int r = epoll_ctl(tunEpollFd, EPOLL_CTL_ADD, fds[i], &ev);
    //     check0(r, "epoll_ctl[tun] add failed[%d], %s", errno, strerror(errno));
    // }
    // pthread_t serverTunThread;
    // ret = pthread_create(&serverTunThread, NULL, server_multi_queue_tun_thread, &tunEpollFd);
    // check0(ret != 0, "create server tun thread fail: %d", ret);
}

/**
 * @brief 从虚拟ip池中申请一个虚拟ip
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
    return 0;
}

/**
 * @brief 向客户端推送路由配置
 *
 * @param ch
 * @return int
 */
int pushRouteConf(Channel *ch)
{
    int writeLen = 0;
    unsigned char conf[1024] = {0};
    unsigned char packet[1024 + 8] = {0};
    unsigned int enpackLen = sizeof(packet);
    cJSON *root = NULL;
    cJSON *route4Arr = NULL;
    SSL *ssl = ch->ssl_;

    if (route4Count == 0)
    {
        return 0;
    }
    // 创建配置json
    root = cJSON_CreateObject();
    route4Arr = cJSON_CreateArray();
    for (size_t i = 0; i < route4Count; i++)
    {
        cJSON_AddItemToArray(route4Arr, cJSON_CreateString(route4 + i * IPV4_ROUTE_LEN));
    }
    cJSON_AddItemToObject(root, "route4", route4Arr);
    // TODO ipv6路由

    char *str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    log("push ipv4 route to client[%p] -> %s\n", ssl, str);

    memset(conf, 0, sizeof(conf));
    memcpy(conf, RECORD_TYPE_CONTROL_ROUTE_CONFIG, RECORD_TYPE_LABEL_LEN);
    memcpy(conf + RECORD_TYPE_LABEL_LEN, str, strlen(str));

    enpack(RECORD_TYPE_CONTROL, conf, strlen(str) + RECORD_TYPE_LABEL_LEN, packet, &enpackLen);

    // 推送数据 TODO 发送数据不全需要处理
    writeLen = SSL_write(ssl, packet, enpackLen);
    if (writeLen <= 0)
    {
        log("路由配置[%s]推送失败! 错误码: %d, 错误信息: '%s'\n", conf, errno, strerror(errno));
        return -1;
    }
    return 0;
}

/**
 * @brief 向客户端推送网卡配置
 *
 * @param ch
 * @return int
 */
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
    cJSON_AddNumberToObject(root, "mtu", tunmtu);
    cJSON_AddStringToObject(root, "svip", ipInt2String(vipPool.sVip));
    cJSON_AddStringToObject(root, "cvip", vip);
    cJSON_AddStringToObject(root, "cidr", vipPool.ipv4_net);
    char *str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    log("push tun config to client[%p] -> %s\n", ssl, str);

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

/**
 * @brief 解析ipv4推送路由配置
 *
 * @param r
 */
void parseRoute(char *r)
{
    log_debug("parse ipv4 route: %s\n", r);
    char *ptr = NULL;
    char *tmp = NULL;

    memset(route4, 0, sizeof(route4));
    if (strlen(r) <= 0)
    {
        return;
    }
    ptr = strtok_r(r, ",", &tmp);
    if (ptr == NULL)
    {
        strcpy(route4, r);
        route4Count = 1;
        return;
    }
    while (ptr)
    {
        if (route4Count > 48)
        {
            fprintf(stderr, "ipv4推送路由最多支持配置48条\n");
            exit(1);
        }
        printf("%s\n", ptr);
        strcpy(route4 + route4Count * IPV4_ROUTE_LEN, ptr);
        route4Count++;
        ptr = strtok_r(NULL, ",", &tmp);
    }
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "-e: 使用engine\n");
    fprintf(stderr, "-t: tun网卡名称, 默认为tun21\n");
    fprintf(stderr, "-p: 服务运行端口, 默认: 1443\n");
    fprintf(stderr, "-i: 虚拟网络ip地址, 默认: 10.12.9.0\n");
    fprintf(stderr, "-m: 虚拟网络掩码, 默认: 255.255.255.0\n");
    fprintf(stderr, "-u: 虚拟网卡mtu值, 例如: 1500, 1500 <= mtu <= 15000\n");
    fprintf(stderr, "-r: ipv4推送路由(最多48条推送路由), 例如: 192.168.20.0/24,10.123.20.0/24\n");
    fprintf(stderr, "-c: 开启客户端验证模式, 开启后必须配置客户端ca证书\n");
    fprintf(stderr, "-a: 客户端ca证书文件, 打开验证客户端模式下生效\n");
    fprintf(stderr, "-g: 开启客户端全代理模式\n");
    fprintf(stderr, "-x: 使用代理服务并设置代理服务ip和端口,例如: 127.0.0.1:9112\n");
    fprintf(stderr, "-l: 配置吊销证书列表crl路径, 例如: /crl/path/crl\n");
    fprintf(stderr, "-d: 开启debug模式\n");
    fprintf(stderr, "-h: 使用帮助\n");
    exit(1);
}

int main(int argc, char **argv)
{
    int option;
    int port = 1443;
    const char *defaultVip = "10.12.9.0";
    const char *defaultVmask = "255.255.255.0";
    char vip[15] = {0};
    char vmask[15] = {0};
    char *split, *proxyportptr;

    signal(SIGINT, handleInterrupt);

    memset(tunname, 0, sizeof(tunname));
    memset(vip, 0, sizeof(vip));
    memset(vmask, 0, sizeof(vmask));
    memset(ca, 0, sizeof(ca));
    memset(proxyaddr, 0, sizeof(proxyaddr));
    memset(crl, 0, sizeof(crl));

    strncpy(vip, defaultVip, sizeof(vip));
    strncpy(vmask, defaultVmask, sizeof(vmask));

    /* Check command line options */
    while ((option = getopt(argc, argv, "et:p:i:m:u:r:gca:x:l:dh")) > 0)
    {
        switch (option)
        {
        case 'e':
            USE_ENGINE = true;
            break;
        case 't':
            memset(tunname, 0, sizeof(tunname));
            strncpy(tunname, optarg, sizeof(tunname));
            break;
        case 'p':
            port = atoi(optarg);
            break;
        case 'i':
            strncpy(vip, optarg, sizeof(vip));
            break;
        case 'm':
            strncpy(vmask, optarg, sizeof(vmask));
            break;
        case 'u':
            tunmtu = atoi(optarg);
            break;
        case 'r':
            parseRoute(optarg);
            break;
        case 'g':
            GLOBAL_MODE = true;
            break;
        case 'c':
            verifyClient = true;
            break;
        case 'a':
            strncpy(ca, optarg, sizeof(ca));
            if (access(ca, F_OK) != 0)
            {
                log("ca证书文件不存在\n");
                usage();
            }
            break;
        case 'x':
            strncpy(proxyaddr, optarg, sizeof(proxyaddr));
            split = strstr(proxyaddr, ":");
            if (split == NULL)
            {
                log("代理服务器配置错误\n");
                usage();
            }
            *split = '\0';
            proxyportptr = split + 1;
            strcpy(PROXY_IP, proxyaddr);
            PROXY_PORT = atoi(proxyportptr);
            OPEN_PROXY = true;
            break;
        case 'l':
            strncpy(crl, optarg, sizeof(crl));
            if (access(crl, F_OK) != 0)
            {
                log("证书吊销列表文件不存在\n");
                usage();
            }
            break;
        case 'd':
            DEBUG_MODE = true;
            break;
        case 'h':
            usage();
            break;
        default:
            printf("Unknown option %c\n", option);
            usage();
        }
    }
    argv += optind;
    argc -= optind;

    if (argc > 0)
    {
        log("Too many options!\n");
        usage();
    }
    if (port <= 0 || port > 65535)
    {
        log("服务端口设置错误, 0 < mtu <= 65535\n");
        usage();
    }
    if (tunmtu < 1500 || tunmtu > 15000)
    {
        log("mtu设置错误, 1500 <= mtu <= 15000\n");
        usage();
    }
    if (*vip == '\0' || *vmask == '\0')
    {
        log("虚拟网络设置错误, 请同时设置vip与vmask\n");
        usage();
    }
    if (verifyClient && access(ca, F_OK) != 0)
    {
        log("ca证书文件不存在\n");
        usage();
    }

    if (*tunname == '\0')
    {
        strcpy(tunname, TUN_DEV);
    }

    // 初始化ssl
    initSSL();

    // 创建程序epollfd
    epollfd = epoll_create1(EPOLL_CLOEXEC);

    // 创建并配置虚拟网卡
    initTun(tunmtu, vip, vmask);

    // 自动nat转换配置
    autoNatConfig();

    // 创建服务监听端口
    listenfd = createServer(port);
    Channel *cl = new Channel(listenfd, EPOLLIN | EPOLLET, false);
    // 添加服务端口到epoll中
    addEpollFd(epollfd, cl);

    // 主程序循环
    while (!g_stop)
    {
        loop_once(epollfd, 100);
    }
    // 清除已配置的nat转换
    releaseAutoNat();
    delete cl;
    ::close(epollfd);
    BIO_free(errBio);
    SSL_CTX_free(g_sslCtx);
    ERR_free_strings();
    log("program exited\n");
    return 0;
}
