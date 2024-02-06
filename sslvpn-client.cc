//
// Created by 刘伟 on 2021/5/8.
//
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>
#include <regex.h>

#include "protocol.h"
#include "tun.h"
#include "cJSON.h"
#include "print.h"
#include "engine/sslengine.h"

#define MAX_BUF_SIZE 20480

using namespace std;

static ENGINE *e;

// 初始化虚拟网卡
static int initTun(int global, char *cvip, char *ipv4_net, unsigned int mtu);

// 处理控制数据
static int controlHandler(unsigned char *data, unsigned int len);

static void *client_tun_thread(void *arg);

static int sendAuthData(SSL *ssl);

void ShowCerts(SSL *ssl);

int isIPv4Valid(const char *ip);

static bool DEBUG_MODE = false; // debug模式
static bool USE_ENGINE = false; // 使用engine
static char serverIp[16];
static int serverPort;

static const int IPV4_ROUTE_LEN = 20;
int route4Count = 0;
char route4[IPV4_ROUTE_LEN * 48];

SSL *ssl;
int tun_fd;
TUNCONFIG_T tunCfg;

int g_stop = 0;

void handleInterrupt(int sig)
{
    g_stop = true;
}

void delRoute(const char *route)
{
    char buf[512] = {0};

    memset(buf, 0, sizeof(buf));
    sprintf(buf, "route del -net %s dev %s", route, tunCfg.dev);
    printf("删除路由: %s\n", buf);
    system(buf);
}

void releasePushRoute()
{
    if (route4Count == 0)
    {
        return;
    }
    for (size_t i = 0; i < route4Count; i++)
    {
        delRoute(route4 + i * IPV4_ROUTE_LEN);
    }
}

void usage(void)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "-e: 使用engine\n");
    fprintf(stderr, "-s: 服务端ip地址\n");
    fprintf(stderr, "-p: 服务端port\n");
    fprintf(stderr, "-d: 开启debug模式\n");
    fprintf(stderr, "-h: 使用帮助\n");
    exit(1);
}

int main(int argc, char **argv)
{
    int option;
    bool useTLS13 = false;
    bool useDHE = false;
    int sockfd, len;
    int ret;
    struct sockaddr_in dest;
    unsigned char buffer[MAX_BUF_SIZE + HEADER_LEN];
    unsigned char packet[MAX_BUF_SIZE + 1];
    unsigned int depack_len = 0;
    unsigned char *next = NULL;
    unsigned int next_len = 0;
    pthread_t clientTunThread;

    /* Check command line options */
    while ((option = getopt(argc, argv, "es:p:dh")) > 0)
    {
        switch (option)
        {
        case 'e':
            USE_ENGINE = true;
            break;
        case 's':
            memset(serverIp, 0, sizeof(serverIp));
            strncpy(serverIp, optarg, sizeof(serverIp));
            break;
        case 'p':
            serverPort = atoi(optarg);
            break;
        case 'd':
            DEBUG_MODE = true;
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
        printf("Too many options!\n");
        usage();
    }
    if (!isIPv4Valid(serverIp))
    {
        printf("非法服务端ip地址\n");
        usage();
    }
    if (serverPort <= 0 || serverPort > 65535)
    {
        printf("非法服务端端口\n");
        usage();
    }

    signal(SIGINT, handleInterrupt);
    signal(SIGTERM, handleInterrupt);

    if (USE_ENGINE)
    {
        e = register_engine();
        if (e == NULL)
        {
            printf("register engine fail\n");
        }
    }

    // 变量定义
    const SSL_METHOD *meth = NULL;
    SSL_CTX *ctx = NULL;
    const char *sign_key_file = "certs/signclient.key";
    const char *sign_cert_file = "certs/signclient.crt";
    const char *enc_key_file = "certs/encclient.key";
    const char *enc_cert_file = "certs/encclient.crt";

    // 双证书相关client的各种定义
    meth = NTLS_client_method();
    // 生成上下文
    ctx = SSL_CTX_new(meth);
    // 允许使用国密双证书功能
    SSL_CTX_enable_ntls(ctx);

    if (useTLS13)
    {
        // 对于tls1.3: 设置算法套件为TLS_SM4_GCM_SM3/TLS_SM4_CCM_SM3
        SSL_CTX_set1_curves_list(ctx, "SM2:X25519:prime256v1");
        ret = SSL_CTX_set_ciphersuites(ctx, "TLS_SM4_GCM_SM3");
    }
    else
    {
        // 对于tlcp: 设置算法套件为ECC-SM2-WITH-SM4-SM3或者ECDHE-SM2-WITH-SM4-SM3,
        // 这一步并不强制编写，默认ECC-SM2-WITH-SM4-SM3优先
        if (useDHE)
        {
            printf("use ECDHE-SM2-WITH-SM4-SM3\n");
            ret = SSL_CTX_set_cipher_list(ctx, "ECDHE-SM2-WITH-SM4-SM3");
            // 加载签名证书，加密证书，仅ECDHE-SM2-WITH-SM4-SM3套件需要这一步,
            // 该部分流程用...begin...和...end...注明
            //  ...begin...
            if (!SSL_CTX_use_sign_PrivateKey_file(ctx, sign_key_file, SSL_FILETYPE_PEM))
            {
                goto err;
            }
            if (!SSL_CTX_use_sign_certificate_file(ctx, sign_cert_file, SSL_FILETYPE_PEM))
            {
                goto err;
            }
            if (!SSL_CTX_use_enc_PrivateKey_file(ctx, enc_key_file, SSL_FILETYPE_PEM))
            {
                goto err;
            }
            if (!SSL_CTX_use_enc_certificate_file(ctx, enc_cert_file, SSL_FILETYPE_PEM))
            {
                goto err;
            }
            // ...end...
        }
        else
        {
            printf("use ECC-SM2-WITH-SM4-SM3\n");
            ret = SSL_CTX_set_cipher_list(ctx, "ECC-SM2-WITH-SM4-SM3");
        }
    }

    if (ret <= 0)
    {
        printf("SSL_CTX_set_cipher_list fail\n");
        goto err;
    }

    /* 创建一个 socket 用于 tcp 通信 */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Socket");
        exit(errno);
    }
    printf("socket created\n");

    // 设置超时
    struct timeval tv;
    tv.tv_sec = 0;           // 5 seconds
    tv.tv_usec = 100 * 1000; // 100ms
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

    /* 初始化服务器端（对方）的地址和端口信息 */
    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(serverPort);
    if (inet_aton(serverIp, (struct in_addr *)&dest.sin_addr.s_addr) == 0)
    {
        perror(argv[1]);
        exit(errno);
    }

    printf("address created\n");

    /* 连接服务器 */
    if (connect(sockfd, (struct sockaddr *)&dest, sizeof(dest)) != 0)
    {
        perror("Connect ");
        exit(errno);
    }
    // printf("server connected\n");

    /* 基于 ctx 产生一个新的 SSL */
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    /* 建立 SSL 连接 */
    if (SSL_connect(ssl) == -1)
    {
        ERR_print_errors_fp(stderr);
        goto exit;
    }
    else
    {
        printf("密码套件: %s\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);
    }
    printf("SSL_connect finish\n");

    // 发送登录认证消息
    if (sendAuthData(ssl) != 0)
    {
        printf("发送登录认证数据失败\n");
        goto exit;
    }

    /*循环读取服务端响应数据*/
    while (!g_stop)
    {
        if (next == NULL)
        {
            next = buffer;
            next_len = 0;
        }
        /* 1、接收服务器来的消息 */
        len = SSL_read(ssl, next + next_len, sizeof(buffer) - next_len);
        if (len <= 0)
        {
            // printf("消息接收失败！错误代码是%d, 错误信息是'%s'\n", errno, strerror(errno));
            int ssle = SSL_get_error(ssl, len);
            if (len < 0 && ssle != SSL_ERROR_WANT_READ)
            {
                if (errno != EAGAIN)
                {
                    printf("SSL_read return %d, error: %d, errno: %d, msg: %s\n", len, ssle, errno, strerror(errno));
                    goto finish;
                }
                continue;
            }
            if (len == 0)
            {
                if (ssle == SSL_ERROR_ZERO_RETURN)
                    printf("SSL has been shutdown.\n");
                else
                    printf("Connection has been aborted.\n");
                goto finish;
            }
            continue;
        }

        // 2、对数据进行解包
        memset(packet, 0, sizeof(packet));
        depack_len = sizeof(packet);
        while ((ret = depack(next, len, packet, &depack_len, &next, &next_len)) > 0)
        {
            // dump_hex(packet, depack_len, 16);
            len = next_len;
            int datalen = depack_len - RECORD_HEADER_LEN;
            // 判定数据类型
            if (memcmp(packet, RECORD_TYPE_CONTROL, RECORD_TYPE_LABEL_LEN) == 0) // 控制类型
            {
                printf("接收服务控制消息\n");
                *(packet + RECORD_HEADER_LEN + datalen) = '\0';
                ret = controlHandler(packet + RECORD_HEADER_LEN, datalen);
                if (ret != 0)
                {
                    goto finish;
                }
            }
            else if (memcmp(packet, RECORD_TYPE_DATA, RECORD_TYPE_LABEL_LEN) == 0) // 数据类型
            {
                /* 3、写入到虚拟网卡 */
                int wlen = write(tun_fd, packet + RECORD_HEADER_LEN, datalen);
                if (wlen < datalen)
                {
                    printf("虚拟网卡写入数据长度小于预期长度, write len: %d, data len: %d\n", wlen, datalen);
                }
            }
            else if (memcmp(packet, RECORD_TYPE_ALARM, RECORD_HEADER_LEN) == 0) // 警告类型
            {
                printf("接收告警数据\n");
            }
            else
            {
            }
            memset(packet, 0, sizeof(packet));
            depack_len = sizeof(packet);
        }
        if (ret < 0)
        {
            printf("非vpn协议数据\n");
        }
    }
    // 程序运行结束释放推送的路由配置
    releasePushRoute();
    // 如果时全局代理，删除指定路由
    if (tunCfg.global)
    {
        delRoute("0.0.0.0/1");
        delRoute("128.0.0.0/1");
    }
finish:
    /* 关闭连接 */
    SSL_shutdown(ssl);
    SSL_free(ssl);
exit:
    close(sockfd);
    SSL_CTX_free(ctx);
err:
    return 1;
}

static void *client_tun_thread(void *arg)
{
    int ret_length;
    unsigned char buf[MAX_BUF_SIZE + 1];
    unsigned char packet[MAX_BUF_SIZE + 1 + HEADER_LEN];
    unsigned int enpack_len = 0;

    // 2、读取虚拟网卡数据
    while (1)
    {
        // 1、读取数据
        ret_length = read(tun_fd, buf, sizeof(buf));
        if (ret_length < 0)
        {
            printf("tun read len < 0\n");
            break;
        }
        // 2、分析报文
        unsigned char src_ip[4];
        unsigned char dst_ip[4];
        memcpy(src_ip, &buf[16], 4);
        memcpy(dst_ip, &buf[20], 4);
        // printf("read tun data: %d.%d.%d.%d -> %d.%d.%d.%d (%d)\n", dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3],
        //        src_ip[0], src_ip[1], src_ip[2], src_ip[3], ret_length);

        // 3、对数据进行封包
        enpack_len = sizeof(packet);
        enpack(RECORD_TYPE_DATA, buf, ret_length, packet, &enpack_len);

        // 4、直接发送到服务端
        int len = SSL_write(ssl, packet, enpack_len);
        if (len <= 0)
        {
            printf("消息'%s'发送失败! 错误代码是%d, 错误信息是'%s'\n", buf, errno, strerror(errno));
            // TODO 需要重新发送
        }
        bzero(buf, MAX_BUF_SIZE + 1);
    }
    return NULL;
}

static void addRoute(char *route)
{
    char buf[512] = {0};
    memset(buf, 0, sizeof(buf));
    sprintf(buf, "route add -net %s dev %s", route, tunCfg.dev);
    printf("添加路由: %s\n", buf);
    system(buf);
}

static int controlHandler(unsigned char *data, unsigned int len)
{
    int ret = 0;
    cJSON *root = NULL;
    cJSON *iterm_global = NULL, *iterm_cvip = NULL, *iterm_ipv4_net = NULL, *iterm_mtu = NULL;
    cJSON *iterm_route4 = NULL, *route_item = NULL;
    int route4_array_size = 0;

    printf("receive config: %s\n", data + RECORD_TYPE_LABEL_LEN);

    root = cJSON_Parse((char *)(data + RECORD_TYPE_LABEL_LEN));
    if (root == NULL)
    {
        printf("parse control data fail.\n");
        return -1;
    }

    if (memcmp(data, RECORD_TYPE_CONTROL_TUN_CONFIG, RECORD_TYPE_LABEL_LEN) == 0) // 虚拟网卡控制类型
    {
        iterm_global = cJSON_GetObjectItemCaseSensitive(root, "global");
        iterm_cvip = cJSON_GetObjectItemCaseSensitive(root, "cvip");
        iterm_ipv4_net = cJSON_GetObjectItemCaseSensitive(root, "cidr");
        iterm_mtu = cJSON_GetObjectItemCaseSensitive(root, "mtu");
        if (iterm_global == NULL || iterm_cvip == NULL || iterm_ipv4_net == NULL || iterm_mtu == NULL)
        {
            printf("iterm is NULL\n");
            ret = -1;
            goto end;
        }
        ret = initTun(iterm_global->valueint, iterm_cvip->valuestring, iterm_ipv4_net->valuestring, iterm_mtu->valueint);
    }
    else if (memcmp(data, RECORD_TYPE_CONTROL_ROUTE_CONFIG, RECORD_TYPE_LABEL_LEN) == 0) // 路由配置控制类型
    {
        route4Count = 0;
        memset(route4, 0, sizeof(route4));
        iterm_route4 = cJSON_GetObjectItem(root, "route4");
        route4_array_size = cJSON_GetArraySize(iterm_route4);
        for (size_t i = 0; i < route4_array_size; i++)
        {
            route_item = cJSON_GetArrayItem(iterm_route4, i);
            strcpy(route4 + i * IPV4_ROUTE_LEN, route_item->valuestring);
            route4Count++;
            // 添加路由
            addRoute(route_item->valuestring);
        }
    }
    else
    {
    }
end:
    cJSON_Delete(root);
    return ret;
}

static int initTun(int global, char *cvip, char *ipv4_net, unsigned int mtu)
{
    printf("----------------\n");
    // 创建tun虚拟网卡
    pthread_t clientTunThread;

    memset(&tunCfg, 0, sizeof(TUNCONFIG_T));
    tunCfg.global = global;
    tunCfg.mtu = mtu;
    memcpy(tunCfg.ipv4, cvip, strlen(cvip));
    memcpy(tunCfg.ipv4_net, ipv4_net, strlen(ipv4_net));

    tun_fd = tun_create(&tunCfg);
    if (tun_fd <= 0)
    {
        perror("create tun fail");
        goto err;
    }

    // 创建client tun读取线程
    if (pthread_create(&clientTunThread, NULL, client_tun_thread, NULL) != 0)
    {
        perror("create client tun thread fail");
        goto err;
    }
    return 0;
err:
    return -1;
}

static int sendAuthData(SSL *ssl)
{
    int writeLen = 0;
    unsigned char conf[512] = {0};
    unsigned char packet[514] = {0};
    unsigned int enpackLen = sizeof(packet);
    const char *data = "{\"username\":\"test\",\"passwork\":\"123456\"}";

    // 封装数据
    memset(conf, 0, sizeof(conf));
    memcpy(conf, RECORD_TYPE_AUTH_ACCOUNT, RECORD_TYPE_LABEL_LEN);
    memcpy(conf + RECORD_TYPE_LABEL_LEN, data, strlen(data));

    enpack(RECORD_TYPE_AUTH, conf, strlen(data) + RECORD_TYPE_LABEL_LEN, packet, &enpackLen);

    // 发送登录认证数据
    writeLen = SSL_write(ssl, packet, enpackLen);
    if (writeLen <= 0)
    {
        printf("ssl write auth data fail %d\n", writeLen);
        return -1;
    }
    return 0;
}

void ShowCerts(SSL *ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL)
    {
        printf("服务端证书信息:\n");
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
        printf("无证书信息！\n");
    }
}

int isIPv4Valid(const char *ip)
{
    regex_t regex;
    int ret = regcomp(&regex, "^([0-9]{1,3}\\.){3}[0-9]{1,3}$", REG_EXTENDED);
    if (ret != 0)
    {
        fprintf(stderr, "Could not compile regex\n");
        return 0;
    }

    ret = regexec(&regex, ip, 0, NULL, 0);
    regfree(&regex);

    return (ret == 0);
}