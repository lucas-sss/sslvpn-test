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

#include "protocol.h"
#include "tun.h"
#include "cJSON.h"
#include "print.h"

#define MAX_BUF_SIZE 20480

using namespace std;

// 初始化虚拟网卡
static int initTun(int global, char *cvip, char *ipv4_net, unsigned int mtu);

// 处理控制数据
static int controlHandler(unsigned char *data, unsigned int len);

static void *client_tun_thread(void *arg);

static int sendAuthData(SSL *ssl);

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

int debug = 0;
SSL *ssl;
int tun_fd;

void do_debug(char *msg, ...)
{

    va_list argp;

    if (debug)
    {
        va_start(argp, msg);
        vfprintf(stderr, msg, argp);
        va_end(argp);
    }
}

int main(int argc, char **argv)
{
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

    // 变量定义
    const SSL_METHOD *meth = NULL;
    SSL_CTX *ctx = NULL;
    const char *sign_key_file = "certs/signclient.key";
    const char *sign_cert_file = "certs/signclient.crt";
    const char *enc_key_file = "certs/encclient.key";
    const char *enc_cert_file = "certs/encclient.crt";

    int global = 0;
    char *cvip = "12.12.9.2";
    char *ipv4_net = "12.12.9.0/24";
    unsigned int mtu = 1500;

    if (argc != 3)
    {
        printf("please run this: ./sslvpn-client server_ip server_port\n");
        exit(-1);
    }

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

    /* 初始化服务器端（对方）的地址和端口信息 */
    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(atoi(argv[2]));
    if (inet_aton(argv[1], (struct in_addr *)&dest.sin_addr.s_addr) == 0)
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
    // if (sendAuthData(ssl) != 0)
    // {
    //     printf("发送登录认证数据失败\n");
    //     goto exit;
    // }

    initTun(global, cvip, ipv4_net, mtu);

    /*循环读取服务端响应数据*/
    while (1)
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
            printf("消息接收失败！错误代码是%d, 错误信息是'%s'\n", errno, strerror(errno));
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
    int i = 1;
    int n = 2;
    int ret_length;
    unsigned char buf[MAX_BUF_SIZE + 1];
    unsigned char packet[MAX_BUF_SIZE + 1 + HEADER_LEN];
    unsigned int enpack_len = 0;
    unsigned char bigbuff[MAX_BUF_SIZE * n + HEADER_LEN * n];
    unsigned int copylen = 0;

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

        memcpy(bigbuff + copylen, packet, enpack_len);
        copylen += enpack_len;
        if (i % (n + 1) != 0)
        {
            // printf("积攒数据: %d\n", enpack_len);
            i++;
            continue;
        }
        // printf("发送数据: %d\n", copylen);

        // 4、直接发送到服务端
        // int len = SSL_write(ssl, packet, enpack_len);
        int len = SSL_write(ssl, bigbuff, copylen);
        if (len <= 0)
        {
            printf("消息'%s'发送失败! 错误代码是%d, 错误信息是'%s'\n", buf, errno, strerror(errno));
        }
        copylen = 0;
        i = 1;
        bzero(buf, MAX_BUF_SIZE + 1);
    }
    return NULL;
}

static int controlHandler(unsigned char *data, unsigned int len)
{
    int ret = 0;
    cJSON *root = NULL;
    cJSON *iterm_global = NULL, *iterm_cvip = NULL, *iterm_ipv4_net = NULL, *iterm_mtu = NULL;

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
    TUNCONFIG_T tunCfg = {0};
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