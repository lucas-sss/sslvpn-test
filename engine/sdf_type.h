//
// Created by liuwe on 2021/1/23.
//

#ifndef GM_T_0018_2012_SDF_TYPE_H
#define GM_T_0018_2012_SDF_TYPE_H


typedef struct DeviceInfo_st {
    unsigned char IssuerName[40];
    unsigned char DeviceName[16];
    unsigned char DeviceSerial[16];
    unsigned int DeviceVersion;
    unsigned int StandardVersion;
    unsigned int AsymAlgAbility[2];
    unsigned int SymAlgAbility;
    unsigned int HashAlgAbility;
    unsigned int BufferSize;
} DEVICEINFO;


/* RSA */
#define RSAref_MAX_BITS        2048
#define RSAref_MAX_LEN         ((RSAref_MAX_BITS + 7) / 8)
#define RSAref_MAX_PBITS       ((RSAref_MAX_BITS + 1) / 2)
#define RSAref_MAX_PLEN        ((RSAref_MAX_PBITS + 7) / 8)

typedef struct RSArefPublicKey_st {
    unsigned int bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
} RSArefPublicKey;

typedef struct RSArefPrivateKey_st {
    unsigned int bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
    unsigned char d[RSAref_MAX_LEN];
    unsigned char prime[2][RSAref_MAX_PLEN];
    unsigned char pexp[2][RSAref_MAX_PLEN];
    unsigned char coef[RSAref_MAX_PLEN];
} RSArefPrivateKey;


/* ECC */
#define ECCref_MAX_BITS       512
#define ECCref_MAX_LEN        ((ECCref_MAX_BITS + 7) / 8)


typedef struct ECCrefPublicKey_st {
    unsigned int bits;
    unsigned char x[ECCref_MAX_LEN];
    unsigned char y[ECCref_MAX_LEN];
} ECCrefPublicKey;

typedef struct ECCrefPrivateKey_st {
    unsigned int bits;
    unsigned char K[ECCref_MAX_LEN];
} ECCrefPrivateKey;

typedef struct ECCCipher_st {
    unsigned char x[ECCref_MAX_LEN];
    unsigned char y[ECCref_MAX_LEN];
    unsigned char M[32];
    unsigned int L;
    unsigned char C[136];
} ECCCipher;

typedef struct ECCSignature_st {
    unsigned char r[ECCref_MAX_LEN];
    unsigned char s[ECCref_MAX_LEN];
} ECCSignature;


/*ecc enveloped key struct*/
#define ECC_MAX_XCOORDINATE_BITS_LEN        512
#define ECC_MAX_YCOORDINATE_BITS_LEN        ECC_MAX_XCOORDINATE_BITS_LEN
#define ECC_MAX_MODULUS_BITS_LEN            ECC_MAX_XCOORDINATE_BITS_LEN

typedef struct eccpubkeyblob_st {
    unsigned int BitLen;
    unsigned char XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN / 8];
    unsigned char YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN / 8];
} ECCPUBLICKEYBLOB, *PECCPUBLICKEYBLOB;

typedef struct ecccipherblob_st {
    unsigned char XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN / 8];
    unsigned char YCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN / 8];
    unsigned char Hash[32];
    unsigned int CipherLen;
    unsigned char Cipher[128];
} ECCCIPHERBLOB, *PECCCIPHERBLOB;

//ECC加密密钥对保护结构
typedef struct SDF_ENVELOPEDKEYBLOB {
    unsigned long ulAsymmAlgID;     //保护对称密钥的非对称算法标识
    unsigned long ulSymmAlgID;      //对称算法标识,必须为ＥＣＢ模式
    ECCCIPHERBLOB ECCCipherBlob;    //对称密钥密文
    ECCPUBLICKEYBLOB PubKey;        //加密密钥对的公钥
    unsigned char cbEncryptedPrikey[64];//加密密钥对的私钥密文，其有效长度为原文的（ｕｌＢｉｔｓ＋ ７）／８
} ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;



/* algorithm */
#define SGD_SM1_ECB              0x00000101    /* SM1算法ECB加密模式 */
#define SGD_SM1_CBC              0x00000102    /* SM1算法CBC加密模式 */
#define SGD_SM1_CFB              0x00000104    /* SM1算法CFB加密模式 */
#define SGD_SM1_OFB              0x00000108    /* SM1算法OFB加密模式 */
#define SGD_SM1_MAC              0x00000110    /* SM1算法MAC运算 */

#define SGD_SSF33_ECB            0x00000201    /* SSF33算法ECB加密模式 */
#define SGD_SSF33_CBC            0x00000202    /* SSF33算法CBC加密模式 */
#define SGD_SSF33_CFB            0x00000204    /* SSF33算法CFB加密模式 */
#define SGD_SSF33_OFB            0x00000208    /* SSF33算法OFB加密模式 */
#define SGD_SSF33_MAC            0x00000210    /* SSF33算法MAC运算 */

#define SGD_SMS4_ECB            0x00000401    /* SMS4算法ECB加密模式 */
#define SGD_SMS4_CBC            0x00000402    /* SMS4算法CBC加密模式 */
#define SGD_SMS4_CFB            0x00000404    /* SMS4算法CFB加密模式 */
#define SGD_SMS4_OFB            0x00000408    /* SMS4算法OFB加密模式 */
#define SGD_SMS4_MAC            0x00000410    /* SMS4算法MAC运算 */

#define SGD_AES                 0x80000200
#define SGD_AES_ECB             0x00002001    /* AES算法ECB加密模式 */
#define SGD_AES_CBC             0x00002002    /* AES算法CBC加密模式 */
#define SGD_AES_CFB             0x00002004    /* AES算法CFB加密模式 */
#define SGD_AES_OFB             0x00002008    /* AES算法OFB加密模式 */
#define SGD_AES_MAC             0x00002010    /* AES算法MAC运算 */

#define SGD_SM3                 0x00000001  /* 标准SM3算法 */
#define SGD_SHA1                0x00000002    /* SHA1杂凑算法 */
#define SGD_SHA256              0x00000004    /* SHA256杂凑算法 */
//#define SGD_SM3_STD		0x00000008	/* 用于SM2签名的SM3算法,等价于SGD_SM2_1|SGD_SM3*/
#define SGD_EIA3                0x00000010  /* 祖冲之杂凑算法 */
#define SGD_HMAC_SM3            0x00000020  /* SM3的HASH-MAC算法 */
#define SGD_HMAC_SHA256         0x00000040  /* SHA256的HASH-MAC算法*/
#define SGD_SHA512              0x00000080    /* SHA512杂凑算法 */

#define SGD_SM2                 0x00020100
#define SGD_SM2_1               0x00020200
#define SGD_SM2_2               0x00020400
#define SGD_SM2_3               0x00020800


/* return value */
#define SDR_OK                      0x00000000
#define SDR_BASE                    0x01000000
#define SDR_UNKNOWERR               SDR_BASE + 0x00000001
#define SDR_NOTSUPPORT              SDR_BASE + 0x00000002
#define SDR_COMMFAIL                SDR_BASE + 0x00000003
#define SDR_HARDFAIL                SDR_BASE + 0x00000004
#define SDR_OPENDEVICE              SDR_BASE + 0x00000005
#define SDR_OPENSESSION             SDR_BASE + 0x00000006
#define SDR_PARDENY                 SDR_BASE + 0x00000007
#define SDR_KEYNOTEXIT              SDR_BASE + 0x00000008
#define SDR_ALGNOTSUPPORT           SDR_BASE + 0x00000009
#define SDR_ALGMODNOTSUPPORT        SDR_BASE + 0x0000000A
#define SDR_PKOPERR                 SDR_BASE + 0x0000000B
#define SDR_SKOPERR                 SDR_BASE + 0x0000000C
#define SDR_SIGNERR                 SDR_BASE + 0x0000000D
#define SDR_VERIFYERR               SDR_BASE + 0x0000000E
#define SDR_SYMOPERR                SDR_BASE + 0x0000000F
#define SDR_STEPERR                 SDR_BASE + 0x00000010
#define SDR_FILESIZEERR             SDR_BASE + 0x00000011
#define SDR_FILENOEXIST             SDR_BASE + 0x00000012
#define SDR_FILEOFSERR              SDR_BASE + 0x00000013
#define SDR_KEYTYPEERR              SDR_BASE + 0x00000014
#define SDR_KEYERR                  SDR_BASE + 0x00000015
#define SDR_ENCDATAERR              SDR_BASE + 0x00000016
#define SDR_RANDERR                 SDR_BASE + 0x00000017
#define SDR_PRKRERR                 SDR_BASE + 0x00000018
#define SDR_MACERR                  SDR_BASE + 0x00000019
#define SDR_FILEEXISTS              SDR_BASE + 0x0000001A
#define SDR_FILEWERR                SDR_BASE + 0x0000001B
#define SDR_NOBUFFER                SDR_BASE + 0x0000001C
#define SDR_INARGERR                SDR_BASE + 0x0000001D
#define SDR_OUTARGERR               SDR_BASE + 0x0000001E

#endif //GM_T_0018_2012_SDF_TYPE_H
