/*
 * Title:  socks5 server header (apache module)
 * Author: Shuichiro Endo
 */

#define BUFFER_SIZE 8192

int aesEncrypt(unsigned char *plaintext, int plaintext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *ciphertext);
int aesDecrypt(unsigned char *ciphertext, int ciphertext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *plaintext);
int recvData(int sock, void *buffer, int length, long tv_sec, long tv_usec);
int recvDataAes(int sock, void *buffer, int length, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec);
int recvDataTls(int sock, SSL *ssl ,void *buffer, int length, long tv_sec, long tv_usec);
int sendData(int sock, void *buffer, int length, long tv_sec, long tv_usec);
int sendDataAes(int sock, void *buffer, int length, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec);
int sendDataTls(int sock, SSL *ssl, void *buffer, int length, long tv_sec, long tv_usec);
int forwarder(int clientSock, int targetSock, long tv_sec, long tv_usec);
int forwarderAes(int clientSock, int targetSock, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec);
int forwarderTls(int clientSock, int targetSock, SSL *clientSslSocks5, long tv_sec, long tv_usec);
int sendSocksResponseIpv4(int clientSock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int sendSocksResponseIpv4Aes(int clientSock, char ver, char req, char rsv, char atyp, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec);
int sendSocksResponseIpv4Tls(int clientSock, SSL *clientSsl, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int sendSocksResponseIpv6(int clientSock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int sendSocksResponseIpv6Aes(int clientSock, char ver, char req, char rsv, char atyp, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec);
int sendSocksResponseIpv6Tls(int clientSock, SSL *clientSsl, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int sslAcceptNonBlock(int sock, SSL *ssl, long tv_sec, long tv_usec);
void closeSocket(int sock);
int worker(void *ptr);

typedef struct {
	int clientSock;
	SSL *clientSslSocks5;
	int socks5OverTlsFlag;
	unsigned char *aes_key;
	unsigned char *aes_iv;
	long tv_sec;		// recv send
	long tv_usec;		// recv send
	long forwarder_tv_sec;
	long forwarder_tv_usec;
} PARAM, *pPARAM;

typedef struct {
	SSL_CTX *clientCtxSocks5;
	SSL *clientSslSocks5;
} SSLPARAM, *pSSLPARAM;

void finiSsl(pSSLPARAM pSslParam);

typedef struct sock_userdata_t sock_userdata_t;
struct sock_userdata_t {
	sock_userdata_t *next;
	const char *key;
	void *data;
};

typedef struct apr_socket_t {
	apr_pool_t * pool;
	int socketdes;
	int type;
	int protocol;
	apr_sockaddr_t *local_addr;
	apr_sockaddr_t *remote_addr;
	apr_interval_time_t timeout;
	int nonblock;
	int local_port_unknown;
	int local_interface_unknown;
	int remote_addr_unknown;
	apr_int32_t options;
	apr_int32_t inherit;
	sock_userdata_t *userdata;
	apr_pollset_t *pollset;
} apr_socket_t;

typedef struct
{
	char ver;
	char ulen;
	char uname;
	// variable
} USERNAME_PASSWORD_AUTHENTICATION_REQUEST_TMP, *pUSERNAME_PASSWORD_AUTHENTICATION_REQUEST_TMP;

typedef struct {
	unsigned char encryptDataLength[16];
	unsigned char encryptData[BUFFER_SIZE*2];
} SEND_RECV_DATA, *pSEND_RECV_DATA;

typedef struct {
	unsigned char encryptDataLength[16];
	unsigned char encryptData[BUFFER_SIZE*10];
} FORWARDER_DATA, *pFORWARDER_DATA;

