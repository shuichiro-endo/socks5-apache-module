/*
 * Title:  socks5 server header (apache module)
 * Author: Shuichiro Endo
 */

int recvData(int sock, void *buffer, int length);
int recvDataTls(SSL *ssl ,void *buffer, int length);
int sendData(int sock, void *buffer, int length);
int sendDataTls(SSL *ssl, void *buffer, int length);
int forwarder(int clientSock, int targetSock);
int forwarderTls(int clientSock, int targetSock, SSL *clientSslSocks5);
int sendSocksResponseIpv4(int clientSock, char ver, char req, char rsv, char atyp);
int sendSocksResponseIpv4Tls(SSL *clientSsl, char ver, char req, char rsv, char atyp);
int sendSocksResponseIpv6(int clientSock, char ver, char req, char rsv, char atyp);
int sendSocksResponseIpv6Tls(SSL *clientSsl, char ver, char req, char rsv, char atyp);
int worker(void *ptr);

typedef struct {
	int clientSock;
	SSL *clientSslSocks5;
	int socks5OverTlsFlag;
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

