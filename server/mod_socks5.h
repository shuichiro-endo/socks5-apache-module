/*
 * Title:  socks5 server header (apache module)
 * Author: Shuichiro Endo
 */

#define BUFFER_SIZE 8192

int encrypt_aes(unsigned char *plaintext, int plaintext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *ciphertext);
int decrypt_aes(unsigned char *ciphertext, int ciphertext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *plaintext);
int recv_data(int sock, void *buffer, int length, long tv_sec, long tv_usec);
int recv_data_aes(int sock, void *buffer, int length, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec);
int recv_data_tls(int sock, SSL *ssl ,void *buffer, int length, long tv_sec, long tv_usec);
int send_data(int sock, void *buffer, int length, long tv_sec, long tv_usec);
int send_data_aes(int sock, void *buffer, int length, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec);
int send_data_tls(int sock, SSL *ssl, void *buffer, int length, long tv_sec, long tv_usec);
int forwarder(int client_sock, int target_sock, long tv_sec, long tv_usec);
int forwarder_aes(int client_sock, int target_sock, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec);
int forwarder_tls(int client_sock, int target_sock, SSL *client_ssl_socks5, long tv_sec, long tv_usec);
int send_socks_response_ipv4(int client_sock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int send_socks_response_ipv4_aes(int client_sock, char ver, char req, char rsv, char atyp, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec);
int send_socks_response_ipv4_tls(int client_sock, SSL *client_ssl, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int send_socks_response_ipv6(int client_sock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int send_socks_response_ipv6_aes(int client_sock, char ver, char req, char rsv, char atyp, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec);
int send_socks_response_ipv6_tls(int client_sock, SSL *client_ssl, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int ssl_sccept_non_blocking(int sock, SSL *ssl, long tv_sec, long tv_usec);
void close_socket(int sock);
int worker(void *ptr);

struct worker_param {
	int client_sock;
	SSL *client_ssl_socks5;
	int socks5_over_tls_flag;	// 0:socks5 over aes 1:socks5 over tls
	unsigned char *aes_key;
	unsigned char *aes_iv;
	long tv_sec;		// recv send
	long tv_usec;		// recv send
	long forwarder_tv_sec;
	long forwarder_tv_usec;
};

struct ssl_param {
	SSL_CTX *client_ctx_socks5;
	SSL *client_ssl_socks5;
};

void fini_ssl(struct ssl_param *param);

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

struct username_password_authentication_request_tmp
{
	char ver;
	char ulen;
	char uname;
	// variable
};

struct send_recv_data_aes {
	unsigned char encrypt_data_length[16];
	unsigned char encrypt_data[BUFFER_SIZE*2];
};
