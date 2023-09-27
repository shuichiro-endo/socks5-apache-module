/*
 * Title:  socks5 server module (apache module)
 * Author: Shuichiro Endo
 */

//#define _DEBUG

#include <stdio.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"

#include "socks5.h"
#include "mod_socks5.h"
#include "serverkey.h"

#define BUFFER_SIZE 8192

#define HTTP_REQUEST_HEADER_SOCKS5_KEY "socks5"
#define HTTP_REQUEST_HEADER_SOCKS5_VALUE "socks5"
#define HTTP_REQUEST_HEADER_AESKEY_KEY "aeskey"
#define HTTP_REQUEST_HEADER_AESIV_KEY "aesiv"
#define HTTP_REQUEST_HEADER_TLS_KEY "tls"
#define HTTP_REQUEST_HEADER_TLS_VALUE1 "off"	// Socks5 over AES
#define HTTP_REQUEST_HEADER_TLS_VALUE2 "on"	// Socks5 over TLS
#define HTTP_REQUEST_HEADER_TVSEC_KEY "sec"	// recv/send tv_sec
#define HTTP_REQUEST_HEADER_TVUSEC_KEY "usec"	// recv/send tv_usec
#define HTTP_REQUEST_HEADER_FORWARDER_TVSEC_KEY "forwardersec"		// forwarder tv_sec
#define HTTP_REQUEST_HEADER_FORWARDER_TVUSEC_KEY "forwarderusec"	// forwarder tv_usec

static char authentication_method = 0x0;	// 0x0:No Authentication Required	0x2:Username/Password Authentication
static char username[256] = "socks5user";
static char password[256] = "supersecretpassword";

char cipher_suite_tls_1_2[1000] = "AESGCM+ECDSA:CHACHA20+ECDSA:+AES256";	// TLS1.2
char cipher_suite_tls_1_3[1000] = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";	// TLS1.3


int encrypt_aes(unsigned char *plaintext, int plaintext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *ctx;
	int length;
	int ciphertext_length;
	int ret;
	
	ctx = EVP_CIPHER_CTX_new();
	if(ctx == NULL){
#ifdef _DEBUG
//		printf("[E] EVP_CIPHER_CTX_new error.\n");
#endif
		return -1;
	}
	
	ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_EncryptInit_ex error.\n");
#endif
		return -1;
	}
	
	ret = EVP_EncryptUpdate(ctx, ciphertext, &length, plaintext, plaintext_length);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_EncryptUpdate error.\n");
#endif
		return -1;
	}
	ciphertext_length = length;
	
	ret = EVP_EncryptFinal_ex(ctx, ciphertext+length, &length);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_EncryptFinal_ex error.\n");
#endif
		return -1;
	}
	ciphertext_length += length;
	
	EVP_CIPHER_CTX_free(ctx);
	
	return ciphertext_length;
}


int decrypt_aes(unsigned char *ciphertext, int ciphertext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;
	int length;
	int plaintext_length;
	int ret;
	
	ctx = EVP_CIPHER_CTX_new();
	if(ctx == NULL){
#ifdef _DEBUG
//		printf("[E] EVP_CIPHER_CTX_new error.\n");
#endif
		return -1;
	}
	
	ret = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_DecryptInit_ex error.\n");
#endif
		return -1;
	}
	
	ret = EVP_DecryptUpdate(ctx, plaintext, &length, ciphertext, ciphertext_length);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_DecryptUpdate error.\n");
#endif
		return -1;
	}
	plaintext_length = length;
	
	ret = EVP_DecryptFinal_ex(ctx, plaintext+length, &length);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_DecryptFinal_ex error.\n");
#endif
		return -1;
	}
	plaintext_length += length;
	
	EVP_CIPHER_CTX_free(ctx);
	
	return plaintext_length;
}


int recv_data(int sock, void *buffer, int length, long tv_sec, long tv_usec)
{
	int rec = 0;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	struct timeval start;
	struct timeval end;
	long t = 0;
	bzero(buffer, length+1);
	
	if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
		printf("[E] gettimeofday error.\n");
#endif
		return -1;
	}
	
	while(1){
		if(gettimeofday(&end, NULL) == -1){
#ifdef _DEBUG
			printf("[E] gettimeofday error.\n");
#endif
			return -1;
		}
		
		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec)){
#ifdef _DEBUG
			printf("[I] recv_data timeout.\n");
#endif
			return -1;
		}
		
		FD_ZERO(&readfds);
		FD_SET(sock, &readfds);
		nfds = sock + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] recv_data select timeout.\n");
#endif
			return -1;
		}
		
		if(FD_ISSET(sock, &readfds)){
			rec = recv(sock, buffer, length, 0);
			if(rec <= 0){
				if(errno == EINTR){
					continue;
				}else if(errno == EAGAIN){
					usleep(5000);
					continue;
				}else{
					return -1;
				}
			}else{
				break;
			}
		}
	}
	
	return rec;
}


int recv_data_aes(int sock, void *buffer, int length, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec)
{
	int rec = 0;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	struct timeval start;
	struct timeval end;
	long t = 0;
	bzero(buffer, length+1);
	int ret = 0;
	struct send_recv_data_aes *data;
	int encrypt_data_length = 0;
	unsigned char *tmp = calloc(16, sizeof(unsigned char));
	unsigned char *buffer2 = calloc(BUFFER_SIZE*2, sizeof(unsigned char));
	
	if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
		printf("[E] gettimeofday error.\n");
#endif
		free(tmp);
		free(buffer2);
		return -1;
	}
	
	while(1){
		if(gettimeofday(&end, NULL) == -1){
#ifdef _DEBUG
			printf("[E] gettimeofday error.\n");
#endif
			free(tmp);
			free(buffer2);
			return -1;
		}
		
		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec)){
#ifdef _DEBUG
			printf("[I] recv_data_aes timeout.\n");
#endif
			free(tmp);
			free(buffer2);
			return -1;
		}
		
		FD_ZERO(&readfds);
		FD_SET(sock, &readfds);
		nfds = sock + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] recv_data_aes select timeout.\n");
#endif
			free(tmp);
			free(buffer2);
			return -1;
		}
		
		if(FD_ISSET(sock, &readfds)){
			rec = recv(sock, buffer2, BUFFER_SIZE*2, 0);
			if(rec <= 0){
				if(errno == EINTR){
					continue;
				}else if(errno == EAGAIN){
					usleep(5000);
					continue;
				}else{
					free(tmp);
					free(buffer2);
					return -1;
				}
			}else if(rec >= 16){	// unsigned char encrypt_data_length[16]
				data = (struct send_recv_data_aes *)buffer2;
				
				ret = decrypt_aes(data->encrypt_data_length, 16, aes_key, aes_iv, (unsigned char *)tmp);
				if(ret == 4){	// int encrypt_data_length
					encrypt_data_length = (tmp[0] << 24)|(tmp[1] << 16)|(tmp[2] << 8)|(tmp[3]);
				}else{
					free(tmp);
					free(buffer2);
					return -1;
				}
				
				if(encrypt_data_length <= rec-16){
					ret = decrypt_aes(data->encrypt_data, encrypt_data_length, aes_key, aes_iv, (unsigned char *)buffer);
					if(ret > 0){
						rec = ret;
					}else{
						free(tmp);
						free(buffer2);
						return -1;
					}
					
					break;
				}else{
					break;
				}
			}else{
				break;
			}
		}
	}
	
	free(tmp);
	free(buffer2);
	return rec;
}


int recv_data_tls(int sock, SSL *ssl ,void *buffer, int length, long tv_sec, long tv_usec)
{
	int rec = 0;
	int err = 0;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	struct timeval start;
	struct timeval end;
	long t = 0;
	bzero(buffer, length+1);
	
	if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
		printf("[E] gettimeofday error.\n");
#endif
		return -2;
	}
	
	while(1){
		if(gettimeofday(&end, NULL) == -1){
#ifdef _DEBUG
			printf("[E] gettimeofday error.\n");
#endif
			return -2;
		}
		
		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec)){
#ifdef _DEBUG
			printf("[I] recv_data_tls timeout.\n");
#endif
			return -2;
		}
		
		FD_ZERO(&readfds);
		FD_SET(sock, &readfds);
		nfds = sock + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] recv_data_tls select timeout.\n");
#endif
			return -2;
		}
		
		if(FD_ISSET(sock, &readfds)){
			rec = SSL_read(ssl, buffer, length);
			err = SSL_get_error(ssl, rec);
			
			if(err == SSL_ERROR_NONE){
				break;
			}else if(err == SSL_ERROR_ZERO_RETURN){
				break;
			}else if(err == SSL_ERROR_WANT_READ){
				usleep(5000);
			}else if(err == SSL_ERROR_WANT_WRITE){
				usleep(5000);
			}else{
#ifdef _DEBUG
				printf("[E] SSL_read error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
				return -2;
			}
		}
	}
	
	return rec;
}


int send_data(int sock, void *buffer, int length, long tv_sec, long tv_usec)
{
	int sen = 0;
	int send_length = 0;
	int len = length;
	fd_set writefds;
	int nfds = -1;
	struct timeval tv;
	struct timeval start;
	struct timeval end;
	long t = 0;
	
	if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
		printf("[E] gettimeofday error.\n");
#endif
		return -1;
	}
	
	while(len > 0){
		if(gettimeofday(&end, NULL) == -1){
#ifdef _DEBUG
			printf("[E] gettimeofday error.\n");
#endif
			return -1;
		}
		
		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec)){
#ifdef _DEBUG
			printf("[I] send_data timeout.\n");
#endif
			return -1;
		}
		
		FD_ZERO(&writefds);
		FD_SET(sock, &writefds);
		nfds = sock + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, NULL, &writefds, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] send_data select timeout.\n");
#endif
			return -1;
		}
		
		if(FD_ISSET(sock, &writefds)){
			sen = send(sock, buffer+send_length, len, 0);
			if(sen <= 0){
				if(errno == EINTR){
					continue;
				}else if(errno == EAGAIN){
					usleep(5000);
					continue;
				}else{
					return -1;
				}
			}
			send_length += sen;
			len -= sen;
		}
	}
	
	return length;
}


int send_data_aes(int sock, void *buffer, int length, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec)
{
	int sen = 0;
	int send_length = 0;
	int len = 0;
	fd_set writefds;
	int nfds = -1;
	struct timeval tv;
	struct timeval start;
	struct timeval end;
	long t = 0;
	int ret = 0;
	struct send_recv_data_aes *data = (struct send_recv_data_aes *)calloc(1, sizeof(struct send_recv_data_aes));
	int encrypt_data_length = 0;
	unsigned char *tmp = calloc(16, sizeof(unsigned char));
	
	ret = encrypt_aes((unsigned char *)buffer, length, aes_key, aes_iv, data->encrypt_data);
	if(ret > 0){
		encrypt_data_length = ret;
	}else{
		free(tmp);
		free(data);
		return -1;
	}
	
	if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
		printf("[E] gettimeofday error.\n");
#endif
		free(tmp);
		free(data);
		return -1;
	}
	
	tmp[0] = (unsigned char)encrypt_data_length >> 24;
	tmp[1] = (unsigned char)encrypt_data_length >> 16;
	tmp[2] = (unsigned char)encrypt_data_length >> 8;
	tmp[3] = (unsigned char)encrypt_data_length;
	
	ret = encrypt_aes((unsigned char *)tmp, 4, aes_key, aes_iv, data->encrypt_data_length);
	if(ret != 16){	// unsigned char encrypt_data_length[16]
		free(tmp);
		free(data);
		return -1;
	}
	
	len = 16 + encrypt_data_length;
	
	while(len > 0){
		if(gettimeofday(&end, NULL) == -1){
#ifdef _DEBUG
			printf("[E] gettimeofday error.\n");
#endif
			free(tmp);
			free(data);
			return -1;
		}
		
		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec)){
#ifdef _DEBUG
			printf("[I]  timeout.\n");
#endif
			free(tmp);
			free(data);
			return -1;
		}
		
		FD_ZERO(&writefds);
		FD_SET(sock, &writefds);
		nfds = sock + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, NULL, &writefds, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] send_data_aes select timeout.\n");
#endif
			free(tmp);
			free(data);
			return -1;
		}
		
		if(FD_ISSET(sock, &writefds)){
			sen = send(sock, (unsigned char *)data+send_length, len, 0);
			if(sen <= 0){
				if(errno == EINTR){
					continue;
				}else if(errno == EAGAIN){
					usleep(5000);
					continue;
				}else{
					free(tmp);
					free(data);
					return -1;
				}
			}
			send_length += sen;
			len -= sen;
		}
	}
	
	free(tmp);
	free(data);
	return length;
}


int send_data_tls(int sock, SSL *ssl, void *buffer, int length, long tv_sec, long tv_usec)
{
	int sen = 0;
	int err = 0;
	fd_set writefds;
	int nfds = -1;
	struct timeval tv;
	struct timeval start;
	struct timeval end;
	long t = 0;
	
	if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
		printf("[E] gettimeofday error.\n");
#endif
		return -2;
	}
	
	while(1){
		if(gettimeofday(&end, NULL) == -1){
#ifdef _DEBUG
			printf("[E] gettimeofday error.\n");
#endif
			return -2;
		}
		
		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec)){
#ifdef _DEBUG
			printf("[I] send_data_tls timeout.\n");
#endif
			return -2;
		}
		
		FD_ZERO(&writefds);
		FD_SET(sock, &writefds);
		nfds = sock + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, NULL, &writefds, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] send_data_tls select timeout.\n");
#endif
			return -2;
		}
		
		if(FD_ISSET(sock, &writefds)){
			sen = SSL_write(ssl, buffer, length);
			err = SSL_get_error(ssl, sen);
			
			if(err == SSL_ERROR_NONE){
				break;
			}else if(err == SSL_ERROR_WANT_WRITE){
				usleep(5000);
			}else if(err == SSL_ERROR_WANT_READ){
				usleep(5000);
			}else{
#ifdef _DEBUG
				printf("[E] SSL_write error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
				return -2;
			}
		}
	}
		
	return length;
}


int forwarder(int client_sock, int target_sock, long tv_sec, long tv_usec)
{
	int rec, sen;
	int len = 0;
	int send_length = 0;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	char buffer[BUFFER_SIZE+1];
	bzero(buffer, BUFFER_SIZE+1);
	
	while(1){
		FD_ZERO(&readfds);
		FD_SET(client_sock, &readfds);
		FD_SET(target_sock, &readfds);
		nfds = (client_sock > target_sock ? client_sock : target_sock) + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] forwarder select timeout.\n");
#endif
			break;
		}
						
		if(FD_ISSET(client_sock, &readfds)){
			if((rec = recv(client_sock, buffer, BUFFER_SIZE, 0)) > 0){
				len = rec;
				send_length = 0;
				
				while(len > 0){
					sen = send(target_sock, buffer+send_length, len, 0);
					if(sen <= 0){
						if(errno == EINTR){
							continue;
						}else if(errno == EAGAIN){
							usleep(5000);
							continue;
						}else{
							return -1;
						}
					}
					send_length += sen;
					len -= sen;
				}
			}else{
				break;
			}
		}
		
		if(FD_ISSET(target_sock, &readfds)){
			if((rec = recv(target_sock, buffer, BUFFER_SIZE, 0)) > 0){
				len = rec;
				send_length = 0;
				
				while(len > 0){
					sen = send(client_sock, buffer+send_length, len, 0);
					if(sen <= 0){
						if(errno == EINTR){
							continue;
						}else if(errno == EAGAIN){
							usleep(5000);
							continue;
						}else{
							return -1;
						}
					}
					send_length += sen;
					len -= sen;
				}
			}else{
				break;
			}
		}
	}
	
	return 0;
}


int forwarder_aes(int client_sock, int target_sock, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec)
{
	int rec, sen;
	int len = 0;
	int recv_length = 0;
	int send_length = 0;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	int ret = 0;
	struct send_recv_data_aes *data = (struct send_recv_data_aes *)calloc(1, sizeof(struct send_recv_data_aes));
	int encrypt_data_length = 0;
	unsigned char *tmp = calloc(16, sizeof(unsigned char));
	unsigned char *buffer = calloc(BUFFER_SIZE*2, sizeof(unsigned char));
	unsigned char *buffer2 = calloc(BUFFER_SIZE*2, sizeof(unsigned char));
	
	while(1){
		FD_ZERO(&readfds);
		FD_SET(client_sock, &readfds);
		FD_SET(target_sock, &readfds);
		nfds = (client_sock > target_sock ? client_sock : target_sock) + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] forwarder_aes select timeout.\n");
#endif
			break;
		}
		
		if(FD_ISSET(client_sock, &readfds)){
			bzero(tmp, 16);
			bzero(buffer, BUFFER_SIZE*2);
			bzero(buffer2, BUFFER_SIZE*2);
			
			len = 16;
			recv_length = 0;

			while(len > 0){
				rec = recv(client_sock, (unsigned char *)buffer+recv_length, len, 0);	// unsigned char encrypt_data_length[16]
				if(rec <= 0){
					if(errno == EINTR){
						continue;
					}else if(errno == EAGAIN){
						usleep(5000);
						continue;
					}else{
						free(tmp);
						free(data);
						free(buffer);
						free(buffer2);
						return -1;
					}
				}
				recv_length += rec;
				len -= rec;
			}

			ret = decrypt_aes((unsigned char *)buffer, 16, aes_key, aes_iv, tmp);
			if(ret != 4){	// int encrypt_data_length
				free(tmp);
				free(data);
				free(buffer);
				free(buffer2);
				return -1;
			}

			encrypt_data_length = (tmp[0] << 24)|(tmp[1] << 16)|(tmp[2] << 8)|(tmp[3]);

			if(encrypt_data_length <= 0 || encrypt_data_length > BUFFER_SIZE*2 || (encrypt_data_length & 0xf) != 0){
				free(tmp);
				free(data);
				free(buffer);
				free(buffer2);
				return -1;
			}
				
			bzero(buffer, BUFFER_SIZE*2);
			len = encrypt_data_length;
			recv_length = 0;

			while(len > 0){
				rec = recv(client_sock, (unsigned char *)buffer+recv_length, len, 0);
				if(rec <= 0){
					if(errno == EINTR){
						continue;
					}else if(errno == EAGAIN){
						usleep(5000);
						continue;
					}else{
						free(tmp);
						free(data);
						free(buffer);
						free(buffer2);
						return -1;
					}
				}
				recv_length += rec;
				len -= rec;
			}

			ret = decrypt_aes((unsigned char *)buffer, encrypt_data_length, aes_key, aes_iv, buffer2);
			if(ret < 0){
				free(tmp);
				free(data);
				free(buffer);
				free(buffer2);
				return -1;
			}

			len = ret;
			send_length = 0;

			while(len > 0){
				sen = send(target_sock, (unsigned char *)buffer2+send_length, len, 0);
				if(sen <= 0){
					if(errno == EINTR){
						continue;
					}else if(errno == EAGAIN){
						usleep(5000);
						continue;
					}else{
						free(tmp);
						free(data);
						free(buffer);
						free(buffer2);
						return -1;
					}
				}
				send_length += sen;
				len -= sen;
			}
		}
		
		if(FD_ISSET(target_sock, &readfds)){
			bzero(tmp, 16);
			bzero(data, sizeof(struct send_recv_data_aes));
			bzero(buffer, BUFFER_SIZE*2);
			
			rec = recv(target_sock, buffer, BUFFER_SIZE, 0);
			if(rec <= 0){
				if(errno == EINTR){
					continue;
				}else if(errno == EAGAIN){
					usleep(5000);
					continue;
				}else{
					free(tmp);
					free(data);
					free(buffer);
					free(buffer2);
					return -1;
				}
			}else{
				ret = encrypt_aes((unsigned char *)buffer, rec, aes_key, aes_iv, data->encrypt_data);
				if(ret > 0){
					encrypt_data_length = ret;
				}else{
					free(tmp);
					free(data);
					free(buffer);
					free(buffer2);
					return -1;
				}
				
				tmp[0] = (unsigned char)(encrypt_data_length >> 24);
				tmp[1] = (unsigned char)(encrypt_data_length >> 16);
				tmp[2] = (unsigned char)(encrypt_data_length >> 8);
				tmp[3] = (unsigned char)encrypt_data_length;
				
				ret = encrypt_aes((unsigned char *)tmp, 4, aes_key, aes_iv, data->encrypt_data_length);
				if(ret != 16){	// unsigned char encrypt_data_length[16]
					free(tmp);
					free(data);
					free(buffer);
					free(buffer2);
					return -1;
				}
				
				len = 16 + encrypt_data_length;
				send_length = 0;
				
				while(len > 0){
					sen = send(client_sock, (unsigned char *)data+send_length, len, 0);
					if(sen <= 0){
						if(errno == EINTR){
							continue;
						}else if(errno == EAGAIN){
							usleep(5000);
							continue;
						}else{
							free(tmp);
							free(data);
							free(buffer);
							free(buffer2);
							return -1;
						}
					}
					send_length += sen;
					len -= sen;
				}
			}
		}
	}
	
	free(tmp);
	free(data);
	free(buffer);
	free(buffer2);
	return 0;
}


int forwarder_tls(int client_sock, int target_sock, SSL *client_ssl_socks5, long tv_sec, long tv_usec)
{
	int rec, sen;
	int len = 0;
	int send_length = 0;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	unsigned char *buffer = calloc(BUFFER_SIZE*2, sizeof(unsigned char));
	int err = 0;
	
	while(1){
		FD_ZERO(&readfds);
		FD_SET(client_sock, &readfds);
		FD_SET(target_sock, &readfds);
		nfds = (client_sock > target_sock ? client_sock : target_sock) + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] forwarder_tls select timeout.\n");
#endif
			break;
		}
		
		if(FD_ISSET(client_sock, &readfds)){
			bzero(buffer, BUFFER_SIZE*2);

			rec = SSL_read(client_ssl_socks5, buffer, BUFFER_SIZE);
			err = SSL_get_error(client_ssl_socks5, rec);
			
			if(err == SSL_ERROR_NONE){
				len = rec;
				send_length = 0;
				
				while(len > 0){
					sen = send(target_sock, (unsigned char *)buffer+send_length, len, 0);
					if(sen <= 0){
						if(errno == EINTR){
							continue;
						}else if(errno == EAGAIN){
							usleep(5000);
							continue;
						}else{
							free(buffer);
							return -2;
						}
					}
					send_length += sen;
					len -= sen;
				}
			}else if(err == SSL_ERROR_ZERO_RETURN){
				break;
			}else if(err == SSL_ERROR_WANT_READ){
				usleep(5000);
			}else if(err == SSL_ERROR_WANT_WRITE){
				usleep(5000);
			}else{
#ifdef _DEBUG
				printf("[E] SSL_read error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
				free(buffer);
				return -2;
			}
		}
		
		if(FD_ISSET(target_sock, &readfds)){
			bzero(buffer, BUFFER_SIZE*2);

			rec = recv(target_sock, buffer, BUFFER_SIZE, 0);
			if(rec <= 0){
				if(errno == EINTR){
					continue;
				}else if(errno == EAGAIN){
					usleep(5000);
					continue;
				}else{
					free(buffer);
					return -2;
				}
			}else{
				while(1){
					sen = SSL_write(client_ssl_socks5, buffer, rec);
					err = SSL_get_error(client_ssl_socks5, sen);

					if(err == SSL_ERROR_NONE){
						break;
					}else if(err == SSL_ERROR_WANT_WRITE){
						usleep(5000);
					}else if(err == SSL_ERROR_WANT_READ){
						usleep(5000);
					}else{
#ifdef _DEBUG
						printf("[E] SSL_write error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
						free(buffer);
						return -2;
					}
				}
			}
		}
	}
	
	free(buffer);
	return 0;
}


int send_socks_response_ipv4(int client_sock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec)
{
	int sen;
	struct socks_response_ipv4 *socks_response_ipv4 = (struct socks_response_ipv4 *)malloc(sizeof(struct socks_response_ipv4));
		
	socks_response_ipv4->ver = ver;		// protocol version
	socks_response_ipv4->req = req;		// Connection refused
	socks_response_ipv4->rsv = rsv;		// RESERVED
	socks_response_ipv4->atyp = atyp;	// IPv4
	bzero(socks_response_ipv4->bnd_addr, 4);	// BND.ADDR
	bzero(socks_response_ipv4->bnd_port, 2);	// BND.PORT

	sen = send_data(client_sock, socks_response_ipv4, sizeof(struct socks_response_ipv4), tv_sec, tv_usec);

	free(socks_response_ipv4);

	return sen;
}


int send_socks_response_ipv4_aes(int client_sock, char ver, char req, char rsv, char atyp, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec)
{
	int sen;
	struct socks_response_ipv4 *socks_response_ipv4 = (struct socks_response_ipv4 *)malloc(sizeof(struct socks_response_ipv4));
	
	socks_response_ipv4->ver = ver;		// protocol version
	socks_response_ipv4->req = req;		// Connection refused
	socks_response_ipv4->rsv = rsv;		// RESERVED
	socks_response_ipv4->atyp = atyp;	// IPv4
	bzero(socks_response_ipv4->bnd_addr, 4);	// BND.ADDR
	bzero(socks_response_ipv4->bnd_port, 2);	// BND.PORT

	sen = send_data_aes(client_sock, socks_response_ipv4, sizeof(struct socks_response_ipv4), aes_key, aes_iv, tv_sec, tv_usec);

	free(socks_response_ipv4);

	return sen;
}


int send_socks_response_ipv4_tls(int client_sock, SSL *client_ssl, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec)
{
	int sen;
	struct socks_response_ipv4 *socks_response_ipv4 = (struct socks_response_ipv4 *)malloc(sizeof(struct socks_response_ipv4));
	
	socks_response_ipv4->ver = ver;		// protocol version
	socks_response_ipv4->req = req;		// Connection refused
	socks_response_ipv4->rsv = rsv;		// RESERVED
	socks_response_ipv4->atyp = atyp;	// IPv4
	bzero(socks_response_ipv4->bnd_addr, 4);	// BND.ADDR
	bzero(socks_response_ipv4->bnd_port, 2);	// BND.PORT

	sen = send_data_tls(client_sock, client_ssl, socks_response_ipv4, sizeof(struct socks_response_ipv4), tv_sec, tv_usec);

	free(socks_response_ipv4);

	return sen;
}


int send_socks_response_ipv6(int client_sock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec)
{
	int sen;
	struct socks_response_ipv6 *socks_response_ipv6 = (struct socks_response_ipv6 *)malloc(sizeof(struct socks_response_ipv6));
	
	socks_response_ipv6->ver = ver;		// protocol version
	socks_response_ipv6->req = req;		// Connection refused
	socks_response_ipv6->rsv = rsv;		// RESERVED
	socks_response_ipv6->atyp = atyp;	// IPv6
	bzero(socks_response_ipv6->bnd_addr, 16);	// BND.ADDR
	bzero(socks_response_ipv6->bnd_port, 2);	// BND.PORT
	
	sen = send_data(client_sock, socks_response_ipv6, sizeof(struct socks_response_ipv6), tv_sec, tv_usec);
	
	free(socks_response_ipv6);

	return sen;
}


int send_socks_response_ipv6_aes(int client_sock, char ver, char req, char rsv, char atyp, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec)
{
	int sen;
	struct socks_response_ipv6 *socks_response_ipv6 = (struct socks_response_ipv6 *)malloc(sizeof(struct socks_response_ipv6));
	
	socks_response_ipv6->ver = ver;		// protocol version
	socks_response_ipv6->req = req;		// Connection refused
	socks_response_ipv6->rsv = rsv;		// RESERVED
	socks_response_ipv6->atyp = atyp;	// IPv6
	bzero(socks_response_ipv6->bnd_addr, 16);	// BND.ADDR
	bzero(socks_response_ipv6->bnd_port, 2);	// BND.PORT
	
	sen = send_data_aes(client_sock, socks_response_ipv6, sizeof(struct socks_response_ipv6), aes_key, aes_iv, tv_sec, tv_usec);
	
	free(socks_response_ipv6);

	return sen;
}


int send_socks_response_ipv6_tls(int client_sock, SSL *client_ssl, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec)
{
	int sen;
	struct socks_response_ipv6 *socks_response_ipv6 = (struct socks_response_ipv6 *)malloc(sizeof(struct socks_response_ipv6));
	
	socks_response_ipv6->ver = ver;		// protocol version
	socks_response_ipv6->req = req;		// Connection refused
	socks_response_ipv6->rsv = rsv;		// RESERVED
	socks_response_ipv6->atyp = atyp;	// IPv6
	bzero(socks_response_ipv6->bnd_addr, 16);	// BND.ADDR
	bzero(socks_response_ipv6->bnd_port, 2);	// BND.PORT
	
	sen = send_data_tls(client_sock, client_ssl, socks_response_ipv6, sizeof(struct socks_response_ipv6), tv_sec, tv_usec);
						
	free(socks_response_ipv6);

	return sen;
}


int worker(void *ptr)
{
	struct worker_param *worker_param = (struct worker_param *)ptr;
	int client_sock = worker_param->client_sock;
	SSL *client_ssl_socks5 = worker_param->client_ssl_socks5;
	int socks5_over_tls_flag = worker_param->socks5_over_tls_flag;	// 0:Socks5 over AES 1:Socks5 over TLS
	unsigned char *aes_key = worker_param->aes_key;
	unsigned char *aes_iv = worker_param->aes_iv;
	long tv_sec = worker_param->tv_sec;		// recv send
	long tv_usec = worker_param->tv_usec;		// recv send
	long forwarder_tv_sec = worker_param->forwarder_tv_sec;
	long forwarder_tv_usec = worker_param->forwarder_tv_usec;
	
	char buffer[BUFFER_SIZE+1];
	bzero(buffer, BUFFER_SIZE+1);
	int rec, sen;
	int err = 0;
	
	
	// socks selection_request
#ifdef _DEBUG
	printf("[I] Receive selection request.\n");
#endif
	if(socks5_over_tls_flag == 0){	// Socks5 over AES
		rec = recv_data_aes(client_sock, buffer, BUFFER_SIZE, aes_key, aes_iv, tv_sec, tv_usec);
	}else{	// Socks5 over TLS
		rec = recv_data_tls(client_sock, client_ssl_socks5, buffer, BUFFER_SIZE, tv_sec, tv_usec);
	}
	if(rec <= 0){
#ifdef _DEBUG
		printf("[E] Receive selection request.\n");
#endif
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Receive selection request:%d bytes.\n", rec);
#endif
	struct selection_request *selection_request = (struct selection_request *)buffer;
	unsigned char method = 0xFF;
	for(int i=0; i<selection_request->nmethods; i++){
		if(selection_request->methods[i] == 0x0 || selection_request->methods[i] == 0x2){	// no authentication required or username/password
			method = selection_request->methods[i];
			break;
		}
	}
	if(method == 0xFF){
#ifdef _DEBUG
		printf("[E] Selection request method error.\n");
#endif
	}


	// socks selection_response
	struct selection_response *selection_response = (struct selection_response *)malloc(sizeof(struct selection_response));
	selection_response->ver = 0x5;		// socks version 5
	selection_response->method = method;	// no authentication required or username/password
	if(selection_request->ver != 0x5 || authentication_method != method){
		selection_response->method = 0xFF;
	}
	if(socks5_over_tls_flag == 0){	// Socks5 over AES
		sen = send_data_aes(client_sock, selection_response, sizeof(struct selection_response), aes_key, aes_iv, tv_sec, tv_usec);
	}else{	// Socks5 over TLS
		sen = send_data_tls(client_sock, client_ssl_socks5, selection_response, sizeof(struct selection_response), tv_sec, tv_usec);
	}
	if(sen <= 0){
#ifdef _DEBUG
		printf("[E] Send selection response.\n");
#endif
		free(selection_response);
		return -1;
	}
	
	free(selection_response);
#ifdef _DEBUG
	printf("[I] Send selection response:%d bytes.\n", sen);
#endif
	
	if(authentication_method != method){
#ifdef _DEBUG
		printf("[E] Authentication method error. server:0x%x client:0x%x\n", authentication_method, method);
#endif
		return -1;
	}


	// socks username_password_authentication
	unsigned char ulen = 0;
	unsigned char plen = 0;
	char uname[256] = {0};
	char passwd[256] = {0};
	if(method == 0x2){
		// socks username_password_authentication_request
#ifdef _DEBUG
		printf("[I] Receive username password authentication request.\n");
#endif
		if(socks5_over_tls_flag == 0){	// Socks5 over AES
			rec = recv_data_aes(client_sock, buffer, BUFFER_SIZE, aes_key, aes_iv, tv_sec, tv_usec);
		}else{	// Socks5 over TLS
			rec = recv_data_tls(client_sock, client_ssl_socks5, buffer, BUFFER_SIZE, tv_sec, tv_usec);
		}
		if(rec <= 0){
#ifdef _DEBUG
			printf("[E] Receive username password authentication request.\n");
#endif
			return -1;
		}
#ifdef _DEBUG
		printf("[I] Receive username password authentication request:%d bytes.\n", rec);
#endif
		struct username_password_authentication_request_tmp *username_password_authentication_request = (struct username_password_authentication_request_tmp *)buffer;

		ulen = username_password_authentication_request->ulen;
		memcpy(uname, &username_password_authentication_request->uname, ulen);
		memcpy(&plen, &username_password_authentication_request->uname + ulen, 1);
		memcpy(passwd, &username_password_authentication_request->uname + ulen + 1, plen);
#ifdef _DEBUG
		printf("[I] uname:%s ulen:%d, passwd:%s plen:%d\n", uname, ulen, passwd, plen);
#endif


		// socks username_password_authentication_response
		struct username_password_authentication_response *username_password_authentication_response = (struct username_password_authentication_response *)malloc(sizeof(struct username_password_authentication_response));
		username_password_authentication_response->ver = 0x1;
		
		if(username_password_authentication_request->ver == 0x1 && !strncmp(uname, username, sizeof(username)) && !strncmp(passwd, password, sizeof(password))){
#ifdef _DEBUG
			printf("[I] Succeed username password authentication.\n");
#endif
			username_password_authentication_response->status = 0x0;
			
			if(socks5_over_tls_flag == 0){	// Socks5 over AES
				sen = send_data_aes(client_sock, username_password_authentication_response, sizeof(struct username_password_authentication_response), aes_key, aes_iv, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = send_data_tls(client_sock, client_ssl_socks5, username_password_authentication_response, sizeof(struct username_password_authentication_response), tv_sec, tv_usec);
			}
			if(sen <= 0){
#ifdef _DEBUG
				printf("[E] Send username password authentication response.\n");
#endif
				
				free(username_password_authentication_response);
				return -1;
			}
#ifdef _DEBUG
			printf("[I] Send username password authentication response:%d bytes.\n", sen);
#endif
			
			free(username_password_authentication_response);
		}else{
#ifdef _DEBUG
			printf("[E] Fail username password authentication.\n");
#endif
			username_password_authentication_response->status = 0xFF;
			
			if(socks5_over_tls_flag == 0){	// Socks5 over AES
				sen = send_data_aes(client_sock, username_password_authentication_response, sizeof(struct username_password_authentication_response), aes_key, aes_iv, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = send_data_tls(client_sock, client_ssl_socks5, username_password_authentication_response, sizeof(struct username_password_authentication_response), tv_sec, tv_usec);
			}
			if(sen <= 0){
#ifdef _DEBUG
				printf("[E] Send username password authentication response.\n");
#endif
			}else{
#ifdef _DEBUG
				printf("[I] Send username password authentication response:%d bytes.\n", sen);
#endif
			}
			
			free(username_password_authentication_response);
			return -1;
		}
	}
	
	
	// socks socks_request
#ifdef _DEBUG
	printf("[I] Receive socks request.\n");
#endif
	bzero(buffer, BUFFER_SIZE+1);
	if(socks5_over_tls_flag == 0){	// Socks5 over AES
		rec = recv_data_aes(client_sock, buffer, BUFFER_SIZE, aes_key, aes_iv, tv_sec, tv_usec);
	}else{	// Socks5 over TLS
		rec = recv_data_tls(client_sock, client_ssl_socks5, buffer, BUFFER_SIZE, tv_sec, tv_usec);
	}
	if(rec <= 0){
#ifdef _DEBUG
		printf("[E] Receive socks request.\n");
#endif
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Receive socks request:%d bytes.\n", rec);
#endif
	
	struct socks_request *socks_request = (struct socks_request *)buffer;
	struct socks_request_ipv4 *socks_request_ipv4;
	struct socks_request_domainname *socks_request_domainname;
	struct socks_request_ipv6 *socks_request_ipv6;
	
	char atyp = socks_request->atyp;
	if(atyp != 0x1 && atyp != 0x3 && atyp != 0x4){
#ifdef _DEBUG
		printf("[E] Socks request atyp(%d) error.\n", atyp);
		printf("[E] Not implemented.\n");
#endif

		// socks socks_response
		if(socks5_over_tls_flag == 0){	// Socks5 over AES
			sen = send_socks_response_ipv4_aes(client_sock, 0x5, 0x8, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
		}else{	// Socks5 over TLS
			sen = send_socks_response_ipv4_tls(client_sock, client_ssl_socks5, 0x5, 0x8, 0x0, 0x1, tv_sec, tv_usec);
		}
		if(sen <= 0){
#ifdef _DEBUG
			printf("[E] Send socks response.\n");
#endif
		}

		return -1;
	}
	
	char cmd = socks_request->cmd;
	if(cmd != 0x1){	// CONNECT only
#ifdef _DEBUG
		printf("[E] Socks request cmd(%d) error.\n", cmd);
		printf("[E] Not implemented.\n");
#endif
		
		// socks socks_response
		if(atyp == 0x1 || atyp == 0x3){	// IPv4
			if(socks5_over_tls_flag == 0){	// Socks5 over AES
				sen = send_socks_response_ipv4_aes(client_sock, 0x5, 0x7, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = send_socks_response_ipv4_tls(client_sock, client_ssl_socks5, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
			}
		}else{	// IPv6
			if(socks5_over_tls_flag == 0){	// Socks5 over AES
				sen = send_socks_response_ipv6_aes(client_sock, 0x5, 0x7, 0x0, 0x4, aes_key, aes_iv, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = send_socks_response_ipv6_tls(client_sock, client_ssl_socks5, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			}
		}
		if(sen <= 0){
#ifdef _DEBUG
			printf("[E] Send socks response.\n");
#endif
		}
		
		return -1;
	}
		
	struct sockaddr_in target_addr, *tmp_ipv4;		// IPv4
	memset(&target_addr, 0, sizeof(struct sockaddr_in));
	
	struct sockaddr_in6 target_addr6, *tmp_ipv6;	// IPv6
	memset(&target_addr6, 0, sizeof(struct sockaddr_in6));
	
	struct addrinfo hints, *target_host;
	memset(&hints, 0, sizeof(struct addrinfo));
	
	int family = 0;
	char domainname[256] = {0};
	u_short domainname_length = 0;
	char *colon;
	
	if(socks_request->atyp == 0x1){	// IPv4
		family = AF_INET;
		target_addr.sin_family = AF_INET;
		socks_request_ipv4 = (struct socks_request_ipv4 *)buffer;
		memcpy(&target_addr.sin_addr.s_addr, &socks_request_ipv4->dst_addr, 4);
		memcpy(&target_addr.sin_port, &socks_request_ipv4->dst_port, 2);
	}else if(socks_request->atyp == 0x3){	// domain name
		socks_request_domainname = (struct socks_request_domainname *)buffer;
		domainname_length = socks_request_domainname->dst_addr_len;
		memcpy(&domainname, &socks_request_domainname->dst_addr, domainname_length);
#ifdef _DEBUG
		printf("[I] Domainname:%s, Length:%d.\n", domainname, domainname_length);
#endif

		colon = strstr(domainname, ":");	// check ipv6 address
		if(colon == NULL){	// ipv4 address or domainname
			hints.ai_family = AF_INET;	// IPv4
			if(getaddrinfo(domainname, NULL, &hints, &target_host) != 0){
				hints.ai_family = AF_INET6;	// IPv6
				if(getaddrinfo(domainname, NULL, &hints, &target_host) != 0){
#ifdef _DEBUG
					printf("[E] Cannot resolv the domain name:%s.\n", (char *)domainname);
#endif
					
					// socks socks_response
					if(socks5_over_tls_flag == 0){	// Socks5 over AES
						sen = send_socks_response_ipv4_aes(client_sock, 0x5, 0x5, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
					}else{	// Socks5 over TLS
						sen = send_socks_response_ipv4_tls(client_sock, client_ssl_socks5, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
					}
					if(sen <= 0){
#ifdef _DEBUG
						printf("[E] Send socks response.\n");
#endif
					}
					
					return -1;
				}
			}
		}else{	// ipv6 address
			hints.ai_family = AF_INET6;	// IPv6
			if(getaddrinfo(domainname, NULL, &hints, &target_host) != 0){
#ifdef _DEBUG
				printf("[E] Cannot resolv the domain name:%s.\n", (char *)domainname);
#endif
				
				// socks socks_response
				if(socks5_over_tls_flag == 0){	// Socks5 over AES
					sen = send_socks_response_ipv6_aes(client_sock, 0x5, 0x5, 0x0, 0x4, aes_key, aes_iv, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = send_socks_response_ipv6_tls(client_sock, client_ssl_socks5, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
				}
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send socks response.\n");
#endif
				}

				return -1;
			}
		}
		
		if(target_host->ai_family == AF_INET){
			family = AF_INET;
			target_addr.sin_family = AF_INET;
			tmp_ipv4 = (struct sockaddr_in *)target_host->ai_addr;
			memcpy(&target_addr.sin_addr, &tmp_ipv4->sin_addr, sizeof(unsigned long));
			memcpy(&target_addr.sin_port, &socks_request_domainname->dst_addr[domainname_length], 2);
			freeaddrinfo(target_host);
		}else if(target_host->ai_family == AF_INET6){
			family = AF_INET6;
			target_addr6.sin6_family = AF_INET6;
			tmp_ipv6 = (struct sockaddr_in6 *)target_host->ai_addr;
			memcpy(&target_addr6.sin6_addr, &tmp_ipv6->sin6_addr, sizeof(struct in6_addr));
			memcpy(&target_addr6.sin6_port, &socks_request_domainname->dst_addr[domainname_length], 2);
			freeaddrinfo(target_host);
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented.\n");
#endif

			// socks socks_response
			if(socks5_over_tls_flag == 0){	// Socks5 over AES
				sen = send_socks_response_ipv4_aes(client_sock, 0x5, 0x1, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = send_socks_response_ipv4_tls(client_sock, client_ssl_socks5, 0x1, 0x5, 0x0, 0x1, tv_sec, tv_usec);
			}
			if(sen <= 0){
#ifdef _DEBUG
				printf("[E] Send socks response.\n");
#endif
			}
			
			freeaddrinfo(target_host);
			return -1;
		}
	}else if(socks_request->atyp == 0x4){	// IPv6
		family = AF_INET6;
		target_addr6.sin6_family = AF_INET6;
		socks_request_ipv6 = (struct socks_request_ipv6 *)buffer;
		memcpy(&target_addr6.sin6_addr, &socks_request_ipv6->dst_addr, 16);
		memcpy(&target_addr6.sin6_port, &socks_request_ipv6->dst_port, 2);
	}else {
#ifdef _DEBUG
		printf("[E] Not implemented.\n");
#endif

		// socks socks_response
		if(socks5_over_tls_flag == 0){	// Socks5 over AES
			sen = send_socks_response_ipv4_aes(client_sock, 0x5, 0x1, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
		}else{	// Socks5 over TLS
			sen = send_socks_response_ipv4_tls(client_sock, client_ssl_socks5, 0x1, 0x5, 0x0, 0x1, tv_sec, tv_usec);
		}
		if(sen <= 0){
#ifdef _DEBUG
			printf("[E] Send socks response.\n");
#endif
		}
		
		return -1;
	}
	
	
	// socks socks_response
	int target_sock;
	char target_addr6_string[INET6_ADDRSTRLEN+1] = {0};
	char *target_addr6_string_pointer = target_addr6_string;
	int flags = 0;
	
	if(atyp == 0x1){	// IPv4
#ifdef _DEBUG
		printf("[I] Connecting. ip:%s port:%d\n", inet_ntoa(target_addr.sin_addr), ntohs(target_addr.sin_port));
#endif

		if(cmd == 0x1){	// CONNECT
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:CONNECT.\n");
#endif
			target_sock = socket(AF_INET, SOCK_STREAM, 0);
			
			// blocking
			flags = fcntl(target_sock, F_GETFL, 0);
			fcntl(target_sock, F_SETFL, flags & ~O_NONBLOCK);
			
			if((err = connect(target_sock, (struct sockaddr *)&target_addr, sizeof(target_addr))) < 0){
#ifdef _DEBUG
				printf("[E] Cannot connect. errno:%d\n", err);
#endif
				
				if(socks5_over_tls_flag == 0){	// Socks5 over AES
					sen = send_socks_response_ipv4_aes(client_sock, 0x5, 0x5, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = send_socks_response_ipv4_tls(client_sock, client_ssl_socks5, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
				}
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send socks response.\n");
#endif
				}else{
#ifdef _DEBUG
					printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
#endif
				}
				
				close_socket(target_sock);

				return -1;
			}

#ifdef _DEBUG
			printf("[I] Connected. ip:%s port:%d\n", inet_ntoa(target_addr.sin_addr), ntohs(target_addr.sin_port));
#endif
			
			if(socks5_over_tls_flag == 0){	// Socks5 over AES
				sen = send_socks_response_ipv4_aes(client_sock, 0x5, 0x0, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = send_socks_response_ipv4_tls(client_sock, client_ssl_socks5, 0x5, 0x0, 0x0, 0x1, tv_sec, tv_usec);
			}
			if(sen <= 0){
#ifdef _DEBUG
				printf("[E] Send socks response.\n");
#endif
				
				close_socket(target_sock);
				return -1;
			}else{
#ifdef _DEBUG
				printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
#endif
			}
			
		}else if(cmd == 0x2){	// BIND
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:BIND.\n");
			printf("[E] Not implemented.\n");
#endif
			
			if(socks5_over_tls_flag == 0){	// Socks5 over AES
				sen = send_socks_response_ipv4_aes(client_sock, 0x5, 0x7, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = send_socks_response_ipv4_tls(client_sock, client_ssl_socks5, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
			}
			if(sen <= 0){
#ifdef _DEBUG
				printf("[E] Send socks response.\n");
#endif
			}
			
			return -1;
			
		}else if(cmd == 0x3){	// UDP ASSOCIATE
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE.\n");
			printf("[E] Not implemented.\n");
#endif
			
			if(socks5_over_tls_flag == 0){	// Socks5 over AES
				sen = send_socks_response_ipv4_aes(client_sock, 0x5, 0x7, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = send_socks_response_ipv4_tls(client_sock, client_ssl_socks5, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
			}
			if(sen <= 0){
#ifdef _DEBUG
				printf("[E] Send socks response.\n");
#endif
			}
			
			return -1;
			
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented.\n");
#endif
			
			if(socks5_over_tls_flag == 0){	// Socks5 over AES
				sen = send_socks_response_ipv4_aes(client_sock, 0x5, 0x1, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = send_socks_response_ipv4_tls(client_sock, client_ssl_socks5, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
			}
			if(sen <= 0){
#ifdef _DEBUG
				printf("[E] Send socks response.\n");
#endif
			}
			
			return -1;
			
		}
	}else if(atyp == 0x3){	// domain name
		if(family == AF_INET){	// IPv4
#ifdef _DEBUG
			printf("[I] Connecting. ip:%s port:%d\n", inet_ntoa(target_addr.sin_addr), ntohs(target_addr.sin_port));
#endif

			if(cmd == 0x1){	// CONNECT
#ifdef _DEBUG
				printf("[I] SOCKS_RESPONSE cmd:CONNECT.\n");
#endif
				target_sock = socket(AF_INET, SOCK_STREAM, 0);
				
				// blocking
				flags = fcntl(target_sock, F_GETFL, 0);
				fcntl(target_sock, F_SETFL, flags & ~O_NONBLOCK);
				
				if((err = connect(target_sock, (struct sockaddr *)&target_addr, sizeof(target_addr))) < 0){
#ifdef _DEBUG
					printf("[E] Cannot connect. errno:%d\n", err);
#endif
					
					if(socks5_over_tls_flag == 0){	// Socks5 over AES
						sen = send_socks_response_ipv4_aes(client_sock, 0x5, 0x5, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
					}else{	// Socks5 over TLS
						sen = send_socks_response_ipv4_tls(client_sock, client_ssl_socks5, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
					}
					if(sen <= 0){
#ifdef _DEBUG
						printf("[E] Send socks response.\n");
#endif
					}else{
#ifdef _DEBUG
						printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
#endif
					}
					
					close_socket(target_sock);
					return -1;
				}

#ifdef _DEBUG
				printf("[I] Connected. ip:%s port:%d\n", inet_ntoa(target_addr.sin_addr), ntohs(target_addr.sin_port));
#endif
				
				if(socks5_over_tls_flag == 0){	// Socks5 over AES
					sen = send_socks_response_ipv4_aes(client_sock, 0x5, 0x0, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = send_socks_response_ipv4_tls(client_sock, client_ssl_socks5, 0x5, 0x0, 0x0, 0x1, tv_sec, tv_usec);
				}
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send socks response.\n");
#endif
					
					close_socket(target_sock);
					return -1;
				}else{
#ifdef _DEBUG
					printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
#endif
				}
				
			}else if(cmd == 0x2){	// BIND
#ifdef _DEBUG
				printf("[I] SOCKS_RESPONSE cmd:BIND.\n");
				printf("[E] Not implemented.\n");
#endif
				
				if(socks5_over_tls_flag == 0){	// Socks5 over AES
					sen = send_socks_response_ipv4_aes(client_sock, 0x5, 0x7, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = send_socks_response_ipv4_tls(client_sock, client_ssl_socks5, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
				}
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send socks response.\n");
#endif
				}
				
				return -1;
				
			}else if(cmd == 0x3){	// UDP ASSOCIATE
#ifdef _DEBUG
				printf("[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE.\n");
				printf("[E] Not implemented.\n");
#endif
				
				if(socks5_over_tls_flag == 0){	// Socks5 over AES
					sen = send_socks_response_ipv4_aes(client_sock, 0x5, 0x7, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = send_socks_response_ipv4_tls(client_sock, client_ssl_socks5, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
				}
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send socks response.\n");
#endif
				}
				
				return -1;
				
			}else{
#ifdef _DEBUG
				printf("[E] Not implemented.\n");
#endif
				
				if(socks5_over_tls_flag == 0){	// Socks5 over AES
					sen = send_socks_response_ipv4_aes(client_sock, 0x5, 0x1, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = send_socks_response_ipv4_tls(client_sock, client_ssl_socks5, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
				}
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send socks response.\n");
#endif
				}
				
				return -1;
				
			}
		}else if(family == AF_INET6){	// IPv6
			inet_ntop(AF_INET6, &target_addr6.sin6_addr, target_addr6_string_pointer, INET6_ADDRSTRLEN);
#ifdef _DEBUG
			printf("[I] Connecting. ip:%s port:%d\n", target_addr6_string_pointer, ntohs(target_addr6.sin6_port));
#endif

			if(cmd == 0x1){	// CONNECT
#ifdef _DEBUG
				printf("[I] SOCKS_RESPONSE cmd:CONNECT.\n");
#endif
				target_sock = socket(AF_INET6, SOCK_STREAM, 0);

				// blocking
				flags = fcntl(target_sock, F_GETFL, 0);
				fcntl(target_sock, F_SETFL, flags & ~O_NONBLOCK);
				
				if((err = connect(target_sock, (struct sockaddr *)&target_addr6, sizeof(target_addr6))) < 0){
#ifdef _DEBUG
					printf("[E] Cannot connect. errno:%d\n", err);
#endif
					
					if(socks5_over_tls_flag == 0){	// Socks5 over AES
						sen = send_socks_response_ipv6_aes(client_sock, 0x5, 0x5, 0x0, 0x4, aes_key, aes_iv, tv_sec, tv_usec);
					}else{	// Socks5 over TLS
						sen = send_socks_response_ipv6_tls(client_sock, client_ssl_socks5, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
					}
					if(sen <= 0){
#ifdef _DEBUG
						printf("[E] Send socks response.\n");
#endif
					}else{
#ifdef _DEBUG
						printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
#endif
					}
					
					close_socket(target_sock);
					return -1;
				}

#ifdef _DEBUG
				printf("[I] Connected. ip:%s port:%d\n", target_addr6_string_pointer, ntohs(target_addr6.sin6_port));
#endif
				
				if(socks5_over_tls_flag == 0){	// Socks5 over AES
					sen = send_socks_response_ipv6_aes(client_sock, 0x5, 0x0, 0x0, 0x4, aes_key, aes_iv, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = send_socks_response_ipv6_tls(client_sock, client_ssl_socks5, 0x5, 0x0, 0x0, 0x4, tv_sec, tv_usec);
				}
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send socks response.\n");
#endif
					close_socket(target_sock);
					return -1;
				}else{
#ifdef _DEBUG
					printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
#endif
				}
				
			}else if(cmd == 0x2){	// BIND
#ifdef _DEBUG
				printf("[I] SOCKS_RESPONSE cmd:BIND.\n");
				printf("[E] Not implemented.\n");
#endif
				
				if(socks5_over_tls_flag == 0){	// Socks5 over AES
					sen = send_socks_response_ipv6_aes(client_sock, 0x5, 0x7, 0x0, 0x4, aes_key, aes_iv, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = send_socks_response_ipv6_tls(client_sock, client_ssl_socks5, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
				}
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send socks response.\n");
#endif
				}
				
				return -1;
				
			}else if(cmd == 0x3){	// UDP ASSOCIATE
#ifdef _DEBUG
				printf("[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE.\n");
				printf("[E] Not implemented.\n");
#endif
				
				if(socks5_over_tls_flag == 0){	// Socks5 over AES
					sen = send_socks_response_ipv6_aes(client_sock, 0x5, 0x7, 0x0, 0x4, aes_key, aes_iv, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = send_socks_response_ipv6_tls(client_sock, client_ssl_socks5, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
				}
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send socks response.\n");
#endif
				}
				
				return -1;
				
			}else{
#ifdef _DEBUG
				printf("[E] Not implemented.\n");
#endif
				
				if(socks5_over_tls_flag == 0){	// Socks5 over AES
					sen = send_socks_response_ipv4_aes(client_sock, 0x5, 0x1, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = send_socks_response_ipv4_tls(client_sock, client_ssl_socks5, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
				}
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send socks response.\n");
#endif
				}
				
				return -1;
				
			}		
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented.\n");
#endif
			
			if(socks5_over_tls_flag == 0){	// Socks5 over AES
				sen = send_socks_response_ipv4_aes(client_sock, 0x5, 0x1, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = send_socks_response_ipv4_tls(client_sock, client_ssl_socks5, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
			}
			if(sen <= 0){
#ifdef _DEBUG
				printf("[E] Send socks response.\n");
#endif
			}
			
			return -1;
			
		}
	}else if(atyp == 0x4){	// IPv6
		inet_ntop(AF_INET6, &target_addr6.sin6_addr, target_addr6_string_pointer, INET6_ADDRSTRLEN);
#ifdef _DEBUG
		printf("[I] Connecting. ip:%s port:%d\n", target_addr6_string_pointer, ntohs(target_addr6.sin6_port));
#endif

		if(cmd == 0x1){	// CONNECT
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:CONNECT.\n");
#endif
			target_sock = socket(AF_INET6, SOCK_STREAM, 0);
			
			// blocking
			flags = fcntl(target_sock, F_GETFL, 0);
			fcntl(target_sock, F_SETFL, flags & ~O_NONBLOCK);
			
			if((err = connect(target_sock, (struct sockaddr *)&target_addr6, sizeof(target_addr6))) < 0){
#ifdef _DEBUG
				printf("[E] Cannot connect. errno:%d\n", err);
#endif
				
				if(socks5_over_tls_flag == 0){	// Socks5 over AES
					sen = send_socks_response_ipv6_aes(client_sock, 0x5, 0x5, 0x0, 0x4, aes_key, aes_iv, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = send_socks_response_ipv6_tls(client_sock, client_ssl_socks5, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
				}
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send socks response.\n");
#endif
				}else{
#ifdef _DEBUG
					printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
#endif
				}
				
				close_socket(target_sock);
				return -1;
			}

#ifdef _DEBUG
			printf("[I] Connected. ip:%s port:%d\n", target_addr6_string_pointer, ntohs(target_addr6.sin6_port));
#endif
			
			if(socks5_over_tls_flag == 0){	// Socks5 over AES
				sen = send_socks_response_ipv6_aes(client_sock, 0x5, 0x0, 0x0, 0x4, aes_key, aes_iv, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = send_socks_response_ipv6_tls(client_sock, client_ssl_socks5, 0x5, 0x0, 0x0, 0x4, tv_sec, tv_usec);
			}
			if(sen <= 0){
#ifdef _DEBUG
				printf("[E] Send socks response.\n");
#endif
				
				close_socket(target_sock);
				return -1;
			}else{
#ifdef _DEBUG
				printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
#endif
			}

		}else if(cmd == 0x2){	// BIND
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:BIND.\n");
			printf("[E] Not implemented.\n");
#endif
			
			if(socks5_over_tls_flag == 0){	// Socks5 over AES
				sen = send_socks_response_ipv6_aes(client_sock, 0x5, 0x7, 0x0, 0x4, aes_key, aes_iv, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = send_socks_response_ipv6_tls(client_sock, client_ssl_socks5, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			}
			if(sen <= 0){
#ifdef _DEBUG
				printf("[E] Send socks response.\n");
#endif
			}
			
			return -1;
			
		}else if(cmd == 0x3){	// UDP ASSOCIATE
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE.\n");
			printf("[E] Not implemented.\n");
#endif
			
			if(socks5_over_tls_flag == 0){	// Socks5 over AES
				sen = send_socks_response_ipv6_aes(client_sock, 0x5, 0x7, 0x0, 0x4, aes_key, aes_iv, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = send_socks_response_ipv6_tls(client_sock, client_ssl_socks5, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			}
			if(sen <= 0){
#ifdef _DEBUG
				printf("[E] Send socks response.\n");
#endif
			}
			
			return -1;
			
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented.\n");
#endif
			
			if(socks5_over_tls_flag == 0){	// Socks5 over AES
				sen = send_socks_response_ipv6_aes(client_sock, 0x5, 0x1, 0x0, 0x4, aes_key, aes_iv, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = send_socks_response_ipv6_tls(client_sock, client_ssl_socks5, 0x5, 0x1, 0x0, 0x4, tv_sec, tv_usec);
			}
			if(sen <= 0){
#ifdef _DEBUG
				printf("[E] Send socks response.\n");
#endif
			}
			
			return -1;
			
		}
	}else{
#ifdef _DEBUG
		printf("[E] Not implemented.\n");
#endif
		
		if(socks5_over_tls_flag == 0){	// Socks5 over AES
			sen = send_socks_response_ipv4_aes(client_sock, 0x5, 0x1, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
		}else{	// Socks5 over TLS
			sen = send_socks_response_ipv4_tls(client_sock, client_ssl_socks5, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
		}
		if(sen <= 0){
#ifdef _DEBUG
				printf("[E] Send socks response.\n");
#endif
		}
		
		return -1;
	}
	
	
	// forwarder
#ifdef _DEBUG
	printf("[I] Forwarder.\n");
#endif
	if(socks5_over_tls_flag == 0){	// Socks5 over AES
		err = forwarder_aes(client_sock, target_sock, aes_key, aes_iv, forwarder_tv_sec, forwarder_tv_usec);
	}else{	// Socks5 over TLS
		err = forwarder_tls(client_sock, target_sock, client_ssl_socks5, forwarder_tv_sec, forwarder_tv_usec);
	}
	
#ifdef _DEBUG
	printf("[I] Worker exit.\n");
#endif
	close_socket(target_sock);
	
	return 0;
}


int ssl_accept_non_blocking(int sock, SSL *ssl, long tv_sec, long tv_usec)
{
	fd_set readfds;
	fd_set writefds;
	int nfds = -1;
	struct timeval tv;
	struct timeval start;
	struct timeval end;
	long t = 0;
	int ret = 0;
	int err = 0;
	int flags = 0;
	
	// non blocking
	flags = fcntl(sock, F_GETFL, 0);
	fcntl(sock, F_SETFL, flags | O_NONBLOCK);
	
	if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
		printf("[E] gettimeofday error.\n");
#endif
		// blocking
		flags = fcntl(sock, F_GETFL, 0);
		fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
		return -2;
	}

	while(1){
		FD_ZERO(&readfds);
		FD_ZERO(&writefds);
		FD_SET(sock, &readfds);
		FD_SET(sock, &writefds);
		nfds = sock + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, &readfds, &writefds, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] ssl_accept_non_blocking select timeout.\n");
#endif
			// blocking
			flags = fcntl(sock, F_GETFL, 0);
			fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
			return -2;
		}
		
		if(FD_ISSET(sock, &readfds) || FD_ISSET(sock, &writefds)){
			ret = SSL_accept(ssl);
			err = SSL_get_error(ssl, ret);
			
			if(err == SSL_ERROR_NONE){
				break;
			}else if(err == SSL_ERROR_WANT_READ){
				usleep(5000);
			}else if(err == SSL_ERROR_WANT_WRITE){
				usleep(5000);
			}else{
#ifdef _DEBUG
				printf("[E] SSL_accept error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
				// blocking
				flags = fcntl(sock, F_GETFL, 0);
				fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
				return -2;
			}
		}
		
		if(gettimeofday(&end, NULL) == -1){
#ifdef _DEBUG
			printf("[E] gettimeofday error.\n");
#endif
			// blocking
			flags = fcntl(sock, F_GETFL, 0);
			fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
			return -2;
		}
		
		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec)){
#ifdef _DEBUG
			printf("[I] ssl_accept_non_blocking timeout.\n");
#endif
			// blocking
			flags = fcntl(sock, F_GETFL, 0);
			fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
			return -2;
		}
	}
	
	// blocking
	flags = fcntl(sock, F_GETFL, 0);
	fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
	
	return ret;
}


void fini_ssl(struct ssl_param *param)
{
	// Socks5 over TLS
	if(param->client_ssl_socks5 != NULL){
		SSL_shutdown(param->client_ssl_socks5);
		SSL_free(param->client_ssl_socks5);
	}
	if(param->client_ctx_socks5 != NULL){
		SSL_CTX_free(param->client_ctx_socks5);
	}
	
	return;
}


void close_socket(int sock)
{
	shutdown(sock, SHUT_RDWR);
	usleep(500);
	close(sock);
	
	return;
}


static int socks5_post_read_request(request_rec *r)
{

	const apr_array_header_t *fields;
	fields = apr_table_elts(r->headers_in);
	apr_table_entry_t *e = 0;
	e = (apr_table_entry_t *) fields->elts;
	int i = 0;
	int socks5_flag = 0;
	
	extern module core_module;
	apr_socket_t *client_socket;
	int client_sock = -1;
	int flags = 0;
	int ret = 0;
	int err = 0;
	int rec, sen;
	int socks5_over_tls_flag = 0;	// 0:socks5 over aes 1:socks5 over tls
	
	SSL_CTX *client_ctx_socks5 = NULL;
	SSL *client_ssl_socks5 = NULL;
	
	struct worker_param worker_param;
	long tv_sec = 3;	// recv send
	long tv_usec = 0;	// recv send
	long forwarder_tv_sec = 3;
	long forwarder_tv_usec = 0;
	struct ssl_param ssl_param;
	ssl_param.client_ctx_socks5 = NULL;
	ssl_param.client_ssl_socks5 = NULL;

	BIO *bio = NULL;
	EVP_PKEY *s_privatekey_socks5 = NULL;
	X509 *s_cert_socks5 = NULL;
	
	EVP_ENCODE_CTX *base64_encode_ctx = NULL;
	int length = 0;
	unsigned char aes_key_b64[45];
	unsigned char aes_iv_b64[25];
	unsigned char aes_key[33];
	unsigned char aes_iv[17];
	bzero(&aes_key_b64, 45);
	bzero(&aes_iv_b64, 25);
	bzero(&aes_key, 33);
	bzero(&aes_iv, 17);
	
	
	// search header
	for(i = 0; i < fields->nelts; i++){
#ifdef _DEBUG
		printf("[I] e[%d].key:%s e[%d].val:%s\n", i, e[i].key, i, e[i].val);
#endif
		if(!strncmp(e[i].key, HTTP_REQUEST_HEADER_SOCKS5_KEY, strlen(HTTP_REQUEST_HEADER_SOCKS5_KEY))){
			if(!strncmp(e[i].val, HTTP_REQUEST_HEADER_SOCKS5_VALUE, strlen(HTTP_REQUEST_HEADER_SOCKS5_VALUE)+1)){	// socks5
				socks5_flag = 1;
			}
		}else if(!strncmp(e[i].key, HTTP_REQUEST_HEADER_AESKEY_KEY, strlen(HTTP_REQUEST_HEADER_AESKEY_KEY)+1)){	// aes key
			memcpy(&aes_key_b64, e[i].val, 44);
			base64_encode_ctx = EVP_ENCODE_CTX_new();
			EVP_DecodeInit(base64_encode_ctx);
			EVP_DecodeUpdate(base64_encode_ctx, (unsigned char *)aes_key, &length, (unsigned char *)aes_key_b64, 44);
			EVP_DecodeFinal(base64_encode_ctx, (unsigned char *)aes_key, &length);
			EVP_ENCODE_CTX_free(base64_encode_ctx);
#ifdef _DEBUG
			printf("[I] aes_key_b64:%s\n", aes_key_b64);
#endif
		}else if(!strncmp(e[i].key, HTTP_REQUEST_HEADER_AESIV_KEY, strlen(HTTP_REQUEST_HEADER_AESIV_KEY)+1)){	// aes iv
			memcpy(&aes_iv_b64, e[i].val, 24);
			base64_encode_ctx = EVP_ENCODE_CTX_new();
			EVP_DecodeInit(base64_encode_ctx);
			EVP_DecodeUpdate(base64_encode_ctx, (unsigned char *)aes_iv, &length, (unsigned char *)aes_iv_b64, 24);
			EVP_DecodeFinal(base64_encode_ctx, (unsigned char *)aes_iv, &length);
			EVP_ENCODE_CTX_free(base64_encode_ctx);
#ifdef _DEBUG
			printf("[I] aes_iv_b64:%s\n", aes_iv_b64);
#endif
		}else if(!strncmp(e[i].key, HTTP_REQUEST_HEADER_TLS_KEY, strlen(HTTP_REQUEST_HEADER_TLS_KEY)+1)){
			if(!strncmp(e[i].val, HTTP_REQUEST_HEADER_TLS_VALUE2, strlen(HTTP_REQUEST_HEADER_TLS_VALUE2)+1)){
				socks5_over_tls_flag = 1;	// Socks5 over TLS
			}else{
				socks5_over_tls_flag = 0;	// Socks5 over AES
			}
		}else if(!strncmp(e[i].key, HTTP_REQUEST_HEADER_TVSEC_KEY, strlen(HTTP_REQUEST_HEADER_TVSEC_KEY)+1)){
			tv_sec = atol(e[i].val);
		}else if(!strncmp(e[i].key, HTTP_REQUEST_HEADER_TVUSEC_KEY, strlen(HTTP_REQUEST_HEADER_TVUSEC_KEY)+1)){
			tv_usec = atol(e[i].val);
		}else if(!strncmp(e[i].key, HTTP_REQUEST_HEADER_FORWARDER_TVSEC_KEY, strlen(HTTP_REQUEST_HEADER_FORWARDER_TVSEC_KEY)+1)){
			forwarder_tv_sec = atol(e[i].val);
		}else if(!strncmp(e[i].key, HTTP_REQUEST_HEADER_FORWARDER_TVUSEC_KEY, strlen(HTTP_REQUEST_HEADER_FORWARDER_TVUSEC_KEY)+1)){
			forwarder_tv_usec = atol(e[i].val);
		}
	}
	
	
	if(socks5_flag == 1){	// socks5
#ifdef _DEBUG
		printf("[I] Socks5 start.\n");
#endif
		
		if(tv_sec < 0 || tv_sec > 10 || tv_usec < 0 || tv_usec > 1000000){
			tv_sec = 3;
			tv_usec = 0;
		}else if(tv_sec == 0 && tv_usec == 0){
			tv_sec = 3;
			tv_usec = 0;
		}
		
		if(forwarder_tv_sec < 0 || forwarder_tv_sec > 300 || forwarder_tv_usec < 0 || forwarder_tv_usec > 1000000){
			forwarder_tv_sec = 3;
			forwarder_tv_usec = 0;
		}else if(forwarder_tv_sec == 0 && forwarder_tv_usec == 0){
			forwarder_tv_sec = 3;
			forwarder_tv_usec = 0;
		}
#ifdef _DEBUG
		printf("[I] Timeout recv/send tv_sec:%ld sec recv/send tv_usec:%ld microsec.\n", tv_sec, tv_usec);
		printf("[I] Timeout forwarder tv_sec:%ld sec forwarder tv_usec:%ld microsec.\n", forwarder_tv_sec, forwarder_tv_usec);
#endif
		
		client_socket = ap_get_module_config(r->connection->conn_config, &core_module);
		if(client_socket){
			client_sock = client_socket->socketdes;
		}

		// blocking
		flags = fcntl(client_sock, F_GETFL, 0);
		fcntl(client_sock, F_SETFL, flags & ~O_NONBLOCK);
		
		// send OK to client
		sen = send_data_aes(client_sock, "OK", strlen("OK"), aes_key, aes_iv, tv_sec, tv_usec);
#ifdef _DEBUG
		printf("[I] Send OK message.\n");
#endif
		
		if(socks5_over_tls_flag == 1){	// Socks5 over TLS
			// SSL Initialize
			OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
			
			// SSL TLS connection
			client_ctx_socks5 = SSL_CTX_new(TLS_server_method());
			if(client_ctx_socks5 == NULL){
#ifdef _DEBUG
				printf("[E] SSL_CTX_new error.\n");
#endif
				return DECLINED;
			}
			ssl_param.client_ctx_socks5 = client_ctx_socks5;
			
			// server private key (Socks5 over TLS)
			bio = BIO_new(BIO_s_mem());
			BIO_write(bio, server_privatekey_socks5, strlen(server_privatekey_socks5));
			PEM_read_bio_PrivateKey(bio, &s_privatekey_socks5, NULL, NULL);
			BIO_free(bio);
			
			// server X509 certificate (Socks5 over TLS)
			bio = BIO_new(BIO_s_mem());
			BIO_write(bio, server_certificate_socks5, strlen(server_certificate_socks5));
			PEM_read_bio_X509(bio, &s_cert_socks5, NULL, NULL);
			BIO_free(bio);

			SSL_CTX_use_certificate(client_ctx_socks5, s_cert_socks5);
			SSL_CTX_use_PrivateKey(client_ctx_socks5, s_privatekey_socks5);
			err = SSL_CTX_check_private_key(client_ctx_socks5);
			if(err != 1){
#ifdef _DEBUG
				printf("[E] SSL_CTX_check_private_key error.\n");
#endif
				fini_ssl(&ssl_param);
				return DECLINED;
			}
			
//			SSL_CTX_set_mode(client_ctx_socks5, SSL_MODE_AUTO_RETRY);
			
			if(SSL_CTX_set_min_proto_version(client_ctx_socks5, TLS1_2_VERSION) == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_min_proto_version error.\n");
#endif
				fini_ssl(&ssl_param);
				return DECLINED;
			}
			
			ret = SSL_CTX_set_cipher_list(client_ctx_socks5, cipher_suite_tls_1_2);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_cipher_list error.\n");
#endif
				fini_ssl(&ssl_param);
				return DECLINED;
			}
			
			ret = SSL_CTX_set_ciphersuites(client_ctx_socks5, cipher_suite_tls_1_3);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_ciphersuites error.\n");
#endif
				fini_ssl(&ssl_param);
				return DECLINED;
			}
			
			client_ssl_socks5 = SSL_new(client_ctx_socks5);
			if(client_ssl_socks5 == NULL){
#ifdef _DEBUG
				printf("[E] SSL_new error.\n");
#endif
				fini_ssl(&ssl_param);
				return DECLINED;
			}
			ssl_param.client_ssl_socks5 = client_ssl_socks5;
			
			if(SSL_set_fd(client_ssl_socks5, client_sock) == 0){
#ifdef _DEBUG
				printf("[E] SSL_set_fd error.\n");
#endif
				fini_ssl(&ssl_param);
				return DECLINED;
			}
			
			// accept
#ifdef _DEBUG
			printf("[I] Try Socks5 over TLS connection. (SSL_accept)\n");
#endif
			ret = ssl_accept_non_blocking(client_sock, client_ssl_socks5, tv_sec, tv_usec);
			if(ret == -2){
#ifdef _DEBUG
				printf("[E] SSL_accept error.\n");
#endif
				fini_ssl(&ssl_param);
				return DECLINED;
			}
#ifdef _DEBUG
			printf("[I] Succeed Socks5 over TLS connection. (SSL_accept)\n");
#endif
		}
		
		worker_param.client_sock = client_sock;
		worker_param.client_ssl_socks5 = client_ssl_socks5;
		worker_param.socks5_over_tls_flag = socks5_over_tls_flag;
		worker_param.aes_key = (unsigned char *)aes_key;
		worker_param.aes_iv = (unsigned char *)aes_iv;
		worker_param.tv_sec = tv_sec;
		worker_param.tv_usec = tv_usec;
		worker_param.forwarder_tv_sec = forwarder_tv_sec;
		worker_param.forwarder_tv_usec = forwarder_tv_usec;
		
		ret = worker(&worker_param);
		
		fini_ssl(&ssl_param);
	}

    return DECLINED;
}

static void socks5_register_hooks(apr_pool_t *p)
{
    ap_hook_post_read_request((void *)socks5_post_read_request, NULL, NULL, APR_HOOK_FIRST);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA socks5_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    NULL,                  /* table of config file commands       */
    socks5_register_hooks  /* register hooks                      */
};

