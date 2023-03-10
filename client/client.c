/*
 * Title:  socks5 client (apache module)
 * Author: Shuichiro Endo
 */

#define _DEBUG

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "socks5.h"
#include "client.h"

#define HTTP_REQUEST_HEADER_SOCKS5_KEY "socks5"
#define HTTP_REQUEST_HEADER_SOCKS5_VALUE "socks5"
#define HTTP_REQUEST_HEADER_TLS_KEY "tls"
#define HTTP_REQUEST_HEADER_TLS_VALUE1 "off"	// Socks5
#define HTTP_REQUEST_HEADER_TLS_VALUE2 "on"	// Socks5 over TLS

char *socks5ServerIp = NULL;
char *socks5ServerPort = NULL;
char *socks5TargetIp = NULL;
char *socks5TargetPort = NULL;
int httpsFlag = 0;	// 0:http 1:https
int socks5OverTlsFlag = 0;	// 0:socks5 1:socks5 over tls
long tv_sec = 300;
long tv_usec = 0;

char serverCertificateFilenameHttps[256] = "server_https.crt";	// server certificate file name (HTTPS)
char serverCertificateFileDirectoryPathHttps[256] = ".";	// server certificate file directory path (HTTPS)

char serverCertificateFilenameSocks5[256] = "server_socks5.crt";	// server certificate file name (Socks5 over TLS)
char serverCertificateFileDirectoryPathSocks5[256] = ".";	// server certificate file directory path (Socks5 over TLS)


int recvData(int sock, void *buffer, int length)
{
	int rec = 0;

	while(1){
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
	
	return rec;
}


int recvDataTls(SSL *ssl ,void *buffer, int length)
{
	int rec = 0;
	int err = 0;

	while(1){
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
	
	return rec;
}


int sendData(int sock, void *buffer, int length)
{
	int sen = 0;
	int sendLength = 0;
	int len = length;
	
	while(len > 0){
		sen = send(sock, buffer+sendLength, len, 0);
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
		sendLength += sen;
		len -= sen;
	}
	
	return sendLength;
}


int sendDataTls(SSL *ssl, void *buffer, int length)
{
	int sen = 0;
	int err = 0;

	while(1){
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
		
	return sen;
}


int forwarder(int clientSock, int targetSock)
{

	int rec,sen;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	char buffer[BUFSIZ+1];
	bzero(buffer, BUFSIZ+1);
	
	while(1){
		FD_ZERO(&readfds);
		FD_SET(clientSock, &readfds);
		FD_SET(targetSock, &readfds);
		nfds = (clientSock > targetSock ? clientSock : targetSock) + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] Forwarder timeout.\n");
#endif
			break;
		}
		
		if(FD_ISSET(clientSock, &readfds)){
			if((rec = read(clientSock, buffer, BUFSIZ)) > 0){
				sen = write(targetSock, buffer, rec);
				if(sen <= 0){
					break;
				}
			}else{
				break;
			}
		}
		
		if(FD_ISSET(targetSock, &readfds)){
			if((rec = read(targetSock, buffer, BUFSIZ)) > 0){
				sen = write(clientSock, buffer, rec);
				if(sen <= 0){
					break;
				}
			}else{
				break;
			}
		}
	}

	return 0;
}


int forwarderTls(int clientSock, int targetSock, SSL *targetSsl)
{
	int rec,sen;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	char buffer[BUFSIZ+1];
	bzero(buffer, BUFSIZ+1);
	int err = 0;
	
	while(1){
		FD_ZERO(&readfds);
		FD_SET(clientSock, &readfds);
		FD_SET(targetSock, &readfds);
		nfds = (clientSock > targetSock ? clientSock : targetSock) + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] Forwarder timeout.\n");
#endif
			break;
		}
		
		if(FD_ISSET(clientSock, &readfds)){
			if((rec = read(clientSock, buffer, BUFSIZ)) > 0){
				while(1){
					sen = SSL_write(targetSsl, buffer, rec);
					err = SSL_get_error(targetSsl, sen);
					
					if(err == SSL_ERROR_NONE){
						break;
					}else if(err == SSL_ERROR_WANT_WRITE){
						usleep(5000);
					}else if(err == SSL_ERROR_WANT_READ){
						usleep(5000);
					}else{
#ifdef _DEBUG
						printf("[E] SSL_read error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
						return -2;
					}
				}
			}else{
				break;
			}
		}
		
		if(FD_ISSET(targetSock, &readfds)){
			rec = SSL_read(targetSsl, buffer, BUFSIZ);
			err = SSL_get_error(targetSsl, rec);
			
			if(err == SSL_ERROR_NONE){
				sen = write(clientSock, buffer, rec);
				if(sen <= 0){
					break;
				}
			}else if(err == SSL_ERROR_ZERO_RETURN){
				break;
			}else if(err == SSL_ERROR_WANT_READ){
				usleep(5000);
			}else if(err == SSL_ERROR_WANT_WRITE){
				usleep(5000);
			}else{
#ifdef _DEBUG
				printf("[E] SSL_write error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
				return -2;
			}
		}
	}

	return 0;
}


void finiSsl(pSSLPARAM pSslParam)
{
	// Socks5 over TLS
	if(pSslParam->targetSslSocks5 != NULL){
		SSL_shutdown(pSslParam->targetSslSocks5);
		SSL_free(pSslParam->targetSslSocks5);
	}
	if(pSslParam->targetCtxSocks5 != NULL){
		SSL_CTX_free(pSslParam->targetCtxSocks5);
	}
	
	// HTTPS
	if(pSslParam->targetSslHttp != NULL){
		SSL_shutdown(pSslParam->targetSslHttp);
		SSL_free(pSslParam->targetSslHttp);
	}
	if(pSslParam->targetCtxHttp != NULL){
		SSL_CTX_free(pSslParam->targetCtxHttp);
	}

	return;
}


int worker(void *ptr)
{
	pPARAM pParam = (pPARAM)ptr;
	int clientSock = pParam->clientSock;
	
	int targetSock = -1;
	struct sockaddr_in targetAddr, *pTmpIpv4;		// IPv4
	memset(&targetAddr, 0, sizeof(struct sockaddr_in));
	
	struct sockaddr_in6 targetAddr6, *pTmpIpv6;	// IPv6
	memset(&targetAddr6, 0, sizeof(struct sockaddr_in6));

	struct addrinfo hints, *pTargetHost;
	memset(&hints, 0, sizeof(struct addrinfo));	

	int family = 0;
	char *domainname = socks5TargetIp;
	u_short domainnameLength = strlen(domainname);
	char *colon = NULL;
	char *service = socks5TargetPort;
	int flags = 0;
	
	int ret = 0;
	int err = 0;
	
	SSL_CTX *targetCtxHttp = NULL;
	SSL *targetSslHttp = NULL;
	SSL_CTX *targetCtxSocks5 = NULL;
	SSL *targetSslSocks5 = NULL;

	SSLPARAM sslParam;
	sslParam.targetCtxHttp = NULL;
	sslParam.targetSslHttp = NULL;
	sslParam.targetCtxSocks5 = NULL;
	sslParam.targetSslSocks5 = NULL;

	char buffer[BUFSIZ+1];
	bzero(&buffer, BUFSIZ+1);
	int rec, sen;
	int count = 0;
	int check = 0;
	
	char httpRequest[BUFSIZ+1];
	int httpRequestLength = 0;
	bzero(httpRequest, BUFSIZ+1);


#ifdef _DEBUG
	printf("[I] Domainname:%s, Length:%d.\n", domainname, domainnameLength);
#endif
	colon = strstr(domainname, ":");	// check ipv6 address
	if(colon == NULL){	// ipv4 address or domainname
		hints.ai_family = AF_INET;	// IPv4
		if(getaddrinfo(domainname, service, &hints, &pTargetHost) != 0){
			hints.ai_family = AF_INET6;	// IPv6
			if(getaddrinfo(domainname, service, &hints, &pTargetHost) != 0){
#ifdef _DEBUG
				printf("[E] Cannnot resolv the domain name:%s.\n", domainname);
#endif
				close(clientSock);
				return -1;
			}
		}
	}else{	// ipv6 address
		hints.ai_family = AF_INET6;	// IPv6
		if(getaddrinfo(domainname, service, &hints, &pTargetHost) != 0){
#ifdef _DEBUG
			printf("[E] Cannnot resolv the domain name:%s.\n", domainname);
#endif
			close(clientSock);
			return -1;
		}
	}

	if(pTargetHost->ai_family == AF_INET){
		family = AF_INET;
		targetAddr.sin_family = AF_INET;
		pTmpIpv4 = (struct sockaddr_in *)pTargetHost->ai_addr;
		memcpy(&targetAddr.sin_addr, &pTmpIpv4->sin_addr, sizeof(unsigned long));
		memcpy(&targetAddr.sin_port, &pTmpIpv4->sin_port, 2);
		freeaddrinfo(pTargetHost);
	}else if(pTargetHost->ai_family == AF_INET6){
		family = AF_INET6;
		targetAddr6.sin6_family = AF_INET6;
		pTmpIpv6 = (struct sockaddr_in6 *)pTargetHost->ai_addr;
		memcpy(&targetAddr6.sin6_addr, &pTmpIpv6->sin6_addr, sizeof(struct in6_addr));		
		memcpy(&targetAddr6.sin6_port, &pTmpIpv6->sin6_port, 2);;
		freeaddrinfo(pTargetHost);
	}else{
#ifdef _DEBUG
		printf("[E] Not implemented.\n");
#endif
		freeaddrinfo(pTargetHost);
		close(clientSock);
		return -1;
	}

	if(family == AF_INET){	// IPv4
		targetSock = socket(AF_INET, SOCK_STREAM, 0);

		flags = fcntl(targetSock, F_GETFL, 0);
		flags &= ~O_NONBLOCK;
		fcntl(targetSock, F_SETFL, flags);
				
		if(err = connect(targetSock, (struct sockaddr *)&targetAddr, sizeof(targetAddr)) < 0){
#ifdef _DEBUG
			printf("[E] Connect failed. errno:%d\n", err);
#endif
			close(targetSock);
			close(clientSock);
			return -1;
		}
	}else if(family == AF_INET6){	// IPv6
		targetSock = socket(AF_INET6, SOCK_STREAM, 0);
		
		flags = fcntl(targetSock, F_GETFL, 0);
		flags &= ~O_NONBLOCK;
		fcntl(targetSock, F_SETFL, flags);
				
		if(err = connect(targetSock, (struct sockaddr *)&targetAddr6, sizeof(targetAddr6)) < 0){
#ifdef _DEBUG
			printf("[E] Connect failed. errno:%d\n", err);
#endif
			close(targetSock);
			close(clientSock);
			return -1;
		}
	}else{
#ifdef _DEBUG
		printf("[E] Not implemented.\n");
#endif
		close(clientSock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Connect target socks5 server.\n");
#endif

	if(socks5OverTlsFlag == 0){	// Socks5
		httpRequestLength = snprintf(httpRequest, BUFSIZ+1, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n%s: %s\r\n%s: %s\r\nConnection: close\r\n\r\n", domainname, HTTP_REQUEST_HEADER_SOCKS5_KEY, HTTP_REQUEST_HEADER_SOCKS5_VALUE, HTTP_REQUEST_HEADER_TLS_KEY, HTTP_REQUEST_HEADER_TLS_VALUE1);
	}else{	// Socks5 over TLS
		httpRequestLength = snprintf(httpRequest, BUFSIZ+1, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n%s: %s\r\n%s: %s\r\nConnection: close\r\n\r\n", domainname, HTTP_REQUEST_HEADER_SOCKS5_KEY, HTTP_REQUEST_HEADER_SOCKS5_VALUE, HTTP_REQUEST_HEADER_TLS_KEY, HTTP_REQUEST_HEADER_TLS_VALUE2);
	}
	
	if(httpsFlag == 1){	// HTTPS
		// SSL Initialize
		OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);

		// SSL TLS connection
		targetCtxHttp = SSL_CTX_new(TLS_client_method());
		if(targetCtxHttp == NULL){
#ifdef _DEBUG
			printf("[E] SSL_CTX_new error.\n");
#endif
			close(targetSock);
			close(clientSock);
			return -2;
		}
		sslParam.targetCtxHttp = targetCtxHttp;

		SSL_CTX_set_mode(targetCtxHttp, SSL_MODE_AUTO_RETRY);
		
		if(SSL_CTX_set_min_proto_version(targetCtxHttp, TLS1_2_VERSION) == 0){
#ifdef _DEBUG
			printf("[E] SSL_CTX_set_min_proto_version error.\n");
#endif
			finiSsl(&sslParam);
			close(targetSock);
			return -2;
		}
		
		SSL_CTX_set_default_verify_paths(targetCtxHttp);
		SSL_CTX_load_verify_locations(targetCtxHttp, serverCertificateFilenameHttps, serverCertificateFileDirectoryPathHttps);
		SSL_CTX_set_verify(targetCtxHttp, SSL_VERIFY_PEER, NULL);
		
		targetSslHttp = SSL_new(targetCtxHttp);
		if(targetSslHttp == NULL){
#ifdef _DEBUG
			printf("[E] SSL_new error.\n");
#endif
			finiSsl(&sslParam);
			close(targetSock);
			close(clientSock);
			return -2;
		}
		sslParam.targetSslHttp = targetSslHttp;
	
		if(SSL_set_fd(targetSslHttp, targetSock) == 0){
#ifdef _DEBUG
			printf("[E] SSL_set_fd error.\n");
#endif
			finiSsl(&sslParam);
			close(targetSock);
			close(clientSock);
			return -2;
		}
		
#ifdef _DEBUG
		printf("[I] Try HTTPS connection. (SSL_connect)\n");
#endif
		ret = SSL_connect(targetSslHttp);
		if(ret <= 0){
			err = SSL_get_error(targetSslHttp, ret);
#ifdef _DEBUG
			printf("[E] SSL_connect error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
			finiSsl(&sslParam);
			close(targetSock);
			close(clientSock);
			return -2;
		}
#ifdef _DEBUG
		printf("[I] Succeed HTTPS connection. (SSL_connect)\n");
#endif
		
		// HTTP Request
		sen = sendDataTls(targetSslHttp, httpRequest, httpRequestLength);
#ifdef _DEBUG
		printf("[I] Send http request.\n");
#endif
		
	}else{
		// HTTP Request
		sen = sendData(targetSock, httpRequest, httpRequestLength);
#ifdef _DEBUG
		printf("[I] Send http request.\n");
#endif
	}
	
	
	// check Server
	count = 0;
	check = 0;
	do{
		count++;
		rec = recvData(targetSock, buffer, BUFSIZ);
#ifdef _DEBUG
		printf("[I] count:%d rec:%d\n", count, rec);
#endif
		if(rec >= 2 && !strncmp(buffer, "OK", strlen("OK"))){
			check = 1;
			break;
		}
	}while(count < 3);
	if(check == 1){
#ifdef _DEBUG
		printf("[I] Server Socks5 OK.\n");
#endif
	}else{
#ifdef _DEBUG
		printf("[E] Server Socks5 NG.\n");
#endif
		finiSsl(&sslParam);
		close(targetSock);
		close(clientSock);
		return -1;
	}

	
	if(socks5OverTlsFlag == 1){	// Socks5 over TLS
		// SSL Initialize
		OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
		
		// SSL TLS connection
		targetCtxSocks5 = SSL_CTX_new(TLS_client_method());
		if(targetCtxSocks5 == NULL){
#ifdef _DEBUG
			printf("[E] SSL_CTX_new error.\n");
#endif
			close(targetSock);
			close(clientSock);
			return -2;
		}
		sslParam.targetCtxSocks5 = targetCtxSocks5;

		SSL_CTX_set_mode(targetCtxSocks5, SSL_MODE_AUTO_RETRY);
		
		if(SSL_CTX_set_min_proto_version(targetCtxSocks5, TLS1_2_VERSION) == 0){
#ifdef _DEBUG
			printf("[E] SSL_CTX_set_min_proto_version error.\n");
#endif
			finiSsl(&sslParam);
			close(targetSock);
			return -2;
		}

		SSL_CTX_set_default_verify_paths(targetCtxSocks5);
		SSL_CTX_load_verify_locations(targetCtxSocks5, serverCertificateFilenameSocks5, serverCertificateFileDirectoryPathSocks5);
		SSL_CTX_set_verify(targetCtxSocks5, SSL_VERIFY_PEER, NULL);
		
		targetSslSocks5 = SSL_new(targetCtxSocks5);
		if(targetSslSocks5 == NULL){
#ifdef _DEBUG
			printf("[E] SSL_new error.\n");
#endif
			finiSsl(&sslParam);
			close(targetSock);
			close(clientSock);
			return -2;
		}
		sslParam.targetSslSocks5 = targetSslSocks5;

		if(SSL_set_fd(targetSslSocks5, targetSock) == 0){
#ifdef _DEBUG
			printf("[E] SSL_set_fd error.\n");
#endif
			finiSsl(&sslParam);
			close(targetSock);
			close(clientSock);
			return -2;
		}
		
#ifdef _DEBUG
		printf("[I] Try Socks5 over TLS connection. (SSL_connect)\n");
#endif
		ret = SSL_connect(targetSslSocks5);
		if(ret <= 0){
			err = SSL_get_error(targetSslSocks5, ret);
#ifdef _DEBUG
			printf("[E] SSL_connect error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
			finiSsl(&sslParam);
			close(targetSock);
			close(clientSock);
			return -2;
		}
#ifdef _DEBUG
		printf("[I] Succeed Socks5 over TLS connection. (SSL_connect)\n");
#endif
	}


	// socks SELECTION_REQUEST	client -> server
#ifdef _DEBUG
	printf("[I] Recieving selection request. client -> server\n");
#endif
	if((rec = recvData(clientSock, buffer, BUFSIZ)) <= 0){
#ifdef _DEBUG
		printf("[E] Recieving selection request error. client -> server\n");
#endif
		finiSsl(&sslParam);
		close(targetSock);
		close(clientSock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Recieve selection request:%d bytes. client -> server\n", rec);
#endif


	// socks SELECTION_REQUEST	server -> target
#ifdef _DEBUG
	printf("[I] Sending selection request. server -> target\n");
#endif
	if(socks5OverTlsFlag == 0){
		sen = sendData(targetSock, buffer, rec);
	}else{
		sen = sendDataTls(targetSslSocks5, buffer, rec);
	}
#ifdef _DEBUG
	printf("[I] Send selection request:%d bytes. server -> target\n", sen);	
#endif


	// socks SELECTION_RESPONSE	server <- target
#ifdef _DEBUG
	printf("[I] Recieving selection response. server <- target\n");
#endif
	if(socks5OverTlsFlag == 0){
		rec = recvData(targetSock, buffer, BUFSIZ);
	}else{
		rec = recvDataTls(targetSslSocks5, buffer, BUFSIZ);
	}
	if(rec != sizeof(SELECTION_RESPONSE)){
#ifdef _DEBUG
		printf("[E] Recieving selection response error. server <- target\n");
#endif
		finiSsl(&sslParam);
		close(targetSock);
		close(clientSock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Recieve selection response:%d bytes. server <- target\n", rec);
#endif


	// socks SELECTION_RESPONSE	client <- server
#ifdef _DEBUG
	printf("[I] Sending selection response. client <- server\n");
#endif
	sen = sendData(clientSock, buffer, rec);
#ifdef _DEBUG
	printf("[I] Send selection response:%d bytes. client <- server\n", sen);
#endif
	pSELECTION_RESPONSE pSelectionResponse = (pSELECTION_RESPONSE)&buffer;
	if((unsigned char)pSelectionResponse->method == 0xFF){
#ifdef _DEBUG
		printf("[E] Target socks5server Authentication Method error.\n");
#endif
	}

	if(pSelectionResponse->method == 0x2){	// USERNAME_PASSWORD_AUTHENTICATION
		// socks USERNAME_PASSWORD_AUTHENTICATION_REQUEST		client -> server
#ifdef _DEBUG
		printf("[I] Recieving username password authentication request. client -> server\n");
#endif
		if((rec = recvData(clientSock, buffer, BUFSIZ)) <= 0){
#ifdef _DEBUG
			printf("[E] Recieving username password authentication request error. client -> server\n");
#endif
			finiSsl(&sslParam);
			close(targetSock);
			close(clientSock);
			return -1;
		}
#ifdef _DEBUG
		printf("[I] Recieve username password authentication request:%d bytes. client -> server\n", rec);
#endif


		// socks USERNAME_PASSWORD_AUTHENTICATION_REQUEST		server -> target
#ifdef _DEBUG
		printf("[I] Sending username password authentication request. server -> target\n");
#endif
		if(socks5OverTlsFlag == 0){
			sen = sendData(targetSock, buffer, rec);
		}else{
			sen = sendDataTls(targetSslSocks5, buffer, rec);
		}
#ifdef _DEBUG
		printf("[I] Send username password authentication request:%d bytes. server -> target\n", sen);	
#endif
		

		// socks USERNAME_PASSWORD_AUTHENTICATION_RESPONSE	server <- target
#ifdef _DEBUG
		printf("[I] Recieving username password authentication response. server <- target\n");
#endif
		if(socks5OverTlsFlag == 0){
			rec = recvData(targetSock, buffer, BUFSIZ);
		}else{
			rec = recvDataTls(targetSslSocks5, buffer, BUFSIZ);
		}
		if(rec <= 0){
#ifdef _DEBUG
			printf("[E] Recieving username password authentication response error. server <- target\n");
#endif
			finiSsl(&sslParam);
			close(targetSock);
			close(clientSock);
			return -1;
		}
#ifdef _DEBUG
		printf("[I] Recieve username password authentication response:%d bytes. server <- target\n", rec);
#endif


		// socks USERNAME_PASSWORD_AUTHENTICATION_RESPONSE	client <- server
#ifdef _DEBUG
		printf("[I] Sending username password authentication response. client <- server\n");
#endif
		sen = sendData(clientSock, buffer, rec);
#ifdef _DEBUG
		printf("[I] Send username password authentication response:%d bytes. client <- server\n", sen);
#endif
	}


	// socks SOCKS_REQUEST	client -> server
#ifdef _DEBUG
	printf("[I] Recieving socks request. client -> server\n");
#endif
	if((rec = recvData(clientSock, buffer, BUFSIZ)) <= 0){
#ifdef _DEBUG
		printf("[E] Recieving socks request error. client -> server\n");
#endif
		finiSsl(&sslParam);
		close(targetSock);
		close(clientSock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Recieve socks request:%d bytes. client -> server\n", rec);
#endif


	// socks SOCKS_REQUEST	server -> target
#ifdef _DEBUG
	printf("[I] Sending socks request. server -> target\n");
#endif
	if(socks5OverTlsFlag == 0){
		sen = sendData(targetSock, buffer, rec);
	}else{
		sen = sendDataTls(targetSslSocks5, buffer, rec);
	}
#ifdef _DEBUG
	printf("[I] Send socks request:%d bytes. server -> target\n", sen);	
#endif
	

	// socks SOCKS_RESPONSE	server <- target
#ifdef _DEBUG
	printf("[I] Recieving socks response. server <- target\n");
#endif
	if(socks5OverTlsFlag == 0){
		rec = recvData(targetSock, buffer, BUFSIZ);
	}else{
		rec = recvDataTls(targetSslSocks5, buffer, BUFSIZ);
	}
	if(rec <= 0){
#ifdef _DEBUG
		printf("[E] Recieving socks response error. server <- target\n");
#endif
		finiSsl(&sslParam);
		close(targetSock);
		close(clientSock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Recieve socks response:%d bytes. server <- target\n", rec);
#endif


	// socks SOCKS_RESPONSE	client <- server
#ifdef _DEBUG
	printf("[I] Sending socks response. client <- server\n");
#endif
	sen = sendData(clientSock, buffer, rec);
#ifdef _DEBUG
	printf("[I] Send socks response:%d bytes. client <- server\n", sen);
#endif


	// forwarder
#ifdef _DEBUG
	printf("[I] Forwarder.\n");
#endif
	if(socks5OverTlsFlag == 0){
		err = forwarder(clientSock, targetSock);
	}else{
		err = forwarderTls(clientSock, targetSock, targetSslSocks5);
	}


#ifdef _DEBUG
	printf("[I] Worker exit.\n");
#endif
	sleep(5);
	finiSsl(&sslParam);
	close(targetSock);
	close(clientSock);

	return 0;
}

void usage(char *filename){
	printf("usage   : %s -h listen_ip -p listen_port -H target_socks5server_domainname -P target_socks5server_port [-s (HTTPS)] [-t (Socks5 over TLS)]\n", filename);
	printf("example : %s -h 0.0.0.0 -p 9050 -H 192.168.0.10 -P 80\n", filename);
	printf("        : %s -h 0.0.0.0 -p 9050 -H foobar.test -P 80 -t\n", filename);
	printf("        : %s -h 0.0.0.0 -p 9050 -H 192.168.0.10 -P 443 -s\n", filename);
	printf("        : %s -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -s -t\n", filename);
}

int main(int argc, char **argv)
{

	int opt;
	const char* optstring = "h:p:H:P:stu:";
	opterr = 0;

	while((opt=getopt(argc, argv, optstring)) != -1){
		switch(opt){
		case 'h':
			socks5ServerIp = optarg;
			break;
			
		case 'p':
			socks5ServerPort = optarg;
			break;
		
		case 'H':
			socks5TargetIp = optarg;
			break;
			
		case 'P':
			socks5TargetPort = optarg;
			break;
			
		case 's':
			httpsFlag = 1;
			break;
			
		case 't':
			socks5OverTlsFlag = 1;
			break;
			
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if(socks5ServerIp == NULL || socks5ServerPort == NULL || socks5TargetIp == NULL || socks5TargetPort == NULL){
		usage(argv[0]);
		exit(1);
	}
	
	if(httpsFlag == 0){	// HTTP
#ifdef _DEBUG
		printf("[I] HTTPS:off.\n");
#endif
	}else{	// HTTPS
#ifdef _DEBUG
		printf("[I] HTTPS:on.\n");
#endif
	}
	
	if(socks5OverTlsFlag == 0){	// Socks5
#ifdef _DEBUG
		printf("[I] Socks5 over TLS:off.\n");
#endif
	}else{	// Socks5 over TLS
#ifdef _DEBUG
		printf("[I] Socks5 over TLS:on.\n");
#endif
	}
	
	
	int serverSock, clientSock;
	struct sockaddr_in serverAddr, clientAddr;

	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr.s_addr = inet_addr(socks5ServerIp);
	serverAddr.sin_port = htons(atoi(socks5ServerPort));
	
	serverSock = socket(AF_INET, SOCK_STREAM, 0);
	int reuse = 1;
	setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));
	
	// bind
	if(bind(serverSock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1) {
#ifdef _DEBUG
		printf("[E] bind error.\n");
#endif
		return -1;
	}
	
	// listen
	listen(serverSock, 5);
#ifdef _DEBUG
	printf("[I] Listenning port %d on %s.\n", ntohs(serverAddr.sin_port), inet_ntoa(serverAddr.sin_addr));
#endif

	// accept
	int clientAddrLen = sizeof(clientAddr);
	while((clientSock = accept(serverSock, (struct sockaddr *)&clientAddr, (socklen_t *)&clientAddrLen))){
#ifdef _DEBUG
		printf("[I] Connected from %s.\n", inet_ntoa(clientAddr.sin_addr));
#endif

		int flags = fcntl(clientSock, F_GETFL, 0);
		flags &= ~O_NONBLOCK;
		fcntl(clientSock, F_SETFL, flags);
		
		pthread_t thread;
		PARAM param;
		param.clientSock = clientSock;
		
		if(pthread_create(&thread, NULL, (void *)worker, &param))
		{
#ifdef _DEBUG
			printf("[E] pthread_create failed.\n");
#endif
			close(clientSock);
		}else{
			pthread_detach(thread);
		}
	}

	close(serverSock);

	return 0;
}

