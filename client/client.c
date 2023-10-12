/*
 * Title:  socks5 client (apache module)
 * Author: Shuichiro Endo
 */

#define _DEBUG

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <time.h>
#include <signal.h>
#include <iconv.h>

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
#include <openssl/des.h>
#include <openssl/hmac.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#include <gssapi/gssapi_krb5.h>

#include "socks5.h"
#include "ntlm.h"
#include "client.h"

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

char *socks5_server_ip = NULL;
char *socks5_server_port = NULL;
char *socks5_target_ip = NULL;
char *socks5_target_port = NULL;
char *forward_proxy_ip = NULL;		// http proxy ip
char *forward_proxy_port = NULL;	// http proxy port
char *forward_proxy_username = NULL;
char *forward_proxy_password = NULL;
char *forward_proxy_user_domainname = NULL;
char *forward_proxy_workstationname = NULL;
char *forward_proxy_spn = NULL;	// service principal name
int https_flag = 0;		// 0:http 1:https
int socks5_over_tls_flag = 0;	// 0:socks5 over aes 1:socks5 over tls
int forward_proxy_flag = 0;		// 0:no 1:http
int forward_proxy_authentication_flag = 0;	// 0:no 1:basic 2:digest 3:ntlmv2 4:spnego(kerberos)

char server_certificate_filename_https[256] = "server_https.crt";	// server certificate filename (HTTPS)
char server_certificate_file_directory_path_https[256] = ".";	// server certificate file directory path (HTTPS)

char server_certificate_filename_socks5[256] = "server_socks5.crt";	// server certificate filename (Socks5 over TLS)
char server_certificate_file_directory_path_socks5[256] = ".";	// server certificate file directory path (Socks5 over TLS)


void print_bytes(unsigned char *input, int input_length)
{
	for(int i=0; i<input_length; i++){
		if(i != 0 && i%16 == 0){
			printf("\n");
		}else if(i%16 == 8){
			printf(" ");
		}
		printf("%02x ", input[i]);
	}
	printf("\n");

	return;
}


int encrypt_aes(unsigned char *plaintext, int plaintext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *ctx;
	int length;
	int ciphertext_length;
	int ret;
	
	ctx = EVP_CIPHER_CTX_new();
	if(ctx == NULL){
#ifdef _DEBUG
//		printf("[E] EVP_CIPHER_CTX_new error\n");
#endif
		return -1;
	}
	
	ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_EncryptInit_ex error\n");
#endif
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	
	ret = EVP_EncryptUpdate(ctx, ciphertext, &length, plaintext, plaintext_length);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_EncryptUpdate error\n");
#endif
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	ciphertext_length = length;
	
	ret = EVP_EncryptFinal_ex(ctx, ciphertext+length, &length);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_EncryptFinal_ex error\n");
#endif
		EVP_CIPHER_CTX_free(ctx);
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
//		printf("[E] EVP_CIPHER_CTX_new error\n");
#endif
		return -1;
	}
	
	ret = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_DecryptInit_ex error\n");
#endif
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	
	ret = EVP_DecryptUpdate(ctx, plaintext, &length, ciphertext, ciphertext_length);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_DecryptUpdate error\n");
#endif
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	plaintext_length = length;
	
	ret = EVP_DecryptFinal_ex(ctx, plaintext+length, &length);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_DecryptFinal_ex error\n");
#endif
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	plaintext_length += length;
	
	EVP_CIPHER_CTX_free(ctx);
	
	return plaintext_length;
}


int encode_base64(const unsigned char *input, int length, unsigned char *output, int output_size)
{
	BIO *b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	BIO *mem = BIO_new(BIO_s_mem());
	char *ptr = NULL;
	long len = 0;
	int output_length = 0;
	int ret = 0;

	BIO *bio = BIO_push(b64, mem);

	ret = BIO_write(bio, input, length);
	if(ret <= 0){
#ifdef _DEBUG
//		printf("[E] BIO_write error\n");
#endif
		BIO_free_all(bio);
		return -1;
	}

	ret = BIO_flush(bio);
	if(ret <= 0){
#ifdef _DEBUG
//		printf("[E] BIO_flush error\n");
#endif
		BIO_free_all(bio);
		return -1;
	}

	len = BIO_get_mem_data(mem, &ptr);
	if(len <= 0){
#ifdef _DEBUG
//		printf("[E] BIO_get_mem_data error\n");
#endif
		BIO_free_all(bio);
		return -1;
	}

	if(len > output_size){
#ifdef _DEBUG
//		printf("[E] output_size error\n");
#endif
		BIO_free_all(bio);
		return -1;
	}

	memcpy(output, ptr, (int)len);
	output_length = strlen(output);

	BIO_free_all(bio);

	return output_length;
}


int decode_base64(const unsigned char *input, int length, unsigned char *output, int output_size)
{
	BIO *b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	BIO *mem = BIO_new_mem_buf((char *)input, -1);
	int output_length = 0;
	int ret = 0;

	BIO *bio = BIO_push(b64, mem);

	if(length > output_size){
#ifdef _DEBUG
//		printf("[E] output_size error\n");
#endif
		BIO_free_all(bio);
		return -1;
	}

	output_length = BIO_read(bio, output, length);
	if(output_length <= 0){
#ifdef _DEBUG
//		printf("[E] BIO_read error\n");
#endif
		BIO_free_all(bio);
		return -1;
	}

	ret = BIO_flush(bio);
	if(ret <= 0){
#ifdef _DEBUG
//		printf("[E] BIO_flush error\n");
#endif
		BIO_free_all(bio);
		return -1;
	}

	BIO_free_all(bio);

	return output_length;
}


int get_md5_hash(const unsigned char *input, int input_length, unsigned char *output, int output_size)
{
	EVP_MD_CTX *ctx = NULL;
	int ret = 0;
	unsigned char *digest = NULL;
	unsigned int length = 0;

	ctx = EVP_MD_CTX_new();
	if(ctx == NULL){
#ifdef _DEBUG
//		printf("[E] EVP_MD_CTX_new error\n");
#endif
		return -1;
	}

	ret = EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_DigestInit_ex error\n");
#endif
		EVP_MD_CTX_free(ctx);
		return -1;
	}

	ret = EVP_DigestUpdate(ctx, input, input_length);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_DigestUpdate error\n");
#endif
		EVP_MD_CTX_free(ctx);
		return -1;
	}

	if(EVP_MD_size(EVP_md5()) > output_size){
#ifdef _DEBUG
//		printf("[E] output_size error\n");
#endif
		EVP_MD_CTX_free(ctx);
		return -1;
	}

	digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_md5()));
	if(digest == NULL){
#ifdef _DEBUG
//		printf("[E] OPENSSL_malloc error\n");
#endif
		EVP_MD_CTX_free(ctx);
		return -1;
	}

	ret = EVP_DigestFinal_ex(ctx, (unsigned char *)digest, &length);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_DigestFinal_ex error\n");
#endif
		OPENSSL_free(digest);
		EVP_MD_CTX_free(ctx);
		return -1;
	}

	for(int i=0; i*8<length; i++){
		ret = snprintf(output+i*16, 17, "%02x%02x%02x%02x%02x%02x%02x%02x\n", digest[i*8+0], digest[i*8+1], digest[i*8+2], digest[i*8+3], digest[i*8+4], digest[i*8+5], digest[i*8+6], digest[i*8+7]);
	}

	OPENSSL_free(digest);
	EVP_MD_CTX_free(ctx);

	return length;
}


int get_sha_256_hash(const unsigned char *input, int input_length, unsigned char *output, int output_size)
{
	EVP_MD_CTX *ctx = NULL;
	int ret = 0;
	unsigned char *digest = NULL;
	unsigned int length = 0;

	ctx = EVP_MD_CTX_new();
	if(ctx == NULL){
#ifdef _DEBUG
//		printf("[E] EVP_MD_CTX_new error\n");
#endif
		return -1;
	}

	ret = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_DigestInit_ex error\n");
#endif
		EVP_MD_CTX_free(ctx);
		return -1;
	}

	ret = EVP_DigestUpdate(ctx, input, input_length);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_DigestUpdate error\n");
#endif
		EVP_MD_CTX_free(ctx);
		return -1;
	}

	if(EVP_MD_size(EVP_sha256()) > output_size){
#ifdef _DEBUG
//		printf("[E] output_size error\n");
#endif
		EVP_MD_CTX_free(ctx);
		return -1;
	}

	digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()));
	if(digest == NULL){
#ifdef _DEBUG
//		printf("[E] OPENSSL_malloc error\n");
#endif
		EVP_MD_CTX_free(ctx);
		return -1;
	}

	ret = EVP_DigestFinal_ex(ctx, (unsigned char *)digest, &length);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_DigestFinal_ex error\n");
#endif
		OPENSSL_free(digest);
		EVP_MD_CTX_free(ctx);
		return -1;
	}

	for(int i=0; i*8<length; i++){
		ret = snprintf(output+i*16, 17, "%02x%02x%02x%02x%02x%02x%02x%02x\n", digest[i*8+0], digest[i*8+1], digest[i*8+2], digest[i*8+3], digest[i*8+4], digest[i*8+5], digest[i*8+6], digest[i*8+7]);
	}

	OPENSSL_free(digest);
	EVP_MD_CTX_free(ctx);

	return length;
}


int get_sha_512_256_hash(const unsigned char *input, int input_length, unsigned char *output, int output_size)
{
	EVP_MD_CTX *ctx = NULL;
	int ret = 0;
	unsigned char *digest = NULL;
	unsigned int length = 0;

	ctx = EVP_MD_CTX_new();
	if(ctx == NULL){
#ifdef _DEBUG
//		printf("[E] EVP_MD_CTX_new error\n");
#endif
		return -1;
	}

	ret = EVP_DigestInit_ex(ctx, EVP_sha512_256(), NULL);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_DigestInit_ex error\n");
#endif
		EVP_MD_CTX_free(ctx);
		return -1;
	}

	ret = EVP_DigestUpdate(ctx, input, input_length);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_DigestUpdate error\n");
#endif
		EVP_MD_CTX_free(ctx);
		return -1;
	}

	if(EVP_MD_size(EVP_sha512_256()) > output_size){
#ifdef _DEBUG
//		printf("[E] output_size error\n");
#endif
		EVP_MD_CTX_free(ctx);
		return -1;
	}

	digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha512_256()));
	if(digest == NULL){
#ifdef _DEBUG
//		printf("[E] OPENSSL_malloc error\n");
#endif
		EVP_MD_CTX_free(ctx);
		return -1;
	}

	ret = EVP_DigestFinal_ex(ctx, (unsigned char *)digest, &length);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_DigestFinal_ex error\n");
#endif
		OPENSSL_free(digest);
		EVP_MD_CTX_free(ctx);
		return -1;
	}

	for(int i=0; i*8<length; i++){
		ret = snprintf(output+i*16, 17, "%02x%02x%02x%02x%02x%02x%02x%02x\n", digest[i*8+0], digest[i*8+1], digest[i*8+2], digest[i*8+3], digest[i*8+4], digest[i*8+5], digest[i*8+6], digest[i*8+7]);
	}

	OPENSSL_free(digest);
	EVP_MD_CTX_free(ctx);

	return length;
}


int get_http_header(const char *input, const char *key, char *output, int output_size)
{
	char *start = NULL;
	char *end = NULL;
	long d = 0;
	int length = 0;

	start = strstr(input, key);
	end = strstr(start, "\r\n");
	d = end - start;
	if((d <= 0) || (d >= output_size)){
#ifdef _DEBUG
//		printf("[E] get_http_header error:%d\n", d);
#endif
		return -1;
	}

	bzero(output, output_size);
	memcpy(output, start, d);
	length = strlen(output);

	return length;
}


int get_digest_values(const char *input, struct digest_parameters *param)
{
	char *start = NULL;
	char *end = NULL;
	long d = 0;

	// realm
	start = strstr(input, "realm=\"");
	if(start == NULL){
#ifdef _DEBUG
		printf("[E] get_digest_values realm error\n");
#endif
		return -1;
	}
	start += strlen("realm=\"");
	end = strstr(start, "\"");
	d = end - start;
	if((d <= 0) || (d >= 100)){
#ifdef _DEBUG
		printf("[E] get_digest_values realm error:%d\n", d);
#endif
		return -1;
	}
	memcpy(&(param->realm), start, d);

	// nonce
	start = strstr(input, "nonce=\"");
	if(start == NULL){
#ifdef _DEBUG
		printf("[E] get_digest_values nonce error\n");
#endif
		return -1;
	}
	start += strlen("nonce=\"");
	end = strstr(start, "\"");
	d = end - start;
	if((d <= 0) || (d >= 200)){
#ifdef _DEBUG
		printf("[E] get_digest_values nonce error:%d\n", d);
#endif
		return -1;
	}
	memcpy(&(param->nonce), start, d);

	// nonce-prime
	start = strstr(input, "nonce-prime=\"");
	if(start != NULL){
		start += strlen("nonce-prime=\"");
		end = strstr(start, "\"");
		d = end - start;
		if((d <= 0) || (d >= 200)){
#ifdef _DEBUG
			printf("[E] get_digest_values nonce-prime error:%d\n", d);
#endif
			return -1;
		}
		memcpy(&(param->nonce_prime), start, d);
	}

	// qop
	start = strstr(input, "qop=\"");
	if(start == NULL){
#ifdef _DEBUG
		printf("[E] get_digest_values qop error\n");
#endif
		return -1;
	}
	start += strlen("qop=\"");
	end = strstr(start, "\"");
	d = end - start;
	if((d <= 0) || (d >= 10)){
#ifdef _DEBUG
		printf("[E] get_digest_values qop error:%d\n", d);
#endif
		return -1;
	}
	if(!strncmp(start, "auth-int", strlen("auth-int"))){
		memcpy(&(param->qop), "auth-int", strlen("auth-int"));
	}else{
		memcpy(&(param->qop), "auth", strlen("auth"));
	}

	// algorithm
	start = strstr(input, "algorithm=");
	if(start == NULL){
		memcpy(&(param->algorithm), "MD5", strlen("MD5"));
	}else{
		start += strlen("algorithm=");
		end = strstr(start, " ");
		d = end - start;
		if((d < 0) || (d >= 100)){
#ifdef _DEBUG
			printf("[E] get_digest_values algorithm error:%d\n", d);
#endif
			return -1;
		}
		memcpy(&(param->algorithm), start, d);
	}

	// stale
	start = strstr(input, "stale=");
	if(start == NULL){
#ifdef _DEBUG
		printf("[E] get_digest_values stale error\n");
#endif
		return -1;
	}
	start += strlen("stale=");
	if(!strncmp(start, "false", strlen("false"))){
		memcpy(&(param->stale), "false", strlen("false"));
	}else{
		memcpy(&(param->stale), "true", strlen("true"));
	}

#ifdef _DEBUG
//	printf("[I] realm:%s nonce:%s, nonce-prime:%s qop:%s, algorithm:%s stale:%s\n", param->realm, param->nonce, param->nonce_prime, param->qop, param->algorithm, param->stale);
#endif

	return 0;
}


int get_digest_response(struct digest_parameters *param)
{
	int ret = 0;
	int length = 0;
	unsigned char tmp1[17];
	unsigned char tmp2[33];
	unsigned char tmp3[1000];
	unsigned char tmp4[150];
	bzero(&tmp1, 17);
	bzero(&tmp2, 33);
	bzero(&tmp3, 1000);
	bzero(&tmp4, 150);


	// cnonce
	ret = RAND_bytes((unsigned char *)tmp1, 16);
	if(ret != 1){
#ifdef _DEBUG
		printf("[E] RAND_bytes error:%s.\n", ERR_error_string(ERR_peek_last_error(), NULL));
#endif
		return -1;
	}

	for(int i=0; i*8<16; i++){
		ret = snprintf(tmp2+i*16, 17, "%02x%02x%02x%02x%02x%02x%02x%02x\n", tmp1[i*8+0], tmp1[i*8+1], tmp1[i*8+2], tmp1[i*8+3], tmp1[i*8+4], tmp1[i*8+5], tmp1[i*8+6], tmp1[i*8+7]);
	};

	ret = encode_base64(tmp2, 32, param->cnonce, 200);

	// cnonce-prime
	if(param->nonce_prime != NULL){
		bzero(&tmp1, 17);
		bzero(&tmp2, 33);
		ret = RAND_bytes((unsigned char *)tmp1, 16);
		if(ret != 1){
#ifdef _DEBUG
			printf("[E] RAND_bytes error:%s.\n", ERR_error_string(ERR_peek_last_error(), NULL));
#endif
			return -1;
		}

		for(int i=0; i*8<16; i++){
			ret = snprintf(tmp2+i*16, 17, "%02x%02x%02x%02x%02x%02x%02x%02x\n", tmp1[i*8+0], tmp1[i*8+1], tmp1[i*8+2], tmp1[i*8+3], tmp1[i*8+4], tmp1[i*8+5], tmp1[i*8+6], tmp1[i*8+7]);
		};

		ret = encode_base64(tmp2, 32, param->cnonce_prime, 200);
	}


	if(!strncmp(param->algorithm, "MD5-sess", strlen("MD5-sess"))){
		// A1 MD5(username:realm:password):nonce-prime:cnonce-prime
		length = strlen(param->username) + strlen(param->realm) + strlen(param->password) + 2;	// 2 colon
		ret = snprintf(tmp3, length+1, "%s:%s:%s", param->username, param->realm, param->password);
		ret = get_md5_hash((const unsigned char *)&tmp3, length, (unsigned char *)&tmp4, 150);
		if(ret == -1){
#ifdef _DEBUG
			printf("[E] A1-1 get_md5_hash error\n");
#endif
			return -1;
		}

		length = strlen(tmp4) + strlen(param->nonce_prime) + strlen(param->cnonce_prime) + 2;	// 2 colon
		ret = snprintf(param->a1, length+1, "%s:%s:%s", tmp4, param->nonce_prime, param->cnonce_prime);
		ret = get_md5_hash((const unsigned char *)&(param->a1), length, (unsigned char *)&(param->a1_hash), 150);
		if(ret == -1){
#ifdef _DEBUG
			printf("[E] A1-2 get_md5_hash error\n");
#endif
			return -1;
		}

		if(!strncmp(param->qop, "auth-int", strlen("auth-int"))){	// auth-int
			// A2 method:uri:MD5(entity-body)
			length = strlen(param->entity_body);
			ret = get_md5_hash((const unsigned char *)&(param->entity_body), length, (unsigned char *)&(param->entity_body_hash), 150);
			if(ret == -1){
#ifdef _DEBUG
				printf("[E] A2-1 get_md5_hash error\n");
#endif
				return -1;
			}

			length = strlen(param->method) + strlen(param->uri) + strlen(param->entity_body_hash) + 2;	// 2 colon
			ret = snprintf(param->a2, length+1, "%s:%s:%s", param->method, param->uri, param->entity_body_hash);
			ret = get_md5_hash((const unsigned char *)&(param->a2), length, (unsigned char *)&(param->a2_hash), 150);
			if(ret == -1){
#ifdef _DEBUG
				printf("[E] A2-2 get_md5_hash error\n");
#endif
				return -1;
			}
		}else{	// auth
			// A2 method:uri
			length = strlen(param->method) + strlen(param->uri) + 1;	// 1 colon
			ret = snprintf(param->a2, length+1, "%s:%s", param->method, param->uri);
			ret = get_md5_hash((const unsigned char *)&(param->a2), length, (unsigned char *)&(param->a2_hash), 150);
			if(ret == -1){
#ifdef _DEBUG
				printf("[E] A2 get_md5_hash error\n");
#endif
				return -1;
			}
		}

		// response MD5(A1):nonce:nc:cnonce:qop:MD5(A2)
		length = strlen(param->a1_hash) + strlen(param->nonce) + strlen(param->nc) + strlen(param->cnonce) + strlen(param->qop) + strlen(param->a2_hash) + 5;	// 5 colon
		ret = snprintf(param->response, length+1, "%s:%s:%s:%s:%s:%s", param->a1_hash, param->nonce, param->nc, param->cnonce, param->qop, param->a2_hash);
		ret = get_md5_hash((const unsigned char *)&(param->response), length, (unsigned char *)&(param->response_hash), 150);
		if(ret == -1){
#ifdef _DEBUG
			printf("[E] response get_md5_hash error\n");
#endif
			return -1;
		}

	}else if(!strncmp(param->algorithm, "MD5", strlen("MD5"))){
		// A1 username:realm:password
		length = strlen(param->username) + strlen(param->realm) + strlen(param->password) + 2;	// 2 colon
		ret = snprintf(param->a1, length+1, "%s:%s:%s", param->username, param->realm, param->password);
		ret = get_md5_hash((const unsigned char *)&(param->a1), length, (unsigned char *)&(param->a1_hash), 150);
		if(ret == -1){
#ifdef _DEBUG
			printf("[E] A1 get_md5_hash error\n");
#endif
			return -1;
		}

		if(!strncmp(param->qop, "auth-int", strlen("auth-int"))){	// auth-int
			// A2 method:uri:MD5(entity-body)
			length = strlen(param->entity_body);
			ret = get_md5_hash((const unsigned char *)&(param->entity_body), length, (unsigned char *)&(param->entity_body_hash), 150);
			if(ret == -1){
#ifdef _DEBUG
				printf("[E] A2-1 get_md5_hash error\n");
#endif
				return -1;
			}

			length = strlen(param->method) + strlen(param->uri) + strlen(param->entity_body_hash) + 2;	// 2 colon
			ret = snprintf(param->a2, length+1, "%s:%s:%s", param->method, param->uri, param->entity_body_hash);
			ret = get_md5_hash((const unsigned char *)&(param->a2), length, (unsigned char *)&(param->a2_hash), 150);
			if(ret == -1){
#ifdef _DEBUG
				printf("[E] A2-2 get_md5_hash error\n");
#endif
				return -1;
			}
		}else{	// auth
			// A2 method:uri
			length = strlen(param->method) + strlen(param->uri) + 1;	// 1 colon
			ret = snprintf(param->a2, length+1, "%s:%s", param->method, param->uri);
			ret = get_md5_hash((const unsigned char *)&(param->a2), length, (unsigned char *)&(param->a2_hash), 150);
			if(ret == -1){
#ifdef _DEBUG
				printf("[E] A2 get_md5_hash error\n");
#endif
				return -1;
			}
		}

		// response MD5(A1):nonce:nc:cnonce:qop:MD5(A2)
		length = strlen(param->a1_hash) + strlen(param->nonce) + strlen(param->nc) + strlen(param->cnonce) + strlen(param->qop) + strlen(param->a2_hash) + 5;	// 5 colon
		ret = snprintf(param->response, length+1, "%s:%s:%s:%s:%s:%s", param->a1_hash, param->nonce, param->nc, param->cnonce, param->qop, param->a2_hash);
		ret = get_md5_hash((const unsigned char *)&(param->response), length, (unsigned char *)&(param->response_hash), 150);
		if(ret == -1){
#ifdef _DEBUG
			printf("[E] response get_md5_hash error\n");
#endif
			return -1;
		}

	}else if(!strncmp(param->algorithm, "SHA-256-sess", strlen("SHA-256-sess"))){
		// A1 SHA-256(username:realm:password):nonce-prime:cnonce-prime
		length = strlen(param->username) + strlen(param->realm) + strlen(param->password) + 2;	// 2 colon
		ret = snprintf(tmp3, length+1, "%s:%s:%s", param->username, param->realm, param->password);
		ret = get_sha_256_hash((const unsigned char *)&tmp3, length, (unsigned char *)&tmp4, 150);
		if(ret == -1){
#ifdef _DEBUG
			printf("[E] A1-1 get_sha_256_hash error\n");
#endif
			return -1;
		}

		length = strlen(tmp4) + strlen(param->nonce_prime) + strlen(param->cnonce_prime) + 2;	// 2 colon
		ret = snprintf(param->a1, length+1, "%s:%s:%s", tmp4, param->nonce_prime, param->cnonce_prime);
		ret = get_sha_256_hash((const unsigned char *)&(param->a1), length, (unsigned char *)&(param->a1_hash), 150);
		if(ret == -1){
#ifdef _DEBUG
			printf("[E] A1-2 get_sha_256_hash error\n");
#endif
			return -1;
		}

		if(!strncmp(param->qop, "auth-int", strlen("auth-int"))){	// auth-int
			// A2 method:uri:SHA-256(entity-body)
			length = strlen(param->entity_body);
			ret = get_sha_256_hash((const unsigned char *)&(param->entity_body), length, (unsigned char *)&(param->entity_body_hash), 150);
			if(ret == -1){
#ifdef _DEBUG
				printf("[E] A2-1 get_sha_256_hash error\n");
#endif
				return -1;
			}

			length = strlen(param->method) + strlen(param->uri) + strlen(param->entity_body_hash) + 2;	// 2 colon
			ret = snprintf(param->a2, length+1, "%s:%s:%s", param->method, param->uri, param->entity_body_hash);
			ret = get_sha_256_hash((const unsigned char *)&(param->a2), length, (unsigned char *)&(param->a2_hash), 150);
			if(ret == -1){
#ifdef _DEBUG
				printf("[E] A2-2 get_sha_256_hash error\n");
#endif
				return -1;
			}
		}else{	// auth
			// A2 method:uri
			length = strlen(param->method) + strlen(param->uri) + 1;	// 1 colon
			ret = snprintf(param->a2, length+1, "%s:%s", param->method, param->uri);
			ret = get_sha_256_hash((const unsigned char *)&(param->a2), length, (unsigned char *)&(param->a2_hash), 150);
			if(ret == -1){
#ifdef _DEBUG
				printf("[E] A2 get_sha_256_hash error\n");
#endif
				return -1;
			}
		}

		// response SHA-256(A1):nonce:nc:cnonce:qop:SHA-256(A2)
		length = strlen(param->a1_hash) + strlen(param->nonce) + strlen(param->nc) + strlen(param->cnonce) + strlen(param->qop) + strlen(param->a2_hash) + 5;	// 5 colon
		ret = snprintf(param->response, length+1, "%s:%s:%s:%s:%s:%s", param->a1_hash, param->nonce, param->nc, param->cnonce, param->qop, param->a2_hash);
		ret = get_sha_256_hash((const unsigned char *)&(param->response), length, (unsigned char *)&(param->response_hash), 150);
		if(ret == -1){
#ifdef _DEBUG
			printf("[E] response get_sha_256_hash error\n");
#endif
			return -1;
		}

	}else if(!strncmp(param->algorithm, "SHA-256", strlen("SHA-256"))){
		// A1 username:realm:password
		length = strlen(param->username) + strlen(param->realm) + strlen(param->password) + 2;	// 2 colon
		ret = snprintf(param->a1, length+1, "%s:%s:%s", param->username, param->realm, param->password);
		ret = get_sha_256_hash((const unsigned char *)&(param->a1), length, (unsigned char *)&(param->a1_hash), 150);
		if(ret == -1){
#ifdef _DEBUG
			printf("[E] A1 get_sha_256_hash error\n");
#endif
			return -1;
		}

		if(!strncmp(param->qop, "auth-int", strlen("auth-int"))){	// auth-int
			// A2 method:uri:SHA-256(entity-body)
			length = strlen(param->entity_body);
			ret = get_sha_256_hash((const unsigned char *)&(param->entity_body), length, (unsigned char *)&(param->entity_body_hash), 150);
			if(ret == -1){
#ifdef _DEBUG
				printf("[E] A2-1 get_sha_256_hash error\n");
#endif
				return -1;
			}

			length = strlen(param->method) + strlen(param->uri) + strlen(param->entity_body_hash) + 2;	// 2 colon
			ret = snprintf(param->a2, length+1, "%s:%s:%s", param->method, param->uri, param->entity_body_hash);
			ret = get_sha_256_hash((const unsigned char *)&(param->a2), length, (unsigned char *)&(param->a2_hash), 150);
			if(ret == -1){
#ifdef _DEBUG
				printf("[E] A2-2 get_sha_256_hash error\n");
#endif
				return -1;
			}
		}else{	// auth
			// A2 method:uri
			length = strlen(param->method) + strlen(param->uri) + 1;	// 1 colon
			ret = snprintf(param->a2, length+1, "%s:%s", param->method, param->uri);
			ret = get_sha_256_hash((const unsigned char *)&(param->a2), length, (unsigned char *)&(param->a2_hash), 150);
			if(ret == -1){
#ifdef _DEBUG
				printf("[E] A2 get_sha_256_hash error\n");
#endif
				return -1;
			}
		}

		// response SHA-256(A1):nonce:nc:cnonce:qop:SHA-256(A2)
		length = strlen(param->a1_hash) + strlen(param->nonce) + strlen(param->nc) + strlen(param->cnonce) + strlen(param->qop) + strlen(param->a2_hash) + 5;	// 5 colon
		ret = snprintf(param->response, length+1, "%s:%s:%s:%s:%s:%s", param->a1_hash, param->nonce, param->nc, param->cnonce, param->qop, param->a2_hash);
		ret = get_sha_256_hash((const unsigned char *)&(param->response), length, (unsigned char *)&(param->response_hash), 150);
		if(ret == -1){
#ifdef _DEBUG
			printf("[E] response get_sha_256_hash error\n");
#endif
			return -1;
		}

	}else if(!strncmp(param->algorithm, "SHA-512-256-sess", strlen("SHA-512-256-sess"))){
		// A1 SHA-512-256(username:realm:password):nonce-prime:cnonce-prime
		length = strlen(param->username) + strlen(param->realm) + strlen(param->password) + 2;	// 2 colon
		ret = snprintf(tmp3, length+1, "%s:%s:%s", param->username, param->realm, param->password);
		ret = get_sha_512_256_hash((const unsigned char *)&tmp3, length, (unsigned char *)&tmp4, 150);
		if(ret == -1){
#ifdef _DEBUG
			printf("[E] A1-1 get_sha_512_256_hash error\n");
#endif
			return -1;
		}

		length = strlen(tmp4) + strlen(param->nonce_prime) + strlen(param->cnonce_prime) + 2;	// 2 colon
		ret = snprintf(param->a1, length+1, "%s:%s:%s", tmp4, param->nonce_prime, param->cnonce_prime);
		ret = get_sha_512_256_hash((const unsigned char *)&(param->a1), length, (unsigned char *)&(param->a1_hash), 150);
		if(ret == -1){
#ifdef _DEBUG
			printf("[E] A1-2 get_sha_512_256_hash error\n");
#endif
			return -1;
		}

		if(!strncmp(param->qop, "auth-int", strlen("auth-int"))){	// auth-int
			// A2 method:uri:SHA-512-256(entity-body)
			length = strlen(param->entity_body);
			ret = get_sha_512_256_hash((const unsigned char *)&(param->entity_body), length, (unsigned char *)&(param->entity_body_hash), 150);
			if(ret == -1){
#ifdef _DEBUG
				printf("[E] A2-1 get_sha_512_256_hash error\n");
#endif
				return -1;
			}

			length = strlen(param->method) + strlen(param->uri) + strlen(param->entity_body_hash) + 2;	// 2 colon
			ret = snprintf(param->a2, length+1, "%s:%s:%s", param->method, param->uri, param->entity_body_hash);
			ret = get_sha_512_256_hash((const unsigned char *)&(param->a2), length, (unsigned char *)&(param->a2_hash), 150);
			if(ret == -1){
#ifdef _DEBUG
				printf("[E] A2-2 get_sha_512_256_hash error\n");
#endif
				return -1;
			}
		}else{	// auth
			// A2 method:uri
			length = strlen(param->method) + strlen(param->uri) + 1;	// 1 colon
			ret = snprintf(param->a2, length+1, "%s:%s", param->method, param->uri);
			ret = get_sha_512_256_hash((const unsigned char *)&(param->a2), length, (unsigned char *)&(param->a2_hash), 150);
			if(ret == -1){
#ifdef _DEBUG
				printf("[E] A2 get_sha_512_256_hash error\n");
#endif
				return -1;
			}
		}

		// response SHA-512-256(A1):nonce:nc:cnonce:qop:SHA-512-256(A2)
		length = strlen(param->a1_hash) + strlen(param->nonce) + strlen(param->nc) + strlen(param->cnonce) + strlen(param->qop) + strlen(param->a2_hash) + 5;	// 5 colon
		ret = snprintf(param->response, length+1, "%s:%s:%s:%s:%s:%s", param->a1_hash, param->nonce, param->nc, param->cnonce, param->qop, param->a2_hash);
		ret = get_sha_512_256_hash((const unsigned char *)&(param->response), length, (unsigned char *)&(param->response_hash), 150);
		if(ret == -1){
#ifdef _DEBUG
			printf("[E] response get_sha_512_256_hash error\n");
#endif
			return -1;
		}

	}else if(!strncmp(param->algorithm, "SHA-512-256", strlen("SHA-512-256"))){
		// A1 username:realm:password
		length = strlen(param->username) + strlen(param->realm) + strlen(param->password) + 2;	// 2 colon
		ret = snprintf(param->a1, length+1, "%s:%s:%s", param->username, param->realm, param->password);
		ret = get_sha_512_256_hash((const unsigned char *)&(param->a1), length, (unsigned char *)&(param->a1_hash), 150);
		if(ret == -1){
#ifdef _DEBUG
			printf("[E] A1 get_sha_512_256_hash error\n");
#endif
			return -1;
		}

		if(!strncmp(param->qop, "auth-int", strlen("auth-int"))){	// auth-int
			// A2 method:uri:SHA-512-256(entity-body)
			length = strlen(param->entity_body);
			ret = get_sha_512_256_hash((const unsigned char *)&(param->entity_body), length, (unsigned char *)&(param->entity_body_hash), 150);
			if(ret == -1){
#ifdef _DEBUG
				printf("[E] A2-1 get_sha_512_256_hash error\n");
#endif
				return -1;
			}

			length = strlen(param->method) + strlen(param->uri) + strlen(param->entity_body_hash) + 2;	// 2 colon
			ret = snprintf(param->a2, length+1, "%s:%s:%s", param->method, param->uri, param->entity_body_hash);
			ret = get_sha_512_256_hash((const unsigned char *)&(param->a2), length, (unsigned char *)&(param->a2_hash), 150);
			if(ret == -1){
#ifdef _DEBUG
				printf("[E] A2-2 get_sha_512_256_hash error\n");
#endif
				return -1;
			}
		}else{	// auth
			// A2 method:uri
			length = strlen(param->method) + strlen(param->uri) + 1;	// 1 colon
			ret = snprintf(param->a2, length+1, "%s:%s", param->method, param->uri);
			ret = get_sha_512_256_hash((const unsigned char *)&(param->a2), length, (unsigned char *)&(param->a2_hash), 150);
			if(ret == -1){
#ifdef _DEBUG
				printf("[E] A2 get_sha_512_256_hash error\n");
#endif
				return -1;
			}
		}

		// response SHA-512-256(A1):nonce:nc:cnonce:qop:SHA-512-256(A2)
		length = strlen(param->a1_hash) + strlen(param->nonce) + strlen(param->nc) + strlen(param->cnonce) + strlen(param->qop) + strlen(param->a2_hash) + 5;	// 5 colon
		ret = snprintf(param->response, length+1, "%s:%s:%s:%s:%s:%s", param->a1_hash, param->nonce, param->nc, param->cnonce, param->qop, param->a2_hash);
		ret = get_sha_512_256_hash((const unsigned char *)&(param->response), length, (unsigned char *)&(param->response_hash), 150);
		if(ret == -1){
#ifdef _DEBUG
			printf("[E] response get_sha_512_256_hash error\n");
#endif
			return -1;
		}

	}else{
#ifdef _DEBUG
		printf("[E] Not implemented.\n");
#endif
		return -1;
	}

	return 0;
}


int encrypt_des_ecb(unsigned char *plaintext, int plaintext_length, unsigned char *key, unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *ctx = NULL;
	int length = 0;
	int ciphertext_length = 0;
	int ret = 0;

	ctx = EVP_CIPHER_CTX_new();
	if(ctx == NULL){
#ifdef _DEBUG
//		printf("[E] EVP_CIPHER_CTX_new error\n");
#endif
		return -1;
	}

	ret = EVP_EncryptInit(ctx, EVP_des_ecb(), key, NULL);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_EncryptInit error\n");
#endif
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	ret = EVP_EncryptUpdate(ctx, ciphertext, &length, plaintext, plaintext_length);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_EncryptUpdate error\n");
#endif
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	ciphertext_length = length;

	ret = EVP_EncryptFinal(ctx, ciphertext+length, &length);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_EncryptFinal error\n");
#endif
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	ciphertext_length += length;

	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_length;
}


int get_md4_hash(const unsigned char *input, int input_length, unsigned char *output, int output_size)
{
	EVP_MD_CTX *ctx = NULL;
	int ret = 0;
	unsigned char *digest = NULL;
	unsigned int length = 0;

	ctx = EVP_MD_CTX_new();
	if(ctx == NULL){
#ifdef _DEBUG
//		printf("[E] EVP_MD_CTX_new error\n");
#endif
		return -1;
	}

	ret = EVP_DigestInit_ex(ctx, EVP_md4(), NULL);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_DigestInit_ex error\n");
#endif
		EVP_MD_CTX_free(ctx);
		return -1;
	}

	ret = EVP_DigestUpdate(ctx, input, input_length);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_DigestUpdate error\n");
#endif
		EVP_MD_CTX_free(ctx);
		return -1;
	}

	if(EVP_MD_size(EVP_md4()) > output_size){
#ifdef _DEBUG
//		printf("[E] output_size error\n");
#endif
		EVP_MD_CTX_free(ctx);
		return -1;
	}

	digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_md4()));
	if(digest == NULL){
#ifdef _DEBUG
//		printf("[E] OPENSSL_malloc error\n");
#endif
		EVP_MD_CTX_free(ctx);
		return -1;
	}

	ret = EVP_DigestFinal_ex(ctx, (unsigned char *)digest, &length);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_DigestFinal_ex error\n");
#endif
		OPENSSL_free(digest);
		EVP_MD_CTX_free(ctx);
		return -1;
	}

	memcpy(output, digest, length);

	OPENSSL_free(digest);
	EVP_MD_CTX_free(ctx);

	return length;
}


int get_hmac_md5(const unsigned char *input, int input_length, const unsigned char *key, int key_length, unsigned char *output, int output_size)
{
	EVP_MAC *mac = NULL;
	EVP_MAC_CTX *ctx = NULL;
	const char digest[] = "MD5";
	OSSL_PARAM params[] = {
		OSSL_PARAM_construct_utf8_string("digest", (char *)&digest, 0),
		OSSL_PARAM_construct_end()
	};
	int ret = 0;
	size_t length = 0;

	mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	if(mac == NULL){
#ifdef _DEBUG
//		printf("[E] EVP_MAC_fetch error\n");
#endif
		return -1;
	}

	ctx = EVP_MAC_CTX_new(mac);
	if(ctx == NULL){
#ifdef _DEBUG
//		printf("[E] EVP_MAC_CTX_new error\n");
#endif
		EVP_MAC_free(mac);
		return -1;
	}

	ret = EVP_MAC_init(ctx, key, key_length, params);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_MAC_init error\n");
#endif
		EVP_MAC_CTX_free(ctx);
		EVP_MAC_free(mac);
		return -1;
	}

	ret = EVP_MAC_update(ctx, input, input_length);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_MAC_update error\n");
#endif
		EVP_MAC_CTX_free(ctx);
		EVP_MAC_free(mac);
		return -1;
	}

	ret = EVP_MAC_final(ctx, output, (size_t *)&length, output_size);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_MAC_final error\n");
#endif
		EVP_MAC_CTX_free(ctx);
		EVP_MAC_free(mac);
		return -1;
	}

	EVP_MAC_CTX_free(ctx);
	EVP_MAC_free(mac);

	return length;
}


int get_upper_string(const char *input, int input_length, char *output)
{
	for(int i=0; i<input_length; i++){
		output[i] = toupper(input[i]);
	}

	return 0;
}


int convert_utf8_to_utf16(const char *input, char *output, size_t output_size)
{
	iconv_t conv;
	char buffer[BUFFER_SIZE+1];
	char *input_buffer = buffer;
	char *output_buffer = output;
	size_t input_length = strlen(input);
	int output_length = (int)input_length*2;
	size_t size = output_size-1;
	int ret = 0;

	if(input_length*2 > BUFFER_SIZE){
#ifdef _DEBUG
		printf("[E] input_length error\n");
#endif
		return -1;
	}

	bzero(buffer, BUFFER_SIZE+1);
	strncpy(buffer, input, input_length);

	conv = iconv_open("UTF-16LE", "UTF-8");
	if(conv == (iconv_t)-1){
#ifdef _DEBUG
		printf("[E] iconv_open error\n");
#endif
		return -1;
	}

	ret = iconv(conv, &input_buffer, &input_length, &output_buffer, &size);
	if(ret == -1){
#ifdef _DEBUG
		printf("[E] iconv error\n");
#endif
		return -1;
	}

	ret = iconv_close(conv);
	if(ret == -1){
#ifdef _DEBUG
		printf("[E] iconv_close error\n");
#endif
		return -1;
	}

	return output_length;
}


int get_av_pair_value(struct challenge_message *challenge_message, uint16_t av_id, unsigned char *data, int data_size)
{
	uint16_t target_info_len = 0;
    uint16_t target_info_max_len = 0;
    uint32_t target_info_buffer_offset = 0;
	unsigned char *pos = NULL;
	struct av_pair *av_pair = NULL;
	int length = 0;
	int data_length = 0;

	target_info_len = challenge_message->target_info_fields.target_info_len;
	target_info_max_len = challenge_message->target_info_fields.target_info_max_len;
	target_info_buffer_offset = challenge_message->target_info_fields.target_info_buffer_offset;
	pos = (unsigned char *)challenge_message+target_info_buffer_offset;

#ifdef _DEBUG
//	printf("target_info_len:%d\n", target_info_len);
//	printf("target_info_max_len:%d\n", target_info_max_len);
//	printf("target_info_buffer_offset:%d\n", target_info_buffer_offset);
#endif

	while(length < target_info_max_len){
		av_pair = (struct av_pair *)pos;

#ifdef _DEBUG
//		printf("av_id:%d\n", av_pair->av_id);
//		printf("av_len:%d\n", av_pair->av_len);
#endif

		if(av_id == av_pair->av_id){
			if(av_pair->av_len > data_size){
#ifdef _DEBUG
				printf("[E] data_size error\n");
#endif
				break;
			}else{
				data_length = av_pair->av_len;
				memcpy(data, &av_pair->value, av_pair->av_len);
			}
		}

		length += 4 + av_pair->av_len;
		pos += length;
	}

	return data_length;
}


/*
 * Reference:
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3
 */
int ntowfv2(const char *user, const char *password, const char *userdom, unsigned char *output, int output_size)
{
	int ret = 0;

	int password_length = strlen(password);
	int password_utf16le_length = 0;
	int password_utf16le_md4_length = 0;
	unsigned char password_utf16le[1000];
	unsigned char password_utf16le_md4[100];
	bzero(&password_utf16le, 1000);
	bzero(&password_utf16le_md4,16);

	int user_length = strlen(user);
	int userdom_length = strlen(userdom);
	int user_upper_userdom_length = 0;
	int user_upper_userdom_utf16le_length = 0;
	char user_upper[256];
	char user_upper_userdom[1000];
	unsigned char user_upper_userdom_utf16le[2000];
	char *pos = NULL;
	bzero(&user_upper, 256);
	bzero(&user_upper_userdom, 1000);
	bzero(&user_upper_userdom_utf16le, 2000);

	int response_key_length = 0;
	unsigned char response_key[16];
	bzero(&response_key, 16);


	// UNICODE(Passwd)
	ret = convert_utf8_to_utf16(password, (char *)&password_utf16le, 1000);
	if(ret == -1){
#ifdef _DEBUG
		printf("[E] convert_utf8_to_utf16 error\n");
#endif
		return -1;
	}
	password_utf16le_length = ret;

#ifdef _DEBUG
//	printf("password_utf16le:%d\n", password_utf16le_length);
//	print_bytes(password_utf16le, password_utf16le_length);
#endif

	// MD4(UNICODE(Passwd))
	ret = get_md4_hash((const unsigned char *)&password_utf16le, password_utf16le_length, (unsigned char *)&password_utf16le_md4, 16);
	if(ret == -1){
#ifdef _DEBUG
		printf("[E] get_md4_hash error\n");
#endif
		return -1;
	}
	password_utf16le_md4_length = ret;

#ifdef _DEBUG
//	printf("password_utf16le_md4:%d\n", password_utf16le_md4_length);
//	print_bytes(password_utf16le_md4, password_utf16le_md4_length);
#endif

	// Uppercase(user)
	ret = get_upper_string(user, strlen(user), (char *)&user_upper);

	// ConcatenationOf(Uppercase(User), UserDom)
	user_upper_userdom_length = 0;
	pos = (char *)&user_upper_userdom;

	memcpy(pos, &user_upper, user_length);
	user_upper_userdom_length += user_length;

	memcpy(pos+user_upper_userdom_length, userdom, userdom_length);
	user_upper_userdom_length += userdom_length;

	// UNICODE(ConcatenationOf(Uppercase(User), UserDom))
	ret = convert_utf8_to_utf16((const char *)&user_upper_userdom, (char *)&user_upper_userdom_utf16le, 2000);
	if(ret == -1){
#ifdef _DEBUG
		printf("[E] convert_utf8_to_utf16 error\n");
#endif
		return -1;
	}
	user_upper_userdom_utf16le_length = ret;

#ifdef _DEBUG
//	printf("user_upper_userdom_utf16le:%d\n", user_upper_userdom_utf16le_length);
//	print_bytes(user_upper_userdom_utf16le, user_upper_userdom_utf16le_length);
#endif

	// HMAC_MD5(K, M)	Indicates the computation of a 16-byte HMAC-keyed MD5 message digest of the byte string M using the key K.
	// HMAC_MD5(MD4(UNICODE(Passwd)), UNICODE(ConcatenationOf(Uppercase(User), UserDom)))
	ret = get_hmac_md5((const unsigned char *)&user_upper_userdom_utf16le, user_upper_userdom_utf16le_length, (const unsigned char *)password_utf16le_md4, password_utf16le_md4_length, (unsigned char *)&response_key, 16);
	if(ret == -1){
#ifdef _DEBUG
		printf("[E] get_hmac_md5 error\n");
#endif
		return -1;
	}
	response_key_length = ret;

#ifdef _DEBUG
//	printf("response_key:%d\n", response_key_length);
//	print_bytes(response_key, response_key_length);
#endif

	if(output_size > response_key_length){
#ifdef _DEBUG
		printf("[E] output_size error\n");
#endif
		return -1;
	}

	memcpy(output, response_key, response_key_length);

	return response_key_length;
}


/*
 * Reference:
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3
 */
int lmowfv2(const char *user, const char *password, const char *userdom, unsigned char *output, int output_size)
{
	int ret = 0;
	int response_key_length = 0;

	ret = ntowfv2(user, password, userdom, output, output_size);
	if(ret == -1){
#ifdef _DEBUG
		printf("[E] ntowfv2 error\n");
#endif
		return -1;
	}
	response_key_length = ret;

    return response_key_length;
}


/*
 * Reference:
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3
 */
int generate_response_ntlmv2(struct challenge_message *challenge_message, struct authenticate_message *authenticate_message)
{
	int ret = 0;

	unsigned char response_key_nt[16];
	unsigned char response_key_lm[16];
	int response_key_nt_length = 0;
	int response_key_lm_length = 0;
	unsigned char server_challenge[8];
	unsigned char client_challenge[8];

	unsigned char responser_version = 1;
	unsigned char hi_responser_version = 1;
	int64_t timestamp = 0;
	unsigned char server_name[1000];
	int server_name_length = 0;

	unsigned char temp[2000];
	int temp_length = 0;
	unsigned char *pos = NULL;

	unsigned char nt_proof_str[16];
	int nt_proof_str_length = 0;
	unsigned char tmp1[3000];
	int tmp1_length = 0;

	unsigned char nt_challenge_response[2016];
	int nt_challenge_response_length = 0;

	unsigned char lm_challenge_response[24];
	int lm_challenge_response_length = 0;
	unsigned char server_challenge_client_challenge[16];
	unsigned char tmp2[16];
	int tmp2_length = 0;

	unsigned char session_base_key[16];
	int session_base_key_length = 0;

	int authenticate_message_length = 0;
	int32_t offset = 0;
	int forward_proxy_user_domainname_length = strlen(forward_proxy_user_domainname);
	int forward_proxy_username_length = strlen(forward_proxy_username);
	int forward_proxy_workstationname_length = strlen(forward_proxy_workstationname);


	if(forward_proxy_username == NULL && forward_proxy_password == NULL){
		// Special case for anonymous authentication
		// Set NtChallengeResponseLen to 0
		// Set NtChallengeResponseMaxLen to 0
		// Set NtChallengeResponseBufferOffset to 0
		// Set LmChallengeResponse to Z(1)
#ifdef _DEBUG
		printf("[E] Not implemented.\n");
#endif
		return -1;
	}else{
		// ResponseKeyNT
		bzero(&response_key_nt, 16);
		ret = ntowfv2((const char *)forward_proxy_username, (const char *)forward_proxy_password, (const char *)forward_proxy_user_domainname, (unsigned char *)&response_key_nt, 16);
		if(ret == -1){
#ifdef _DEBUG
			printf("[E] ntowfv2 error\n");
#endif
			return -1;
		}
		response_key_nt_length = ret;


		// ResponseKeyLM
		bzero(&response_key_lm, 16);
		ret = lmowfv2((const char *)forward_proxy_username, (const char *)forward_proxy_password, (const char *)forward_proxy_user_domainname, (unsigned char *)&response_key_lm, 16);
		if(ret == -1){
#ifdef _DEBUG
			printf("[E] lmowfv2 error\n");
#endif
			return -1;
		}
		response_key_lm_length = ret;


		// ServerChallenge
		bzero(&server_challenge, 8);
		memcpy(&server_challenge, &challenge_message->server_challenge, 8);

#ifdef _DEBUG
//		printf("server_challenge:%d\n", 8);
//		print_bytes(server_challenge, 8);
#endif


		// ClientChallenge
		bzero(&client_challenge, 8);
		ret = RAND_bytes((unsigned char *)&client_challenge, 8);
		if(ret != 1){
#ifdef _DEBUG
			printf("[E] client_challenge generate error:%s.\n", ERR_error_string(ERR_peek_last_error(), NULL));
#endif
			return -1;
		}

#ifdef _DEBUG
//		printf("client_challenge:%d\n", 8);
//		print_bytes(client_challenge, 8);
#endif


		// TIME
		timestamp = (time(NULL) + 11644473600) * 10000000;

#ifdef _DEBUG
//		printf("time:%d\n", 8);
//		print_bytes((unsigned char *)&timestamp, 8);
#endif


		// ServerName
		// The NtChallengeResponseFields.NTLMv2_RESPONSE.NTLMv2_CLIENT_CHALLENGE.AvPairs field structure of the AUTHENTICATE_MESSAGE payload.
		bzero(&server_name, 1000);
		server_name_length = challenge_message->target_info_fields.target_info_len;
		pos = (unsigned char *)challenge_message;
		pos += challenge_message->target_info_fields.target_info_buffer_offset;

		if(server_name_length > 1000){
#ifdef _DEBUG
			printf("[E] server_name_length error\n");
#endif
			return -1;
		}
		memcpy(&server_name, pos, server_name_length);

#ifdef _DEBUG
//		printf("server_name:%d\n", server_name_length);
//		print_bytes((unsigned char *)&server_name, server_name_length);
#endif


		// temp
		// ConcatenationOf(Responserversion, HiResponserversion, Z(6), Time, ClientChallenge, Z(4), ServerName, Z(4))
		bzero(&temp, 2000);
		pos = (unsigned char *)&temp;
		temp_length = 0;

		memcpy(pos+temp_length, &responser_version, 1);
		temp_length += 1;

		memcpy(pos+temp_length, &hi_responser_version, 1);
		temp_length += 1;

		temp_length += 6;	// Z(6)

		memcpy(pos+temp_length, &timestamp, 8);
		temp_length += 8;

		memcpy(pos+temp_length, &client_challenge, 8);
		temp_length += 8;

		temp_length += 4;	// Z(4)

		memcpy(pos+temp_length, &server_name, server_name_length);
		temp_length += server_name_length;

		temp_length += 4;	// Z(4)

#ifdef _DEBUG
//		printf("temp:%d\n", temp_length);
//		print_bytes((unsigned char *)&temp, temp_length);
#endif


		// NTProofStr
		// ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge,temp)
		bzero(&tmp1, 3000);
		pos = (unsigned char *)&tmp1;
		tmp1_length = 0;

		memcpy(pos+tmp1_length, &server_challenge, 8);
		tmp1_length += 8;

		memcpy(pos+tmp1_length, &temp, temp_length);
		tmp1_length += temp_length;

#ifdef _DEBUG
//		printf("tmp1:%d\n", tmp1_length);
//		print_bytes((unsigned char *)&tmp1, tmp1_length);
#endif

		// HMAC_MD5(ResponseKeyNT, ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge,temp))
		bzero(&nt_proof_str, 16);
		ret = get_hmac_md5((unsigned char *)&tmp1, tmp1_length, (unsigned char *)&response_key_nt, response_key_nt_length, (unsigned char *)&nt_proof_str, 16);
		if(ret == -1){
#ifdef _DEBUG
			printf("[E] get_hmac_md5 error\n");
#endif
			return -1;
		}
		nt_proof_str_length = ret;

#ifdef _DEBUG
//		printf("nt_proof_str:%d\n", nt_proof_str_length);
//		print_bytes((unsigned char *)&nt_proof_str, nt_proof_str_length);
#endif


		// NtChallengeResponse
		// ConcatenationOf(NTProofStr, temp)
		bzero(&nt_challenge_response, 2016);
		pos = (unsigned char *)&nt_challenge_response;
		nt_challenge_response_length = 0;

		memcpy(pos, &nt_proof_str, nt_proof_str_length);
		nt_challenge_response_length += nt_proof_str_length;

		memcpy(pos+nt_proof_str_length, &temp, temp_length);
		nt_challenge_response_length += temp_length;

#ifdef _DEBUG
//		printf("nt_challenge_response:%d\n", nt_challenge_response_length);
//		print_bytes((unsigned char *)&nt_challenge_response, nt_challenge_response_length);
#endif


		// LmChallengeResponse
		// ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge, ClientChallenge)
		bzero(&server_challenge_client_challenge, 16);
		pos = (unsigned char *)&server_challenge_client_challenge;

		memcpy(pos, &server_challenge, 8);
		memcpy(pos+8, &client_challenge, 8);

#ifdef _DEBUG
//		printf("server_challenge_client_challenge:%d\n", 16);
//		print_bytes((unsigned char *)&server_challenge_client_challenge, 16);
#endif

		// HMAC_MD5(ResponseKeyLM, ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge, ClientChallenge))
		bzero(&tmp2, 16);
		ret = get_hmac_md5((unsigned char *)&server_challenge_client_challenge, 16, (unsigned char *)&response_key_lm, response_key_lm_length, (unsigned char *)&tmp2, 16);
		if(ret == -1){
#ifdef _DEBUG
			printf("[E] get_hmac_md5 error\n");
#endif
			return -1;
		}
		tmp2_length = ret;

#ifdef _DEBUG
//		printf("tmp2:%d\n", tmp2_length);
//		print_bytes((unsigned char *)&tmp2, tmp2_length);
#endif

		// ConcatenationOf(HMAC_MD5(ResponseKeyLM, ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge, ClientChallenge)), ClientChallenge)
		bzero(&lm_challenge_response, 24);
		pos = (unsigned char *)&lm_challenge_response;
		lm_challenge_response_length = 0;

		memcpy(pos, &tmp2, tmp2_length);
		lm_challenge_response_length += tmp2_length;

		memcpy(pos+tmp2_length, &client_challenge, 8);
		lm_challenge_response_length += 8;

#ifdef _DEBUG
//		printf("lm_challenge_response:%d\n", lm_challenge_response_length);
//		print_bytes((unsigned char *)&lm_challenge_response, lm_challenge_response_length);
#endif


		// SessionBaseKey
		// HMAC_MD5(ResponseKeyNT, NTProofStr)
		bzero(&session_base_key, 16);
		ret = get_hmac_md5((unsigned char *)&nt_proof_str, nt_proof_str_length, (unsigned char *)&response_key_nt, response_key_nt_length, (unsigned char *)&session_base_key, 16);
		if(ret == -1){
#ifdef _DEBUG
			printf("[E] get_hmac_md5 error\n");
#endif
			return -1;
		}
		session_base_key_length = ret;

#ifdef _DEBUG
//		printf("session_base_key:%d\n", session_base_key_length);
//		print_bytes((unsigned char *)&session_base_key, session_base_key_length);
#endif


		// authenticate_message
		pos = (unsigned char *)authenticate_message;
		authenticate_message_length = 0;
		offset = 0x40;	// start buffer offset

		// authenticate_message Signature
		memcpy(&authenticate_message->signature, "NTLMSSP\0", 8);

		// authenticate_message MessageType
		authenticate_message->message_type = NtLmAuthenticate;

		// authenticate_message LmChallengeResponseFields
		authenticate_message->lm_challenge_response_fields.lm_challenge_response_len = lm_challenge_response_length;
		authenticate_message->lm_challenge_response_fields.lm_challenge_response_max_len = lm_challenge_response_length;
		authenticate_message->lm_challenge_response_fields.lm_challenge_response_buffer_offset = 0x40;

		memcpy(pos+offset, &lm_challenge_response, lm_challenge_response_length);
		offset += lm_challenge_response_length;

		// authenticate_message NtChallengeResponseFields
		authenticate_message->nt_challenge_response_fields.nt_challenge_response_len = nt_challenge_response_length;
		authenticate_message->nt_challenge_response_fields.nt_challenge_response_max_len = nt_challenge_response_length;
		authenticate_message->nt_challenge_response_fields.nt_challenge_response_buffer_offset = offset;

		memcpy(pos+offset, &nt_challenge_response, nt_challenge_response_length);
		offset += nt_challenge_response_length;

		// authenticate_message DomainNameFields
		authenticate_message->domain_name_fields.domain_name_len = forward_proxy_user_domainname_length;
		authenticate_message->domain_name_fields.domain_name_max_len = forward_proxy_user_domainname_length;
		authenticate_message->domain_name_fields.domain_name_buffer_offset = offset;

		memcpy(pos+offset, forward_proxy_user_domainname, forward_proxy_user_domainname_length);
		offset += forward_proxy_user_domainname_length;

		// authenticate_message UserNameFields
		authenticate_message->user_name_fields.user_name_len = forward_proxy_username_length;
		authenticate_message->user_name_fields.user_name_max_len = forward_proxy_username_length;
		authenticate_message->user_name_fields.user_name_buffer_offset = offset;

		memcpy(pos+offset, forward_proxy_username, forward_proxy_username_length);
		offset += forward_proxy_username_length;

		// authenticate_message WorkstationFields
		authenticate_message->workstation_fields.workstation_len = forward_proxy_workstationname_length;
		authenticate_message->workstation_fields.workstation_max_len = forward_proxy_workstationname_length;
		authenticate_message->workstation_fields.workstation_buffer_offset = offset;

		memcpy(pos+offset, forward_proxy_workstationname, forward_proxy_workstationname_length);
		offset += forward_proxy_workstationname_length;

		// authenticate_message EncryptedRandomSessionKeyFields
		authenticate_message->encrypted_random_session_key_fields.encrypted_random_session_key_len = 0;
		authenticate_message->encrypted_random_session_key_fields.encrypted_random_session_key_max_len = 0;
		authenticate_message->encrypted_random_session_key_fields.encrypted_random_session_key_buffer_offset = 0;

		authenticate_message_length = offset;

		// authenticate_message NegotiateFlags
		authenticate_message->negotiate_flags.negotiate_unicode                  = 0;
		authenticate_message->negotiate_flags.negotiate_oem                      = 1;
		authenticate_message->negotiate_flags.request_target                     = 1;
		authenticate_message->negotiate_flags.request_0x00000008                 = 0;
		authenticate_message->negotiate_flags.negotiate_sign                     = 0;
		authenticate_message->negotiate_flags.negotiate_seal                     = 0;
		authenticate_message->negotiate_flags.negotiate_datagram                 = 0;
		authenticate_message->negotiate_flags.negotiate_lan_manager_key          = 0;
		authenticate_message->negotiate_flags.negotiate_0x00000100               = 0;
		authenticate_message->negotiate_flags.negotiate_ntlm_key                 = 1;
		authenticate_message->negotiate_flags.negotiate_nt_only                  = 0;
		authenticate_message->negotiate_flags.negotiate_anonymous                = 0;
		authenticate_message->negotiate_flags.negotiate_oem_domain_supplied      = 0;
		authenticate_message->negotiate_flags.negotiate_oem_workstation_supplied = 0;
		authenticate_message->negotiate_flags.negotiate_0x00004000               = 0;
		authenticate_message->negotiate_flags.negotiate_always_sign              = 1;
		authenticate_message->negotiate_flags.target_type_domain                 = 1;
		authenticate_message->negotiate_flags.target_type_server                 = 0;
		authenticate_message->negotiate_flags.target_type_share                  = 0;
		authenticate_message->negotiate_flags.negotiate_extended_security        = 1;
		authenticate_message->negotiate_flags.negotiate_identify                 = 0;
		authenticate_message->negotiate_flags.negotiate_0x00200000               = 0;
		authenticate_message->negotiate_flags.request_non_nt_session             = 0;
		authenticate_message->negotiate_flags.negotiate_target_info              = 1;
		authenticate_message->negotiate_flags.negotiate_0x01000000               = 0;
		authenticate_message->negotiate_flags.negotiate_version                  = 1;
		authenticate_message->negotiate_flags.negotiate_0x04000000               = 0;
		authenticate_message->negotiate_flags.negotiate_0x08000000               = 0;
		authenticate_message->negotiate_flags.negotiate_0x10000000               = 0;
		authenticate_message->negotiate_flags.negotiate_128                      = 0;
		authenticate_message->negotiate_flags.negotiate_key_exchange             = 0;
		authenticate_message->negotiate_flags.negotiate_56                       = 0;

#ifdef _DEBUG
//		printf("authenticate_message:%d\n", authenticate_message_length);
//		print_bytes((unsigned char *)authenticate_message, authenticate_message_length);
#endif
	}

	return authenticate_message_length;
}


int display_gss_error(OM_uint32 status_value, int status_type, gss_OID mechanism_type, char *buffer, int buffer_size)
{
	OM_uint32 major_status;
	OM_uint32 minor_status;
	OM_uint32 message_context = 0;
	gss_buffer_desc status_string = GSS_C_EMPTY_BUFFER;
	int length = 0;

	do{
		major_status = gss_display_status(&minor_status, status_value, status_type, mechanism_type, &message_context, &status_string);
		if(major_status == GSS_S_COMPLETE && status_string.length > 0){
			if(buffer_size > length + status_string.length + 3){
				length += snprintf(buffer+length, buffer_size-length, "%.*s. ", (int)status_string.length, (char *)status_string.value);
			}
		}

		gss_release_buffer(&minor_status, &status_string);

	}while(!GSS_ERROR(major_status) && message_context);

	return length;
}


gss_name_t get_spn(char *spn)
{
	OM_uint32 major_status;
	OM_uint32 minor_status;
	gss_buffer_desc spn_token = GSS_C_EMPTY_BUFFER;
	gss_name_t spn_gss_name = GSS_C_NO_NAME;
	char error_buffer[1000];
	int ret = 0;

	spn_token.value = spn;
	spn_token.length = strlen(spn_token.value) + 1;

	major_status = gss_import_name(&minor_status, &spn_token, GSS_KRB5_NT_PRINCIPAL_NAME, &spn_gss_name);
	if(GSS_ERROR(major_status)){
#ifdef _DEBUG
		bzero(&error_buffer, 1000);
		ret = display_gss_error(minor_status, GSS_C_GSS_CODE, GSS_C_NO_OID, (char *)&error_buffer, 1000);
		printf("[E] gss_import_name error:\n%s", error_buffer);
#endif
		return GSS_C_NO_NAME;
	}

	return spn_gss_name;
}


int get_base64_kerberos_token(char *spn, char *b64_kerberos_token, int b64_kerberos_token_size)
{
	OM_uint32 major_status;
	OM_uint32 minor_status;
	gss_OID_desc spnego_mechanism_oid = {6, (char *)"\x2b\x06\x01\x05\x05\x02"};
	gss_OID_set_desc mechanism;
	mechanism.elements = &spnego_mechanism_oid;
	mechanism.count = 1;
	OM_uint32 req_flags = GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_MUTUAL_FLAG;
	gss_ctx_id_t context = GSS_C_NO_CONTEXT;
	gss_name_t spn_gss_name = get_spn(spn);
	gss_buffer_desc output_token;
	int ret = 0;
	int b64_kerberos_token_length = 0;
	char error_buffer[1000];

	major_status = gss_init_sec_context(&minor_status, GSS_C_NO_CREDENTIAL, &context, spn_gss_name, mechanism.elements, req_flags, 0, GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER, NULL, &output_token, NULL, NULL);

	if(GSS_ERROR(major_status)){
#ifdef _DEBUG
		bzero(&error_buffer, 1000);
		ret = display_gss_error(minor_status, GSS_C_GSS_CODE, mechanism.elements, (char *)&error_buffer, 1000);
		printf("[E] gss_init_sec_context error:\n%s", error_buffer);
#endif

		if(context != GSS_C_NO_CONTEXT){
			gss_delete_sec_context(&minor_status, &context, GSS_C_NO_BUFFER);
		}

		if(spn_gss_name != GSS_C_NO_NAME){
			gss_release_name(&minor_status, &spn_gss_name);
		}

		gss_release_buffer(&minor_status, &output_token);

		return -1;
	}else if(output_token.length != 0){

		ret = encode_base64(output_token.value, output_token.length, b64_kerberos_token, b64_kerberos_token_size);
		if(ret == -1){
#ifdef _DEBUG
			printf("[E] encode_base64 error\n");
#endif

			if(context != GSS_C_NO_CONTEXT){
				gss_delete_sec_context(&minor_status, &context, GSS_C_NO_BUFFER);
			}

			if(spn_gss_name != GSS_C_NO_NAME){
				gss_release_name(&minor_status, &spn_gss_name);
			}

			gss_release_buffer(&minor_status, &output_token);

			return -1;
		}
		b64_kerberos_token_length = ret;
	}

	if(context != GSS_C_NO_CONTEXT){
		gss_delete_sec_context(&minor_status, &context, GSS_C_NO_BUFFER);
	}

	if(spn_gss_name != GSS_C_NO_NAME){
		gss_release_name(&minor_status, &spn_gss_name);
	}

	gss_release_buffer(&minor_status, &output_token);

	return b64_kerberos_token_length;
}


void enable_blocking_socket(int sock)	// blocking
{
	int flags = 0;
	int ret = 0;

	flags = fcntl(sock, F_GETFL, 0);
	ret = fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
	usleep(5000);
	if(ret == -1){
#ifdef _DEBUG
		printf("[E] enable_blocking_socket error:%d\n", errno);
#endif
	}

	return;
}


void disable_blocking_socket(int sock)	// non blocking
{
	int flags = 0;
	int ret = 0;

	flags = fcntl(sock, F_GETFL, 0);
	ret = fcntl(sock, F_SETFL, flags | O_NONBLOCK);
	usleep(5000);
	if(ret == -1){
#ifdef _DEBUG
		printf("[E] disable_blocking_socket error:%d\n", errno);
#endif
	}

	return;
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
	
	tmp[0] = (unsigned char)(encrypt_data_length >> 24);
	tmp[1] = (unsigned char)(encrypt_data_length >> 16);
	tmp[2] = (unsigned char)(encrypt_data_length >> 8);
	tmp[3] = (unsigned char)encrypt_data_length;
	
	ret = encrypt_aes((unsigned char *)tmp, 4, aes_key, aes_iv, data->encrypt_data_length);
	if(ret != 16){	// unsigned char encrypt_data_length[16]
		free(tmp);
		free(data);
		return -1;
	}
	
	len = 16 + encrypt_data_length;
	
	if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
		printf("[E] gettimeofday error.\n");
#endif
		free(tmp);
		free(data);
		return -1;
	}
	
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
			printf("[I] send_data_aes timeout.\n");
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
	int rec,sen;
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
	int rec,sen;
	int len = 0;
	int recv_length = 0;
	int send_length = 0;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	int ret = 0;
	struct send_recv_data_aes * data = (struct send_recv_data_aes *)calloc(1, sizeof(struct send_recv_data_aes));
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
			bzero(data, sizeof(struct send_recv_data_aes));
			bzero(buffer, BUFFER_SIZE*2);

			rec = recv(client_sock, buffer, BUFFER_SIZE, 0);
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
					sen = send(target_sock, (unsigned char *)data+send_length, len, 0);
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

		if(FD_ISSET(target_sock, &readfds)){
			bzero(tmp, 16);
			bzero(buffer, BUFFER_SIZE*2);
			bzero(buffer2, BUFFER_SIZE*2);

			len = 16;
			recv_length = 0;

			while(len > 0){
				rec = recv(target_sock, (unsigned char *)buffer+recv_length, len, 0);	// unsigned char encrypt_data_length[16]
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
				rec = recv(target_sock, (unsigned char *)buffer+recv_length, len, 0);
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
				sen = send(client_sock, (unsigned char *)buffer2+send_length, len, 0);
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

	free(tmp);
	free(data);
	free(buffer);
	free(buffer2);
	return 0;
}


int forwarder_tls(int client_sock, int target_sock, SSL *target_ssl, long tv_sec, long tv_usec)
{
	int rec,sen;
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

			rec = recv(client_sock, buffer, BUFFER_SIZE, 0);
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
					sen = SSL_write(target_ssl, buffer, rec);
					err = SSL_get_error(target_ssl, sen);
					
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
		
		if(FD_ISSET(target_sock, &readfds)){
			bzero(buffer, BUFFER_SIZE*2);

			rec = SSL_read(target_ssl, buffer, BUFFER_SIZE);
			err = SSL_get_error(target_ssl, rec);
			
			if(err == SSL_ERROR_NONE){
				len = rec;
				send_length = 0;
				
				while(len > 0){
					sen = send(client_sock, (unsigned char *)buffer+send_length, len, 0);
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
	}

	free(buffer);
	return 0;
}


int ssl_connect_non_blocking(int sock, SSL *ssl, long tv_sec, long tv_usec)
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
	
	disable_blocking_socket(sock);	// non blocking
	
	if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
		printf("[E] gettimeofday error.\n");
#endif
		enable_blocking_socket(sock);	// blocking
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
			printf("[I] ssl_connect_non_blocking select timeout.\n");
#endif
			enable_blocking_socket(sock);	// blocking
			return -2;
		}
		
		if(FD_ISSET(sock, &readfds) || FD_ISSET(sock, &writefds)){
			ret = SSL_connect(ssl);
			err = SSL_get_error(ssl, ret);
			
			if(err == SSL_ERROR_NONE){
				break;
			}else if(err == SSL_ERROR_WANT_READ){
				usleep(5000);
			}else if(err == SSL_ERROR_WANT_WRITE){
				usleep(5000);
			}else{
#ifdef _DEBUG
				printf("[E] SSL_connect error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
				enable_blocking_socket(sock);	// blocking
				return -2;
			}
		}
		
		if(gettimeofday(&end, NULL) == -1){
#ifdef _DEBUG
			printf("[E] gettimeofday error.\n");
#endif
			enable_blocking_socket(sock);	// blocking
			return -2;
		}
		
		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec)){
#ifdef _DEBUG
			printf("[I] ssl_connect_non_blocking timeout.\n");
#endif
			enable_blocking_socket(sock);	// blocking
			return -2;
		}
	}
	
	enable_blocking_socket(sock);	// blocking

	return ret;
}


void fini_ssl(struct ssl_param *param)
{
	// Socks5 over TLS
	if(param->target_ssl_socks5 != NULL){
		SSL_shutdown(param->target_ssl_socks5);
		SSL_free(param->target_ssl_socks5);
	}
	if(param->target_ctx_socks5 != NULL){
		SSL_CTX_free(param->target_ctx_socks5);
	}
	
	// HTTPS
	if(param->target_ssl_http != NULL){
		SSL_shutdown(param->target_ssl_http);
		SSL_free(param->target_ssl_http);
	}
	if(param->target_ctx_http != NULL){
		SSL_CTX_free(param->target_ctx_http);
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


int worker(void *ptr)
{
	struct worker_param *worker_param = (struct worker_param *)ptr;
	int client_sock = worker_param->client_sock;
	long tv_sec = worker_param->tv_sec;		// recv send
	long tv_usec = worker_param->tv_usec;		// recv send
	long forwarder_tv_sec = worker_param->forwarder_tv_sec;
	long forwarder_tv_usec = worker_param->forwarder_tv_usec;
	free(ptr);
	
	int forward_proxy_sock = -1;
	int target_sock = -1;

	struct sockaddr_in forward_proxy_addr;		// IPv4
	struct sockaddr_in target_addr;				// IPv4
	struct sockaddr_in *tmp_ipv4;
	struct sockaddr_in6 forward_proxy_addr6;	// IPv6
	struct sockaddr_in6 target_addr6;			// IPv6
	struct sockaddr_in6 *tmp_ipv6;
	struct addrinfo hints;
	struct addrinfo *forward_proxy_host;
	struct addrinfo *target_host;

	char *forward_proxy_domainname = forward_proxy_ip;
	u_short forward_proxy_domainname_length = 0;
	if(forward_proxy_domainname != NULL){
		forward_proxy_domainname_length = strlen(forward_proxy_domainname);
	}
	char *forward_proxy_port_number = forward_proxy_port;

	int proxy_credential_length = 0;
	char proxy_credential[1000];
	char proxy_b64_credential[2000];
	bzero(&proxy_credential, 1000);
	bzero(&proxy_b64_credential, 2000);

	char http_header_data[2000];
	bzero(&http_header_data, 2000);

	char digest_http_header_key[] = "Proxy-Authenticate";
	struct digest_parameters digest_param;
	bzero(&digest_param, sizeof(struct digest_parameters));
	char *pos = NULL;

	char ntlm_http_header_key[] = "Proxy-Authenticate:";
	char *ntlm = NULL;
	char *ntlm_b64 = NULL;
	char *ntlm_challenge_message = NULL;
	struct negotiate_message *negotiate_message = NULL;
	struct challenge_message *challenge_message = NULL;
	struct authenticate_message *authenticate_message = NULL;
	int ntlm_negotiate_message_length = 0;
	int ntlm_challenge_message_length = 0;
	int ntlm_authenticate_message_length = 0;

	char spnego_http_header_key[] = "Proxy-Authenticate:";
	char *b64_kerberos_token = NULL;

	char *target_domainname = socks5_target_ip;
	u_short target_domainname_length = 0;
	if(target_domainname != NULL){
		target_domainname_length = strlen(target_domainname);
	}
	char *target_port_number = socks5_target_port;

	int family = 0;
	char *colon = NULL;

	int ret = 0;
	int err = 0;
	
	SSL_CTX *target_ctx_http = NULL;
	SSL *target_ssl_http = NULL;
	SSL_CTX *target_ctx_socks5 = NULL;
	SSL *target_ssl_socks5 = NULL;

	struct ssl_param ssl_param;
	ssl_param.target_ctx_http = NULL;
	ssl_param.target_ssl_http = NULL;
	ssl_param.target_ctx_socks5 = NULL;
	ssl_param.target_ssl_socks5 = NULL;

	char buffer[BUFFER_SIZE+1];
	bzero(&buffer, BUFFER_SIZE+1);
	int rec, sen;
	int count = 0;
	int check = 0;
	
	char http_request[BUFFER_SIZE+1];
	int http_request_length = 0;
	bzero(http_request, BUFFER_SIZE+1);
	
	EVP_ENCODE_CTX *base64_encode_ctx = NULL;
	int length = 0;
	unsigned char aes_key[33];
	bzero(&aes_key, 33);
	ret = RAND_bytes((unsigned char *)aes_key, 32);
	if(ret != 1){
#ifdef _DEBUG
		printf("[E] aes key generate error:%s.\n", ERR_error_string(ERR_peek_last_error(), NULL));
#endif
		close_socket(client_sock);
		return -1;
	}
	unsigned char aes_key_b64[45];
	bzero(&aes_key_b64, 45);
	base64_encode_ctx = EVP_ENCODE_CTX_new();
	EVP_EncodeInit(base64_encode_ctx);
	EVP_EncodeUpdate(base64_encode_ctx, (unsigned char *)aes_key_b64, &length, (unsigned char *)aes_key, 32);
	EVP_EncodeFinal(base64_encode_ctx, (unsigned char *)aes_key_b64, &length);
	EVP_ENCODE_CTX_free(base64_encode_ctx);
	aes_key_b64[44] = 0x0;	// delete newline character
#ifdef _DEBUG
	printf("[I] aes key (base64):%s\n", aes_key_b64);
#endif
	
	unsigned char aes_iv[17];
	bzero(&aes_iv, 17);
	ret = RAND_bytes((unsigned char *)aes_iv, 16);
	if(ret != 1){
#ifdef _DEBUG
		printf("[E] aes iv generate error:%s.\n", ERR_error_string(ERR_peek_last_error(), NULL));
#endif
		close_socket(client_sock);
		return -1;
	}
	unsigned char aes_iv_b64[25];
	bzero(&aes_iv_b64, 25);
	base64_encode_ctx = EVP_ENCODE_CTX_new();
	EVP_EncodeInit(base64_encode_ctx);
	EVP_EncodeUpdate(base64_encode_ctx, (unsigned char *)aes_iv_b64, &length, (unsigned char *)aes_iv, 16);
	EVP_EncodeFinal(base64_encode_ctx, (unsigned char *)aes_iv_b64, &length);
	EVP_ENCODE_CTX_free(base64_encode_ctx);
	aes_iv_b64[24] = 0x0;	// delete newline character
#ifdef _DEBUG
	printf("[I] aes iv  (base64):%s\n", aes_iv_b64);
#endif
	
	
	if(forward_proxy_flag == 1){	// http forward proxy
		bzero(&forward_proxy_addr, sizeof(struct sockaddr_in));
		bzero(&forward_proxy_addr6, sizeof(struct sockaddr_in6));
		bzero(&hints, sizeof(struct addrinfo));

#ifdef _DEBUG
		printf("[I] Forward proxy domainname:%s, Length:%d.\n", forward_proxy_domainname, forward_proxy_domainname_length);
#endif
		colon = strstr(forward_proxy_domainname, ":");	// check ipv6 address
		if(colon == NULL){	// ipv4 address or domainname
			hints.ai_family = AF_INET;	// IPv4
			if(getaddrinfo(forward_proxy_domainname, forward_proxy_port_number, &hints, &forward_proxy_host) != 0){
				hints.ai_family = AF_INET6;	// IPv6
				if(getaddrinfo(forward_proxy_domainname, forward_proxy_port_number, &hints, &forward_proxy_host) != 0){
#ifdef _DEBUG
					printf("[E] Cannot resolv the domain name:%s.\n", forward_proxy_domainname);
#endif
					close_socket(client_sock);
					return -1;
				}
			}
		}else{	// ipv6 address
			hints.ai_family = AF_INET6;	// IPv6
			if(getaddrinfo(forward_proxy_domainname, forward_proxy_port_number, &hints, &forward_proxy_host) != 0){
#ifdef _DEBUG
				printf("[E] Cannot resolv the domain name:%s.\n", forward_proxy_domainname);
#endif
				close_socket(client_sock);
				return -1;
			}
		}

		if(forward_proxy_host->ai_family == AF_INET){
			family = AF_INET;
			forward_proxy_addr.sin_family = AF_INET;
			tmp_ipv4 = (struct sockaddr_in *)forward_proxy_host->ai_addr;
			memcpy(&forward_proxy_addr.sin_addr, &tmp_ipv4->sin_addr, sizeof(unsigned long));
			memcpy(&forward_proxy_addr.sin_port, &tmp_ipv4->sin_port, 2);
			freeaddrinfo(forward_proxy_host);
		}else if(forward_proxy_host->ai_family == AF_INET6){
			family = AF_INET6;
			forward_proxy_addr6.sin6_family = AF_INET6;
			tmp_ipv6 = (struct sockaddr_in6 *)forward_proxy_host->ai_addr;
			memcpy(&forward_proxy_addr6.sin6_addr, &tmp_ipv6->sin6_addr, sizeof(struct in6_addr));
			memcpy(&forward_proxy_addr6.sin6_port, &tmp_ipv6->sin6_port, 2);;
			freeaddrinfo(forward_proxy_host);
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented.\n");
#endif
			freeaddrinfo(forward_proxy_host);
			close_socket(client_sock);
			return -1;
		}

		if(family == AF_INET){	// IPv4
			forward_proxy_sock = socket(AF_INET, SOCK_STREAM, 0);

			enable_blocking_socket(forward_proxy_sock);	// blocking

			if(err = connect(forward_proxy_sock, (struct sockaddr *)&forward_proxy_addr, sizeof(forward_proxy_addr)) < 0){
#ifdef _DEBUG
				printf("[E] Connect failed. errno:%d\n", err);
#endif
				close_socket(forward_proxy_sock);
				close_socket(client_sock);
				return -1;
			}
		}else if(family == AF_INET6){	// IPv6
			forward_proxy_sock = socket(AF_INET6, SOCK_STREAM, 0);

			enable_blocking_socket(forward_proxy_sock);	// blocking

			if(err = connect(forward_proxy_sock, (struct sockaddr *)&forward_proxy_addr6, sizeof(forward_proxy_addr6)) < 0){
#ifdef _DEBUG
				printf("[E] Connect failed. errno:%d\n", err);
#endif
				close_socket(forward_proxy_sock);
				close_socket(client_sock);
				return -1;
			}
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented.\n");
#endif
			close_socket(client_sock);
			return -1;
		}
#ifdef _DEBUG
		printf("[I] Connected to forward proxy server.\n");
#endif


		if(forward_proxy_authentication_flag == 1){	// forward proxy authentication: basic
			if(strlen(forward_proxy_username) > 256 || strlen(forward_proxy_password) > 256){
#ifdef _DEBUG
				printf("[E] Forward proxy username or password length is too long (length > 256).\n");
#endif
				close_socket(forward_proxy_sock);
				close_socket(client_sock);
				return -1;
			}

			proxy_credential_length = snprintf(proxy_credential, 1000, "%s:%s", forward_proxy_username, forward_proxy_password);
			length = 0;

			length = encode_base64(proxy_credential, proxy_credential_length, proxy_b64_credential, 2000);
#ifdef _DEBUG
			printf("[I] Forward proxy credential (base64):%s\n", proxy_b64_credential);
#endif
		}else if(forward_proxy_authentication_flag == 2){	// forward proxy authentication: digest
			if(strlen(forward_proxy_username) > 256 || strlen(forward_proxy_password) > 256){
#ifdef _DEBUG
				printf("[E] Forward proxy username or password length is too long (length > 256).\n");
#endif
				close_socket(forward_proxy_sock);
				close_socket(client_sock);
				return -1;
			}

			memcpy(&(digest_param.username), forward_proxy_username, strlen(forward_proxy_username));
			memcpy(&(digest_param.password), forward_proxy_password, strlen(forward_proxy_password));
			memcpy(&(digest_param.nc), "00000001", strlen("00000001"));
			memcpy(&(digest_param.method), "CONNECT", strlen("CONNECT"));
			length = snprintf(digest_param.uri, 500, "%s:%s", target_domainname, target_port_number);
		}else if(forward_proxy_authentication_flag == 3){	// forward proxy authentication: ntlmv2
			if(strlen(forward_proxy_username) > 256 || strlen(forward_proxy_password) > 256){
#ifdef _DEBUG
				printf("[E] Forward proxy username or password length is too long (length > 256).\n");
#endif
				close_socket(forward_proxy_sock);
				close_socket(client_sock);
				return -1;
			}
		}else if(forward_proxy_authentication_flag == 4){	// forward proxy authentication: spnego(kerberos)
			if(strlen(forward_proxy_spn) > 260){
#ifdef _DEBUG
				printf("[E] Forward proxy spn length is too long (length > 260).\n");
#endif
				close_socket(forward_proxy_sock);
				close_socket(client_sock);
				return -1;
			}
		}


		bzero(http_request, BUFFER_SIZE+1);
		if(https_flag == 0){	// http (target socks5 server)
			if(forward_proxy_authentication_flag == 0){	// forward proxy authentication: no
//				http_request_length = snprintf(http_request, BUFFER_SIZE+1, "GET http://%s:%s/ HTTP/1.1\r\nHost: %s:%s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\nAccept: */*\r\nProxy-Connection: Keep-Alive\r\n\r\n", target_domainname, target_port_number, target_domainname, target_port_number);

				http_request_length = snprintf(http_request, BUFFER_SIZE+1, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\nAccept: */*\r\nProxy-Connection: Keep-Alive\r\n\r\n", target_domainname, target_port_number, target_domainname, target_port_number);

				// HTTP Request
				sen = send_data(forward_proxy_sock, http_request, http_request_length, tv_sec, tv_usec);
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send http request to forward proxy.\n");
#endif
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Send http request to forward proxy.\n");
#endif

				// HTTP Response
				rec = recv_data(forward_proxy_sock, buffer, BUFFER_SIZE, tv_sec, tv_usec);
				if(rec <= 0){
#ifdef _DEBUG
					printf("[E] Recv http response from forward proxy.\n");
#endif
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Recv http response from forward proxy.\n");
#endif

				ret = strncmp(buffer, "HTTP/1.1 200 Connection established\r\n", strlen("HTTP/1.1 200 Connection established\r\n"));
				if(ret != 0){
#ifdef _DEBUG
					printf("[E] Forward proxy error:\n%s\n", buffer);
#endif
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
			}else if(forward_proxy_authentication_flag == 1){	// forward proxy authentication: basic
//				http_request_length = snprintf(http_request, BUFFER_SIZE+1, "GET http://%s:%s/ HTTP/1.1\r\nHost: %s:%s\r\nProxy-Authorization: Basic %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\nAccept: */*\r\nProxy-Connection: Keep-Alive\r\n\r\n", target_domainname, target_port_number, target_domainname, target_port_number, proxy_b64_credential);

				http_request_length = snprintf(http_request, BUFFER_SIZE+1, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\nProxy-Authorization: Basic %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\nAccept: */*\r\nProxy-Connection: Keep-Alive\r\n\r\n", target_domainname, target_port_number, target_domainname, target_port_number, proxy_b64_credential);

				// HTTP Request
				sen = send_data(forward_proxy_sock, http_request, http_request_length, tv_sec, tv_usec);
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send http request to forward proxy.\n");
#endif
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Send http request to forward proxy.\n");
#endif

				// HTTP Response
				rec = recv_data(forward_proxy_sock, buffer, BUFFER_SIZE, tv_sec, tv_usec);
				if(rec <= 0){
#ifdef _DEBUG
					printf("[E] Recv http response from forward proxy.\n");
#endif
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Recv http response from forward proxy.\n");
#endif

				ret = strncmp(buffer, "HTTP/1.1 200 Connection established\r\n", strlen("HTTP/1.1 200 Connection established\r\n"));
				if(ret != 0){
#ifdef _DEBUG
					printf("[E] Forward proxy error:\n%s\n", buffer);
#endif
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
			}else if(forward_proxy_authentication_flag == 2){	// forward proxy authentication: digest
				http_request_length = snprintf(http_request, BUFFER_SIZE+1, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\nProxy-Connection: Keep-Alive\r\n\r\n", target_domainname, target_port_number, target_domainname, target_port_number);

				// HTTP Request
				sen = send_data(forward_proxy_sock, http_request, http_request_length, tv_sec, tv_usec);
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send http request to forward proxy.\n");
#endif
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Send http request to forward proxy.\n");
#endif

				// HTTP Response (HTTP/1.1 407 Proxy Authentication Required)
				rec = recv_data(forward_proxy_sock, buffer, BUFFER_SIZE, tv_sec, tv_usec);
				if(rec <= 0){
#ifdef _DEBUG
					printf("[E] Recv http response from forward proxy.\n");
#endif
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Recv http response from forward proxy.\n");
#endif

				ret = strncmp(buffer, "HTTP/1.1 407 Proxy Authentication Required\r\n", strlen("HTTP/1.1 407 Proxy Authentication Required\r\n"));
				if(ret != 0){
#ifdef _DEBUG
					printf("[E] Forward proxy error:\n%s\n", buffer);
#endif
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}

				ret = get_http_header((const char *)&buffer, (const char *)&digest_http_header_key, (char *)&http_header_data, 2000);
				if(ret == -1){
#ifdef _DEBUG
					printf("[E] get_http_header error\n");
#endif
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] http_header_data:%s\n", http_header_data);
#endif

				if(!strncmp(digest_param.qop, "auth-int", strlen("auth-int"))){
					pos = strstr((const char *)&buffer, "\r\n\r\n");
					length = snprintf(digest_param.entity_body, BUFFER_SIZE+1, "%s", pos+4);
				}

				ret = get_digest_values((const char *)&http_header_data, &digest_param);
				if(ret == -1){
#ifdef _DEBUG
					printf("[E] get_digest_values error\n");
#endif
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}

				ret = get_digest_response(&digest_param);
				if(ret == -1){
#ifdef _DEBUG
					printf("[E] get_digest_response error\n");
#endif
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}

				bzero(http_request, BUFFER_SIZE+1);
				http_request_length = snprintf(http_request, BUFFER_SIZE+1, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\nProxy-Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", cnonce=\"%s\", nc=%s, qop=%s, response=\"%s\"\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\nProxy-Connection: Keep-Alive\r\n\r\n", target_domainname, target_port_number, target_domainname, target_port_number, digest_param.username, digest_param.realm, digest_param.nonce, digest_param.uri, digest_param.cnonce, digest_param.nc, digest_param.qop, digest_param.response_hash);

				// HTTP Request
				sen = send_data(forward_proxy_sock, http_request, http_request_length, tv_sec, tv_usec);
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send http request to forward proxy.\n");
#endif
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Send http request to forward proxy.\n");
#endif

				// HTTP Response (HTTP/1.1 200 Connection established)
				rec = recv_data(forward_proxy_sock, buffer, BUFFER_SIZE, tv_sec, tv_usec);
				if(rec <= 0){
#ifdef _DEBUG
					printf("[E] Recv http response from forward proxy.\n");
#endif
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Recv http response from forward proxy.\n");
#endif

				ret = strncmp(buffer, "HTTP/1.1 200 Connection established\r\n", strlen("HTTP/1.1 200 Connection established\r\n"));
				if(ret != 0){
#ifdef _DEBUG
					printf("[E] Forward proxy error:\n%s\n", buffer);
#endif
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
			}else if(forward_proxy_authentication_flag == 3){	// forward proxy authentication: ntlmv2
				ntlm = calloc(2000, sizeof(char));
				ntlm_b64 = calloc(3000, sizeof(char));
				ntlm_challenge_message = calloc(2000, sizeof(char));

				// negotiate_message
				negotiate_message = (struct negotiate_message *)ntlm;
				ntlm_negotiate_message_length = 0;

				memcpy(&(negotiate_message->signature), "NTLMSSP\0", 8);
				ntlm_negotiate_message_length += 8;

				negotiate_message->message_type = NtLmNegotiate;
				ntlm_negotiate_message_length += 4;

				negotiate_message->negotiate_flags.negotiate_unicode                  = 0;
				negotiate_message->negotiate_flags.negotiate_oem                      = 1;
				negotiate_message->negotiate_flags.request_target                     = 1;
				negotiate_message->negotiate_flags.request_0x00000008                 = 0;
				negotiate_message->negotiate_flags.negotiate_sign                     = 0;
				negotiate_message->negotiate_flags.negotiate_seal                     = 0;
				negotiate_message->negotiate_flags.negotiate_datagram                 = 0;
				negotiate_message->negotiate_flags.negotiate_lan_manager_key          = 0;
				negotiate_message->negotiate_flags.negotiate_0x00000100               = 0;
				negotiate_message->negotiate_flags.negotiate_ntlm_key                 = 1;
				negotiate_message->negotiate_flags.negotiate_nt_only                  = 0;
				negotiate_message->negotiate_flags.negotiate_anonymous                = 0;
				negotiate_message->negotiate_flags.negotiate_oem_domain_supplied      = 0;
				negotiate_message->negotiate_flags.negotiate_oem_workstation_supplied = 0;
				negotiate_message->negotiate_flags.negotiate_0x00004000               = 0;
				negotiate_message->negotiate_flags.negotiate_always_sign              = 1;
				negotiate_message->negotiate_flags.target_type_domain                 = 0;
				negotiate_message->negotiate_flags.target_type_server                 = 0;
				negotiate_message->negotiate_flags.target_type_share                  = 0;
				negotiate_message->negotiate_flags.negotiate_extended_security        = 1;
				negotiate_message->negotiate_flags.negotiate_identify                 = 0;
				negotiate_message->negotiate_flags.negotiate_0x00200000               = 0;
				negotiate_message->negotiate_flags.request_non_nt_session             = 0;
				negotiate_message->negotiate_flags.negotiate_target_info              = 0;
				negotiate_message->negotiate_flags.negotiate_0x01000000               = 0;
				negotiate_message->negotiate_flags.negotiate_version                  = 0;
				negotiate_message->negotiate_flags.negotiate_0x04000000               = 0;
				negotiate_message->negotiate_flags.negotiate_0x08000000               = 0;
				negotiate_message->negotiate_flags.negotiate_0x10000000               = 0;
				negotiate_message->negotiate_flags.negotiate_128                      = 0;
				negotiate_message->negotiate_flags.negotiate_key_exchange             = 0;
				negotiate_message->negotiate_flags.negotiate_56                       = 0;
				ntlm_negotiate_message_length += 4;

				negotiate_message->domain_name_fields.domain_name_len = 0;
				negotiate_message->domain_name_fields.domain_name_max_len = 0;
				negotiate_message->domain_name_fields.domain_name_buffer_offset = 0;
				ntlm_negotiate_message_length += 8;

				negotiate_message->workstation_fields.workstation_len = 0;
				negotiate_message->workstation_fields.workstation_max_len = 0;
				negotiate_message->workstation_fields.workstation_buffer_offset = 0;
				ntlm_negotiate_message_length += 8;

				ret = encode_base64((const unsigned char *)negotiate_message, ntlm_negotiate_message_length, (unsigned char *)ntlm_b64, 3000);
				if(ret == -1){
#ifdef _DEBUG
					printf("[E] encode_base64 error\n");
#endif
					free(ntlm);
					free(ntlm_b64);
					free(ntlm_challenge_message);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}

#ifdef _DEBUG
				printf("[I] negotiate_message ntlm_b64:%s ntlm_negotiate_message_length:%d\n", ntlm_b64, ntlm_negotiate_message_length);
#endif

				http_request_length = snprintf(http_request, BUFFER_SIZE+1, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\nProxy-Authorization: NTLM %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\nProxy-Connection: Keep-Alive\r\n\r\n", target_domainname, target_port_number, target_domainname, target_port_number, ntlm_b64);

				// HTTP Request
				sen = send_data(forward_proxy_sock, http_request, http_request_length, tv_sec, tv_usec);
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send http request to forward proxy.\n");
#endif
					free(ntlm);
					free(ntlm_b64);
					free(ntlm_challenge_message);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Send http request to forward proxy.\n");
#endif

				// HTTP Response (HTTP/1.1 407 Proxy Authentication Required)
				rec = recv_data(forward_proxy_sock, buffer, BUFFER_SIZE, tv_sec, tv_usec);
				if(rec <= 0){
#ifdef _DEBUG
					printf("[E] Recv http response from forward proxy.\n");
#endif
					free(ntlm);
					free(ntlm_b64);
					free(ntlm_challenge_message);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Recv http response from forward proxy.\n");
#endif

				// challenge message
				ret = get_http_header((const char *)&buffer, (const char *)&ntlm_http_header_key, (char *)&http_header_data, 2000);
				if(ret == -1){
#ifdef _DEBUG
					printf("[E] get_http_header error\n");
#endif
					free(ntlm);
					free(ntlm_b64);
					free(ntlm_challenge_message);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] http_header_data:%s\n", http_header_data);
#endif

				pos = strstr((const char *)&http_header_data, "Proxy-Authenticate: NTLM ");
				if(pos == NULL){
#ifdef _DEBUG
					printf("[E] Cannot find Proxy-Authenticate: NTLM in http header.\n");
#endif
					free(ntlm);
					free(ntlm_b64);
					free(ntlm_challenge_message);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}

				pos += strlen("Proxy-Authenticate: NTLM ");
				length = strlen(pos);
				ntlm_challenge_message_length = decode_base64((const char *)pos, length, ntlm_challenge_message, 2000);
				if(ntlm_challenge_message_length == -1){
#ifdef _DEBUG
					printf("[E] decode_base64 error\n");
#endif
					free(ntlm);
					free(ntlm_b64);
					free(ntlm_challenge_message);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}

				challenge_message = (struct challenge_message *)ntlm_challenge_message;

				if(challenge_message->message_type != NtLmChallenge){
#ifdef _DEBUG
					printf("[E] ntlm challenge message message_type error:%04x\n", challenge_message->message_type);
#endif
					free(ntlm);
					free(ntlm_b64);
					free(ntlm_challenge_message);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}

				// authenticate_message
				bzero(ntlm, 2000);
				bzero(ntlm_b64, 3000);
				authenticate_message = (struct authenticate_message *)ntlm;
				ntlm_authenticate_message_length = 0;

				ret = generate_response_ntlmv2(challenge_message, authenticate_message);
				if(ret == -1){
#ifdef _DEBUG
					printf("[E] generate_response_ntlmv2 error\n");
#endif
					free(ntlm);
					free(ntlm_b64);
					free(ntlm_challenge_message);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
				ntlm_authenticate_message_length = ret;

				ret = encode_base64((const unsigned char *)authenticate_message, ntlm_authenticate_message_length, (unsigned char *)ntlm_b64, 3000);
				if(ret == -1){
#ifdef _DEBUG
					printf("[E] encode_base64 error\n");
#endif
					free(ntlm);
					free(ntlm_b64);
					free(ntlm_challenge_message);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}

#ifdef _DEBUG
				printf("[I] authenticate_message ntlm_b64:%s\n", ntlm_b64);
#endif

				http_request_length = snprintf(http_request, BUFFER_SIZE+1, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\nProxy-Authorization: NTLM %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\nProxy-Connection: Keep-Alive\r\n\r\n", target_domainname, target_port_number, target_domainname, target_port_number, ntlm_b64);

				// HTTP Request
				sen = send_data(forward_proxy_sock, http_request, http_request_length, tv_sec, tv_usec);
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send http request to forward proxy.\n");
#endif
					free(ntlm);
					free(ntlm_b64);
					free(ntlm_challenge_message);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Send http request to forward proxy.\n");
#endif

				// HTTP Response (HTTP/1.1 200 Connection established)
				rec = recv_data(forward_proxy_sock, buffer, BUFFER_SIZE, tv_sec, tv_usec);
				if(rec <= 0){
#ifdef _DEBUG
					printf("[E] Recv http response from forward proxy.\n");
#endif
					free(ntlm);
					free(ntlm_b64);
					free(ntlm_challenge_message);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Recv http response from forward proxy.\n");
#endif

				ret = strncmp(buffer, "HTTP/1.1 200 Connection established\r\n", strlen("HTTP/1.1 200 Connection established\r\n"));
				if(ret != 0){
#ifdef _DEBUG
					printf("[E] Forward proxy error:\n%s\n", buffer);
#endif
					free(ntlm);
					free(ntlm_b64);
					free(ntlm_challenge_message);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}

				free(ntlm);
				free(ntlm_b64);
				free(ntlm_challenge_message);
			}else if(forward_proxy_authentication_flag == 4){	// forward proxy authentication: spnego(kerberos)
				b64_kerberos_token = calloc(4000, sizeof(char));

				ret = get_base64_kerberos_token(forward_proxy_spn, b64_kerberos_token, 4000);
				if(ret == -1){
#ifdef _DEBUG
					printf("[E] get_base64_kerberos_token error\n");
#endif
					free(b64_kerberos_token);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] b64_kerberos_token:%s\n", b64_kerberos_token);
#endif

				http_request_length = snprintf(http_request, BUFFER_SIZE+1, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\nProxy-Connection: Keep-Alive\r\n\r\n", target_domainname, target_port_number, target_domainname, target_port_number);

				// HTTP Request
				sen = send_data(forward_proxy_sock, http_request, http_request_length, tv_sec, tv_usec);
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send http request to forward proxy.\n");
#endif
					free(b64_kerberos_token);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Send http request to forward proxy.\n");
#endif

				// HTTP Response (HTTP/1.1 407 Proxy Authentication Required)
				bzero(&buffer, BUFFER_SIZE+1);
				rec = recv_data(forward_proxy_sock, buffer, BUFFER_SIZE, tv_sec, tv_usec);
				if(rec <= 0){
#ifdef _DEBUG
					printf("[E] Recv http response from forward proxy.\n");
#endif
					free(b64_kerberos_token);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Recv http response from forward proxy.\n");
#endif

				ret = strncmp(buffer, "HTTP/1.1 407 Proxy Authentication Required\r\n", strlen("HTTP/1.1 407 Proxy Authentication Required\r\n"));
				if(ret != 0){
#ifdef _DEBUG
					printf("[E] Forward proxy error:\n%s\n", buffer);
#endif
					free(b64_kerberos_token);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}

				bzero(&http_header_data, 2000);
				ret = get_http_header((const char *)&buffer, (const char *)&spnego_http_header_key, (char *)&http_header_data, 2000);
				if(ret == -1){
#ifdef _DEBUG
					printf("[E] get_http_header error\n");
#endif
					free(b64_kerberos_token);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] http_header_data:%s\n", http_header_data);
#endif

				pos = strstr((const char *)&http_header_data, "Proxy-Authenticate: Negotiate");
				if(pos == NULL){
#ifdef _DEBUG
					printf("[E] Cannot find Proxy-Authenticate: Negotiate in http header.\n");
#endif
					free(b64_kerberos_token);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}

				bzero(http_request, BUFFER_SIZE+1);
				http_request_length = snprintf(http_request, BUFFER_SIZE+1, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\nProxy-Authorization: Negotiate %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\nProxy-Connection: Keep-Alive\r\n\r\n", target_domainname, target_port_number, target_domainname, target_port_number, b64_kerberos_token);

				// HTTP Request
				sen = send_data(forward_proxy_sock, http_request, http_request_length, tv_sec, tv_usec);
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send http request to forward proxy.\n");
#endif
					free(b64_kerberos_token);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Send http request to forward proxy.\n");
#endif

				// HTTP Response (HTTP/1.1 200 Connection established)
				bzero(&buffer, BUFFER_SIZE+1);
				rec = recv_data(forward_proxy_sock, buffer, BUFFER_SIZE, tv_sec, tv_usec);
				if(rec <= 0){
#ifdef _DEBUG
					printf("[E] Recv http response from forward proxy.\n");
#endif
					free(b64_kerberos_token);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Recv http response from forward proxy.\n");
#endif

				ret = strncmp(buffer, "HTTP/1.1 200 Connection established\r\n", strlen("HTTP/1.1 200 Connection established\r\n"));
				if(ret != 0){
#ifdef _DEBUG
					printf("[E] Forward proxy error:\n%s\n", buffer);
#endif
					free(b64_kerberos_token);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}

				free(b64_kerberos_token);
			}else{
#ifdef _DEBUG
				printf("[E] Not implemented.\n");
#endif
				close_socket(forward_proxy_sock);
				close_socket(client_sock);
				return -1;
			}
		}else{	// https (target socks5 server)
			if(forward_proxy_authentication_flag == 0){	// forward proxy authentication: no
				http_request_length = snprintf(http_request, BUFFER_SIZE+1, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\nAccept: */*\r\nProxy-Connection: Keep-Alive\r\n\r\n", target_domainname, target_port_number, target_domainname, target_port_number);

				// HTTP Request
				sen = send_data(forward_proxy_sock, http_request, http_request_length, tv_sec, tv_usec);
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send http request to forward proxy.\n");
#endif
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Send http request to forward proxy.\n");
#endif

				// HTTP Response
				rec = recv_data(forward_proxy_sock, buffer, BUFFER_SIZE, tv_sec, tv_usec);
				if(rec <= 0){
#ifdef _DEBUG
					printf("[E] Recv http response from forward proxy.\n");
#endif
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Recv http response from forward proxy.\n");
#endif

				ret = strncmp(buffer, "HTTP/1.1 200 Connection established\r\n", strlen("HTTP/1.1 200 Connection established\r\n"));
				if(ret != 0){
#ifdef _DEBUG
					printf("[E] Forward proxy error:\n%s\n", buffer);
#endif
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
			}else if(forward_proxy_authentication_flag == 1){	// forward proxy authentication: basic
				http_request_length = snprintf(http_request, BUFFER_SIZE+1, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\nProxy-Authorization: Basic %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\nAccept: */*\r\nProxy-Connection: Keep-Alive\r\n\r\n", target_domainname, target_port_number, target_domainname, target_port_number, proxy_b64_credential);

				// HTTP Request
				sen = send_data(forward_proxy_sock, http_request, http_request_length, tv_sec, tv_usec);
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send http request to forward proxy.\n");
#endif
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Send http request to forward proxy.\n");
#endif

				// HTTP Response
				rec = recv_data(forward_proxy_sock, buffer, BUFFER_SIZE, tv_sec, tv_usec);
				if(rec <= 0){
#ifdef _DEBUG
					printf("[E] Recv http response from forward proxy.\n");
#endif
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Recv http response from forward proxy.\n");
#endif

				ret = strncmp(buffer, "HTTP/1.1 200 Connection established\r\n", strlen("HTTP/1.1 200 Connection established\r\n"));
				if(ret != 0){
#ifdef _DEBUG
					printf("[E] Forward proxy error:\n%s\n", buffer);
#endif
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
			}else if(forward_proxy_authentication_flag == 2){	// forward proxy authentication: digest
				http_request_length = snprintf(http_request, BUFFER_SIZE+1, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\nProxy-Connection: Keep-Alive\r\n\r\n", target_domainname, target_port_number, target_domainname, target_port_number);

				// HTTP Request
				sen = send_data(forward_proxy_sock, http_request, http_request_length, tv_sec, tv_usec);
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send http request to forward proxy.\n");
#endif
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Send http request to forward proxy.\n");
#endif

				// HTTP Response (HTTP/1.1 407 Proxy Authentication Required)
				rec = recv_data(forward_proxy_sock, buffer, BUFFER_SIZE, tv_sec, tv_usec);
				if(rec <= 0){
#ifdef _DEBUG
					printf("[E] Recv http response from forward proxy.\n");
#endif
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Recv http response from forward proxy.\n");
#endif

				ret = strncmp(buffer, "HTTP/1.1 407 Proxy Authentication Required\r\n", strlen("HTTP/1.1 407 Proxy Authentication Required\r\n"));
				if(ret != 0){
#ifdef _DEBUG
					printf("[E] Forward proxy error:\n%s\n", buffer);
#endif
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}

				ret = get_http_header((const char *)&buffer, (const char *)&digest_http_header_key, (char *)&http_header_data, 2000);
				if(ret == -1){
#ifdef _DEBUG
					printf("[E] get_http_header error\n");
#endif
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] http_header_data:%s\n", http_header_data);
#endif

				ret = get_digest_values((const char *)&http_header_data, &digest_param);
				if(ret == -1){
#ifdef _DEBUG
					printf("[E] get_digest_values error\n");
#endif
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}

				ret = get_digest_response(&digest_param);
				if(ret == -1){
#ifdef _DEBUG
					printf("[E] get_digest_response error\n");
#endif
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}

				bzero(http_request, BUFFER_SIZE+1);
				http_request_length = snprintf(http_request, BUFFER_SIZE+1, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\nProxy-Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", cnonce=\"%s\", nc=%s, qop=%s, response=\"%s\"\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\nProxy-Connection: Keep-Alive\r\n\r\n", target_domainname, target_port_number, target_domainname, target_port_number, digest_param.username, digest_param.realm, digest_param.nonce, digest_param.uri, digest_param.cnonce, digest_param.nc, digest_param.qop, digest_param.response_hash);

				// HTTP Request
				sen = send_data(forward_proxy_sock, http_request, http_request_length, tv_sec, tv_usec);
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send http request to forward proxy.\n");
#endif
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Send http request to forward proxy.\n");
#endif

				// HTTP Response (HTTP/1.1 200 Connection established)
				rec = recv_data(forward_proxy_sock, buffer, BUFFER_SIZE, tv_sec, tv_usec);
				if(rec <= 0){
#ifdef _DEBUG
					printf("[E] Recv http response from forward proxy.\n");
#endif
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Recv http response from forward proxy.\n");
#endif

				ret = strncmp(buffer, "HTTP/1.1 200 Connection established\r\n", strlen("HTTP/1.1 200 Connection established\r\n"));
				if(ret != 0){
#ifdef _DEBUG
					printf("[E] Forward proxy error:\n%s\n", buffer);
#endif
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
			}else if(forward_proxy_authentication_flag == 3){	// forward proxy authentication: ntlmv2
				ntlm = calloc(2000, sizeof(char));
				ntlm_b64 = calloc(3000, sizeof(char));
				ntlm_challenge_message = calloc(2000, sizeof(char));

				// negotiate_message
				negotiate_message = (struct negotiate_message *)ntlm;
				ntlm_negotiate_message_length = 0;

				memcpy(&(negotiate_message->signature), "NTLMSSP\0", 8);
				ntlm_negotiate_message_length += 8;

				negotiate_message->message_type = NtLmNegotiate;
				ntlm_negotiate_message_length += 4;

				negotiate_message->negotiate_flags.negotiate_unicode                  = 0;
				negotiate_message->negotiate_flags.negotiate_oem                      = 1;
				negotiate_message->negotiate_flags.request_target                     = 1;
				negotiate_message->negotiate_flags.request_0x00000008                 = 0;
				negotiate_message->negotiate_flags.negotiate_sign                     = 0;
				negotiate_message->negotiate_flags.negotiate_seal                     = 0;
				negotiate_message->negotiate_flags.negotiate_datagram                 = 0;
				negotiate_message->negotiate_flags.negotiate_lan_manager_key          = 0;
				negotiate_message->negotiate_flags.negotiate_0x00000100               = 0;
				negotiate_message->negotiate_flags.negotiate_ntlm_key                 = 1;
				negotiate_message->negotiate_flags.negotiate_nt_only                  = 0;
				negotiate_message->negotiate_flags.negotiate_anonymous                = 0;
				negotiate_message->negotiate_flags.negotiate_oem_domain_supplied      = 0;
				negotiate_message->negotiate_flags.negotiate_oem_workstation_supplied = 0;
				negotiate_message->negotiate_flags.negotiate_0x00004000               = 0;
				negotiate_message->negotiate_flags.negotiate_always_sign              = 1;
				negotiate_message->negotiate_flags.target_type_domain                 = 0;
				negotiate_message->negotiate_flags.target_type_server                 = 0;
				negotiate_message->negotiate_flags.target_type_share                  = 0;
				negotiate_message->negotiate_flags.negotiate_extended_security        = 1;
				negotiate_message->negotiate_flags.negotiate_identify                 = 0;
				negotiate_message->negotiate_flags.negotiate_0x00200000               = 0;
				negotiate_message->negotiate_flags.request_non_nt_session             = 0;
				negotiate_message->negotiate_flags.negotiate_target_info              = 0;
				negotiate_message->negotiate_flags.negotiate_0x01000000               = 0;
				negotiate_message->negotiate_flags.negotiate_version                  = 0;
				negotiate_message->negotiate_flags.negotiate_0x04000000               = 0;
				negotiate_message->negotiate_flags.negotiate_0x08000000               = 0;
				negotiate_message->negotiate_flags.negotiate_0x10000000               = 0;
				negotiate_message->negotiate_flags.negotiate_128                      = 0;
				negotiate_message->negotiate_flags.negotiate_key_exchange             = 0;
				negotiate_message->negotiate_flags.negotiate_56                       = 0;
				ntlm_negotiate_message_length += 4;

				negotiate_message->domain_name_fields.domain_name_len = 0;
				negotiate_message->domain_name_fields.domain_name_max_len = 0;
				negotiate_message->domain_name_fields.domain_name_buffer_offset = 0;
				ntlm_negotiate_message_length += 8;

				negotiate_message->workstation_fields.workstation_len = 0;
				negotiate_message->workstation_fields.workstation_max_len = 0;
				negotiate_message->workstation_fields.workstation_buffer_offset = 0;
				ntlm_negotiate_message_length += 8;

				ret = encode_base64((const unsigned char *)negotiate_message, ntlm_negotiate_message_length, (unsigned char *)ntlm_b64, 3000);
				if(ret == -1){
#ifdef _DEBUG
					printf("[E] encode_base64 error\n");
#endif
					free(ntlm);
					free(ntlm_b64);
					free(ntlm_challenge_message);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}

#ifdef _DEBUG
				printf("[I] negotiate_message ntlm_b64:%s ntlm_negotiate_message_length:%d\n", ntlm_b64, ntlm_negotiate_message_length);
#endif

				http_request_length = snprintf(http_request, BUFFER_SIZE+1, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\nProxy-Authorization: NTLM %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\nProxy-Connection: Keep-Alive\r\n\r\n", target_domainname, target_port_number, target_domainname, target_port_number, ntlm_b64);

				// HTTP Request
				sen = send_data(forward_proxy_sock, http_request, http_request_length, tv_sec, tv_usec);
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send http request to forward proxy.\n");
#endif
					free(ntlm);
					free(ntlm_b64);
					free(ntlm_challenge_message);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Send http request to forward proxy.\n");
#endif

				// HTTP Response (HTTP/1.1 407 Proxy Authentication Required)
				rec = recv_data(forward_proxy_sock, buffer, BUFFER_SIZE, tv_sec, tv_usec);
				if(rec <= 0){
#ifdef _DEBUG
					printf("[E] Recv http response from forward proxy.\n");
#endif
					free(ntlm);
					free(ntlm_b64);
					free(ntlm_challenge_message);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Recv http response from forward proxy.\n");
#endif

				// challenge message
				ret = get_http_header((const char *)&buffer, (const char *)&ntlm_http_header_key, (char *)&http_header_data, 2000);
				if(ret == -1){
#ifdef _DEBUG
					printf("[E] get_http_header error\n");
#endif
					free(ntlm);
					free(ntlm_b64);
					free(ntlm_challenge_message);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] http_header_data:%s\n", http_header_data);
#endif

				pos = strstr((const char *)&http_header_data, "Proxy-Authenticate: NTLM ");
				if(pos == NULL){
#ifdef _DEBUG
					printf("[E] Cannot find Proxy-Authenticate: NTLM in http header.\n");
#endif
					free(ntlm);
					free(ntlm_b64);
					free(ntlm_challenge_message);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}

				pos += strlen("Proxy-Authenticate: NTLM ");
				length = strlen(pos);
				ntlm_challenge_message_length = decode_base64((const char *)pos, length, ntlm_challenge_message, 2000);
				if(ntlm_challenge_message_length == -1){
#ifdef _DEBUG
					printf("[E] decode_base64 error\n");
#endif
					free(ntlm);
					free(ntlm_b64);
					free(ntlm_challenge_message);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}

				challenge_message = (struct challenge_message *)ntlm_challenge_message;

				if(challenge_message->message_type != NtLmChallenge){
#ifdef _DEBUG
					printf("[E] ntlm challenge message message_type error:%04x\n", challenge_message->message_type);
#endif
					free(ntlm);
					free(ntlm_b64);
					free(ntlm_challenge_message);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}

				// authenticate_message
				bzero(ntlm, 2000);
				bzero(ntlm_b64, 3000);
				authenticate_message = (struct authenticate_message *)ntlm;
				ntlm_authenticate_message_length = 0;

				ret = generate_response_ntlmv2(challenge_message, authenticate_message);
				if(ret == -1){
#ifdef _DEBUG
					printf("[E] generate_response_ntlmv2 error\n");
#endif
					free(ntlm);
					free(ntlm_b64);
					free(ntlm_challenge_message);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
				ntlm_authenticate_message_length = ret;

				ret = encode_base64((const unsigned char *)authenticate_message, ntlm_authenticate_message_length, (unsigned char *)ntlm_b64, 3000);
				if(ret == -1){
#ifdef _DEBUG
					printf("[E] encode_base64 error\n");
#endif
					free(ntlm);
					free(ntlm_b64);
					free(ntlm_challenge_message);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}

#ifdef _DEBUG
				printf("[I] authenticate_message ntlm_b64:%s\n", ntlm_b64);
#endif

				http_request_length = snprintf(http_request, BUFFER_SIZE+1, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\nProxy-Authorization: NTLM %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\nProxy-Connection: Keep-Alive\r\n\r\n", target_domainname, target_port_number, target_domainname, target_port_number, ntlm_b64);

				// HTTP Request
				sen = send_data(forward_proxy_sock, http_request, http_request_length, tv_sec, tv_usec);
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send http request to forward proxy.\n");
#endif
					free(ntlm);
					free(ntlm_b64);
					free(ntlm_challenge_message);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Send http request to forward proxy.\n");
#endif

				// HTTP Response (HTTP/1.1 200 Connection established)
				rec = recv_data(forward_proxy_sock, buffer, BUFFER_SIZE, tv_sec, tv_usec);
				if(rec <= 0){
#ifdef _DEBUG
					printf("[E] Recv http response from forward proxy.\n");
#endif
					free(ntlm);
					free(ntlm_b64);
					free(ntlm_challenge_message);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Recv http response from forward proxy.\n");
#endif

				ret = strncmp(buffer, "HTTP/1.1 200 Connection established\r\n", strlen("HTTP/1.1 200 Connection established\r\n"));
				if(ret != 0){
#ifdef _DEBUG
					printf("[E] Forward proxy error:\n%s\n", buffer);
#endif
					free(ntlm);
					free(ntlm_b64);
					free(ntlm_challenge_message);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}

				free(ntlm);
				free(ntlm_b64);
				free(ntlm_challenge_message);
			}else if(forward_proxy_authentication_flag == 4){	// forward proxy authentication: spnego(kerberos)
				b64_kerberos_token = calloc(4000, sizeof(char));

				ret = get_base64_kerberos_token(forward_proxy_spn, b64_kerberos_token, 4000);
				if(ret == -1){
#ifdef _DEBUG
					printf("[E] get_base64_kerberos_token error\n");
#endif
					free(b64_kerberos_token);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] b64_kerberos_token:%s\n", b64_kerberos_token);
#endif

				http_request_length = snprintf(http_request, BUFFER_SIZE+1, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\nProxy-Connection: Keep-Alive\r\n\r\n", target_domainname, target_port_number, target_domainname, target_port_number);

				// HTTP Request
				sen = send_data(forward_proxy_sock, http_request, http_request_length, tv_sec, tv_usec);
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send http request to forward proxy.\n");
#endif
					free(b64_kerberos_token);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Send http request to forward proxy.\n");
#endif

				// HTTP Response (HTTP/1.1 407 Proxy Authentication Required)
				bzero(&buffer, BUFFER_SIZE+1);
				rec = recv_data(forward_proxy_sock, buffer, BUFFER_SIZE, tv_sec, tv_usec);
				if(rec <= 0){
#ifdef _DEBUG
					printf("[E] Recv http response from forward proxy.\n");
#endif
					free(b64_kerberos_token);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Recv http response from forward proxy.\n");
#endif

				ret = strncmp(buffer, "HTTP/1.1 407 Proxy Authentication Required\r\n", strlen("HTTP/1.1 407 Proxy Authentication Required\r\n"));
				if(ret != 0){
#ifdef _DEBUG
					printf("[E] Forward proxy error:\n%s\n", buffer);
#endif
					free(b64_kerberos_token);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}

				bzero(&http_header_data, 2000);
				ret = get_http_header((const char *)&buffer, (const char *)&spnego_http_header_key, (char *)&http_header_data, 2000);
				if(ret == -1){
#ifdef _DEBUG
					printf("[E] get_http_header error\n");
#endif
					free(b64_kerberos_token);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] http_header_data:%s\n", http_header_data);
#endif

				pos = strstr((const char *)&http_header_data, "Proxy-Authenticate: Negotiate");
				if(pos == NULL){
#ifdef _DEBUG
					printf("[E] Cannot find Proxy-Authenticate: Negotiate in http header.\n");
#endif
					free(b64_kerberos_token);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}

				bzero(http_request, BUFFER_SIZE+1);
				http_request_length = snprintf(http_request, BUFFER_SIZE+1, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\nProxy-Authorization: Negotiate %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\nProxy-Connection: Keep-Alive\r\n\r\n", target_domainname, target_port_number, target_domainname, target_port_number, b64_kerberos_token);

				// HTTP Request
				sen = send_data(forward_proxy_sock, http_request, http_request_length, tv_sec, tv_usec);
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send http request to forward proxy.\n");
#endif
					free(b64_kerberos_token);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Send http request to forward proxy.\n");
#endif

				// HTTP Response (HTTP/1.1 200 Connection established)
				bzero(&buffer, BUFFER_SIZE+1);
				rec = recv_data(forward_proxy_sock, buffer, BUFFER_SIZE, tv_sec, tv_usec);
				if(rec <= 0){
#ifdef _DEBUG
					printf("[E] Recv http response from forward proxy.\n");
#endif
					free(b64_kerberos_token);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Recv http response from forward proxy.\n");
#endif

				ret = strncmp(buffer, "HTTP/1.1 200 Connection established\r\n", strlen("HTTP/1.1 200 Connection established\r\n"));
				if(ret != 0){
#ifdef _DEBUG
					printf("[E] Forward proxy error:\n%s\n", buffer);
#endif
					free(b64_kerberos_token);
					close_socket(forward_proxy_sock);
					close_socket(client_sock);
					return -1;
				}

				free(b64_kerberos_token);
			}else{
#ifdef _DEBUG
				printf("[E] Not implemented.\n");
#endif
				close_socket(forward_proxy_sock);
				close_socket(client_sock);
				return -1;
			}
		}
#ifdef _DEBUG
		printf("[I] Forward proxy connection established.\n");
#endif
	}else{	// no forward proxy
		bzero(&target_addr, sizeof(struct sockaddr_in));
		bzero(&target_addr6, sizeof(struct sockaddr_in6));
		bzero(&hints, sizeof(struct addrinfo));

#ifdef _DEBUG
		printf("[I] Target domainname:%s, Length:%d.\n", target_domainname, target_domainname_length);
#endif
		colon = strstr(target_domainname, ":");	// check ipv6 address
		if(colon == NULL){	// ipv4 address or domainname
			hints.ai_family = AF_INET;	// IPv4
			if(getaddrinfo(target_domainname, target_port_number, &hints, &target_host) != 0){
				hints.ai_family = AF_INET6;	// IPv6
				if(getaddrinfo(target_domainname, target_port_number, &hints, &target_host) != 0){
#ifdef _DEBUG
					printf("[E] Cannot resolv the domain name:%s.\n", target_domainname);
#endif
					close_socket(client_sock);
					return -1;
				}
			}
		}else{	// ipv6 address
			hints.ai_family = AF_INET6;	// IPv6
			if(getaddrinfo(target_domainname, target_port_number, &hints, &target_host) != 0){
#ifdef _DEBUG
				printf("[E] Cannot resolv the domain name:%s.\n", target_domainname);
#endif
				close_socket(client_sock);
				return -1;
			}
		}

		if(target_host->ai_family == AF_INET){
			family = AF_INET;
			target_addr.sin_family = AF_INET;
			tmp_ipv4 = (struct sockaddr_in *)target_host->ai_addr;
			memcpy(&target_addr.sin_addr, &tmp_ipv4->sin_addr, sizeof(unsigned long));
			memcpy(&target_addr.sin_port, &tmp_ipv4->sin_port, 2);
			freeaddrinfo(target_host);
		}else if(target_host->ai_family == AF_INET6){
			family = AF_INET6;
			target_addr6.sin6_family = AF_INET6;
			tmp_ipv6 = (struct sockaddr_in6 *)target_host->ai_addr;
			memcpy(&target_addr6.sin6_addr, &tmp_ipv6->sin6_addr, sizeof(struct in6_addr));
			memcpy(&target_addr6.sin6_port, &tmp_ipv6->sin6_port, 2);;
			freeaddrinfo(target_host);
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented.\n");
#endif
			freeaddrinfo(target_host);
			close_socket(client_sock);
			return -1;
		}

		if(family == AF_INET){	// IPv4
			target_sock = socket(AF_INET, SOCK_STREAM, 0);

			enable_blocking_socket(target_sock);	// blocking

			if(err = connect(target_sock, (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0){
#ifdef _DEBUG
				printf("[E] Connect failed. errno:%d\n", err);
#endif
				close_socket(target_sock);
				close_socket(client_sock);
				return -1;
			}
		}else if(family == AF_INET6){	// IPv6
			target_sock = socket(AF_INET6, SOCK_STREAM, 0);

			enable_blocking_socket(target_sock);	// blocking

			if(err = connect(target_sock, (struct sockaddr *)&target_addr6, sizeof(target_addr6)) < 0){
#ifdef _DEBUG
				printf("[E] Connect failed. errno:%d\n", err);
#endif
				close_socket(target_sock);
				close_socket(client_sock);
				return -1;
			}
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented.\n");
#endif
			close_socket(client_sock);
			return -1;
		}
#ifdef _DEBUG
		printf("[I] Connected to target socks5 server.\n");
#endif
	}


	if(socks5_over_tls_flag == 0){	// Socks5 over AES
		http_request_length = snprintf(http_request, BUFFER_SIZE+1, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n%s: %s\r\n%s: %s\r\n%s: %s\r\n%s: %ld\r\n%s: %ld\r\n%s: %ld\r\n%s: %ld\r\nConnection: close\r\n\r\n", target_domainname, HTTP_REQUEST_HEADER_SOCKS5_KEY, HTTP_REQUEST_HEADER_SOCKS5_VALUE, HTTP_REQUEST_HEADER_AESKEY_KEY, aes_key_b64, HTTP_REQUEST_HEADER_AESIV_KEY, aes_iv_b64, HTTP_REQUEST_HEADER_TVSEC_KEY, tv_sec, HTTP_REQUEST_HEADER_TVUSEC_KEY, tv_usec, HTTP_REQUEST_HEADER_FORWARDER_TVSEC_KEY, forwarder_tv_sec, HTTP_REQUEST_HEADER_FORWARDER_TVUSEC_KEY, forwarder_tv_usec);
	}else{	// Socks5 over TLS
		http_request_length = snprintf(http_request, BUFFER_SIZE+1, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n%s: %s\r\n%s: %s\r\n%s: %s\r\n%s: %s\r\n%s: %ld\r\n%s: %ld\r\n%s: %ld\r\n%s: %ld\r\nConnection: close\r\n\r\n", target_domainname, HTTP_REQUEST_HEADER_SOCKS5_KEY, HTTP_REQUEST_HEADER_SOCKS5_VALUE, HTTP_REQUEST_HEADER_AESKEY_KEY, aes_key_b64, HTTP_REQUEST_HEADER_AESIV_KEY, aes_iv_b64, HTTP_REQUEST_HEADER_TLS_KEY, HTTP_REQUEST_HEADER_TLS_VALUE2, HTTP_REQUEST_HEADER_TVSEC_KEY, tv_sec, HTTP_REQUEST_HEADER_TVUSEC_KEY, tv_usec, HTTP_REQUEST_HEADER_FORWARDER_TVSEC_KEY, forwarder_tv_sec, HTTP_REQUEST_HEADER_FORWARDER_TVUSEC_KEY, forwarder_tv_usec);
	}


	if(https_flag == 1){	// HTTPS
		// SSL Initialize
		OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);

		// SSL TLS connection
		target_ctx_http = SSL_CTX_new(TLS_client_method());
		if(target_ctx_http == NULL){
#ifdef _DEBUG
			printf("[E] SSL_CTX_new error.\n");
#endif
			if(forward_proxy_flag == 1){	// http forward proxy
				close_socket(forward_proxy_sock);
			}else{
				close_socket(target_sock);
			}
			close_socket(client_sock);
			return -2;
		}
		ssl_param.target_ctx_http = target_ctx_http;

//		SSL_CTX_set_mode(target_ctx_http, SSL_MODE_AUTO_RETRY);
		
		if(SSL_CTX_set_min_proto_version(target_ctx_http, TLS1_2_VERSION) == 0){
#ifdef _DEBUG
			printf("[E] SSL_CTX_set_min_proto_version error.\n");
#endif
			fini_ssl(&ssl_param);
			if(forward_proxy_flag == 1){	// http forward proxy
				close_socket(forward_proxy_sock);
			}else{
				close_socket(target_sock);
			}
			close_socket(client_sock);
			return -2;
		}
		
		SSL_CTX_set_default_verify_paths(target_ctx_http);
		SSL_CTX_load_verify_locations(target_ctx_http, server_certificate_filename_https, server_certificate_file_directory_path_https);
		SSL_CTX_set_verify(target_ctx_http, SSL_VERIFY_PEER, NULL);
		
		target_ssl_http = SSL_new(target_ctx_http);
		if(target_ssl_http == NULL){
#ifdef _DEBUG
			printf("[E] SSL_new error.\n");
#endif
			fini_ssl(&ssl_param);
			if(forward_proxy_flag == 1){	// http forward proxy
				close_socket(forward_proxy_sock);
			}else{
				close_socket(target_sock);
			}
			close_socket(client_sock);
			return -2;
		}
		ssl_param.target_ssl_http = target_ssl_http;
	
		if(forward_proxy_flag == 1){	// http forward proxy
			ret = SSL_set_fd(target_ssl_http, forward_proxy_sock);
		}else{
			ret = SSL_set_fd(target_ssl_http, target_sock);
		}
		if(ret == 0){
#ifdef _DEBUG
			printf("[E] SSL_set_fd error.\n");
#endif
			fini_ssl(&ssl_param);
			if(forward_proxy_flag == 1){	// http forward proxy
				close_socket(forward_proxy_sock);
			}else{
				close_socket(target_sock);
			}
			close_socket(client_sock);
			return -2;
		}
		
#ifdef _DEBUG
		printf("[I] Try HTTPS connection. (SSL_connect)\n");
#endif
		if(forward_proxy_flag == 1){	// http forward proxy
			ret = ssl_connect_non_blocking(forward_proxy_sock, target_ssl_http, tv_sec, tv_usec);
		}else{
			ret = ssl_connect_non_blocking(target_sock, target_ssl_http, tv_sec, tv_usec);
		}
		if(ret == -2){
#ifdef _DEBUG
			printf("[E] SSL_connect error.\n");
#endif
			fini_ssl(&ssl_param);
			if(forward_proxy_flag == 1){	// http forward proxy
				close_socket(forward_proxy_sock);
			}else{
				close_socket(target_sock);
			}
			close_socket(client_sock);
			return -2;
		}
#ifdef _DEBUG
		printf("[I] Succeed HTTPS connection. (SSL_connect)\n");
#endif
		
		// HTTP Request
		if(forward_proxy_flag == 1){	// http forward proxy
			sen = send_data_tls(forward_proxy_sock, target_ssl_http, http_request, http_request_length, tv_sec, tv_usec);
		}else{
			sen = send_data_tls(target_sock, target_ssl_http, http_request, http_request_length, tv_sec, tv_usec);
		}
		if(sen <= 0){
#ifdef _DEBUG
			printf("[E] Send http request.\n");
#endif
			fini_ssl(&ssl_param);
			if(forward_proxy_flag == 1){	// http forward proxy
				close_socket(forward_proxy_sock);
			}else{
				close_socket(target_sock);
			}
			close_socket(client_sock);
			return -2;
		}
#ifdef _DEBUG
		printf("[I] Send http request.\n");
#endif
	}else{
		// HTTP Request
		if(forward_proxy_flag == 1){	// http forward proxy
			sen = send_data(forward_proxy_sock, http_request, http_request_length, tv_sec, tv_usec);
		}else{
			sen = send_data(target_sock, http_request, http_request_length, tv_sec, tv_usec);
		}
		if(sen <= 0){
#ifdef _DEBUG
			printf("[E] Send http request.\n");
#endif
			fini_ssl(&ssl_param);
			if(forward_proxy_flag == 1){	// http forward proxy
				close_socket(forward_proxy_sock);
			}else{
				close_socket(target_sock);
			}
			close_socket(client_sock);
			return -1;
		}
#ifdef _DEBUG
		printf("[I] Send http request.\n");
#endif
	}
	
	
	// check Server
	count = 0;
	check = 0;
	do{
		count++;
		if(forward_proxy_flag == 1){	// http forward proxy
			rec = recv_data_aes(forward_proxy_sock, buffer, BUFFER_SIZE, aes_key, aes_iv, tv_sec, tv_usec);
		}else{
			rec = recv_data_aes(target_sock, buffer, BUFFER_SIZE, aes_key, aes_iv, tv_sec, tv_usec);
		}
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
		fini_ssl(&ssl_param);
		if(forward_proxy_flag == 1){	// http forward proxy
			close_socket(forward_proxy_sock);
		}else{
			close_socket(target_sock);
		}
		close_socket(client_sock);
		return -1;
	}

	
	if(socks5_over_tls_flag == 1){	// Socks5 over TLS
		// SSL Initialize
		OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
		
		// SSL TLS connection
		target_ctx_socks5 = SSL_CTX_new(TLS_client_method());
		if(target_ctx_socks5 == NULL){
#ifdef _DEBUG
			printf("[E] SSL_CTX_new error.\n");
#endif
			fini_ssl(&ssl_param);
			if(forward_proxy_flag == 1){	// http forward proxy
				close_socket(forward_proxy_sock);
			}else{
				close_socket(target_sock);
			}
			close_socket(client_sock);
			return -2;
		}
		ssl_param.target_ctx_socks5 = target_ctx_socks5;

//		SSL_CTX_set_mode(target_ctx_socks5, SSL_MODE_AUTO_RETRY);
		
		if(SSL_CTX_set_min_proto_version(target_ctx_socks5, TLS1_2_VERSION) == 0){
#ifdef _DEBUG
			printf("[E] SSL_CTX_set_min_proto_version error.\n");
#endif
			fini_ssl(&ssl_param);
			if(forward_proxy_flag == 1){	// http forward proxy
				close_socket(forward_proxy_sock);
			}else{
				close_socket(target_sock);
			}
			close_socket(client_sock);
			return -2;
		}

		SSL_CTX_set_default_verify_paths(target_ctx_socks5);
		SSL_CTX_load_verify_locations(target_ctx_socks5, server_certificate_filename_socks5, server_certificate_file_directory_path_socks5);
		SSL_CTX_set_verify(target_ctx_socks5, SSL_VERIFY_PEER, NULL);
		
		target_ssl_socks5 = SSL_new(target_ctx_socks5);
		if(target_ssl_socks5 == NULL){
#ifdef _DEBUG
			printf("[E] SSL_new error.\n");
#endif
			fini_ssl(&ssl_param);
			if(forward_proxy_flag == 1){	// http forward proxy
				close_socket(forward_proxy_sock);
			}else{
				close_socket(target_sock);
			}
			close_socket(client_sock);
			return -2;
		}
		ssl_param.target_ssl_socks5 = target_ssl_socks5;

		if(forward_proxy_flag == 1){	// http forward proxy
			ret = SSL_set_fd(target_ssl_socks5, forward_proxy_sock);
		}else{
			ret = SSL_set_fd(target_ssl_socks5, target_sock);
		}
		if(ret == 0){
#ifdef _DEBUG
			printf("[E] SSL_set_fd error.\n");
#endif
			fini_ssl(&ssl_param);
			if(forward_proxy_flag == 1){	// http forward proxy
				close_socket(forward_proxy_sock);
			}else{
				close_socket(target_sock);
			}
			close_socket(client_sock);
			return -2;
		}
		
#ifdef _DEBUG
		printf("[I] Try Socks5 over TLS connection. (SSL_connect)\n");
#endif
		if(forward_proxy_flag == 1){	// http forward proxy
			ret = ssl_connect_non_blocking(forward_proxy_sock, target_ssl_socks5, tv_sec, tv_usec);
		}else{
			ret = ssl_connect_non_blocking(target_sock, target_ssl_socks5, tv_sec, tv_usec);
		}
		if(ret == -2){
#ifdef _DEBUG
			printf("[E] SSL_connect error.\n");
#endif
			fini_ssl(&ssl_param);
			if(forward_proxy_flag == 1){	// http forward proxy
				close_socket(forward_proxy_sock);
			}else{
				close_socket(target_sock);
			}
			close_socket(client_sock);
			return -2;
		}
#ifdef _DEBUG
		printf("[I] Succeed Socks5 over TLS connection. (SSL_connect)\n");
#endif
	}


	// socks selection_request	client -> server
	if((rec = recv_data(client_sock, buffer, BUFFER_SIZE, tv_sec, tv_usec)) <= 0){
#ifdef _DEBUG
		printf("[E] Receive selection request. client -> server\n");
#endif
		fini_ssl(&ssl_param);
		if(forward_proxy_flag == 1){	// http forward proxy
			close_socket(forward_proxy_sock);
		}else{
			close_socket(target_sock);
		}
		close_socket(client_sock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Receive selection request:%d bytes. client -> server\n", rec);
#endif


	// socks selection_request	server -> target
	if(forward_proxy_flag == 1){	// http forward proxy
		if(socks5_over_tls_flag == 0){
			sen = send_data_aes(forward_proxy_sock, buffer, rec, aes_key, aes_iv, tv_sec, tv_usec);
		}else{
			sen = send_data_tls(forward_proxy_sock, target_ssl_socks5, buffer, rec, tv_sec, tv_usec);
		}
	}else{
		if(socks5_over_tls_flag == 0){
			sen = send_data_aes(target_sock, buffer, rec, aes_key, aes_iv, tv_sec, tv_usec);
		}else{
			sen = send_data_tls(target_sock, target_ssl_socks5, buffer, rec, tv_sec, tv_usec);
		}
	}
	if(sen <= 0){
#ifdef _DEBUG
		printf("[E] Send selection request. server -> target.\n");
#endif
		fini_ssl(&ssl_param);
		if(forward_proxy_flag == 1){	// http forward proxy
			close_socket(forward_proxy_sock);
		}else{
			close_socket(target_sock);
		}
		close_socket(client_sock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Send selection request:%d bytes. server -> target\n", sen);	
#endif


	// socks selection_response	server <- target
	if(forward_proxy_flag == 1){	// http forward proxy
		if(socks5_over_tls_flag == 0){
			rec = recv_data_aes(forward_proxy_sock, buffer, BUFFER_SIZE, aes_key, aes_iv, tv_sec, tv_usec);
		}else{
			rec = recv_data_tls(forward_proxy_sock, target_ssl_socks5, buffer, BUFFER_SIZE, tv_sec, tv_usec);
		}
	}else{
		if(socks5_over_tls_flag == 0){
			rec = recv_data_aes(target_sock, buffer, BUFFER_SIZE, aes_key, aes_iv, tv_sec, tv_usec);
		}else{
			rec = recv_data_tls(target_sock, target_ssl_socks5, buffer, BUFFER_SIZE, tv_sec, tv_usec);
		}
	}
	if(rec != sizeof(struct selection_response)){
#ifdef _DEBUG
		printf("[E] Receive selection response. server <- target\n");
#endif
		fini_ssl(&ssl_param);
		if(forward_proxy_flag == 1){	// http forward proxy
			close_socket(forward_proxy_sock);
		}else{
			close_socket(target_sock);
		}
		close_socket(client_sock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Receive selection response:%d bytes. server <- target\n", rec);
#endif


	// socks selection_response	client <- server
	sen = send_data(client_sock, buffer, rec, tv_sec, tv_usec);
	if(sen <= 0){
#ifdef _DEBUG
		printf("[E] Send selection response. client <- server\n");
#endif
		fini_ssl(&ssl_param);
		if(forward_proxy_flag == 1){	// http forward proxy
			close_socket(forward_proxy_sock);
		}else{
			close_socket(target_sock);
		}
		close_socket(client_sock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Send selection response:%d bytes. client <- server\n", sen);
#endif
	struct selection_response *selection_response = (struct selection_response *)&buffer;
	if((unsigned char)selection_response->method == 0xFF){
#ifdef _DEBUG
		printf("[E] Target socks5server Authentication Method error.\n");
#endif
	}

	if(selection_response->method == 0x2){	// username_password_authentication
		// socks username_password_authentication_request		client -> server
		if((rec = recv_data(client_sock, buffer, BUFFER_SIZE, tv_sec, tv_usec)) <= 0){
#ifdef _DEBUG
			printf("[E] Receive username password authentication request. client -> server\n");
#endif
			fini_ssl(&ssl_param);
			if(forward_proxy_flag == 1){	// http forward proxy
				close_socket(forward_proxy_sock);
			}else{
				close_socket(target_sock);
			}
			close_socket(client_sock);
			return -1;
		}
#ifdef _DEBUG
		printf("[I] Receive username password authentication request:%d bytes. client -> server\n", rec);
#endif


		// socks username_password_authentication_request		server -> target
		if(forward_proxy_flag == 1){	// http forward proxy
			if(socks5_over_tls_flag == 0){
				sen = send_data_aes(forward_proxy_sock, buffer, rec, aes_key, aes_iv, tv_sec, tv_usec);
			}else{
				sen = send_data_tls(forward_proxy_sock, target_ssl_socks5, buffer, rec, tv_sec, tv_usec);
			}
		}else{
			if(socks5_over_tls_flag == 0){
				sen = send_data_aes(target_sock, buffer, rec, aes_key, aes_iv, tv_sec, tv_usec);
			}else{
				sen = send_data_tls(target_sock, target_ssl_socks5, buffer, rec, tv_sec, tv_usec);
			}
		}
		if(sen <= 0){
#ifdef _DEBUG
			printf("[E] Send username password authentication request. server -> target\n");
#endif
			fini_ssl(&ssl_param);
			if(forward_proxy_flag == 1){	// http forward proxy
				close_socket(forward_proxy_sock);
			}else{
				close_socket(target_sock);
			}
			close_socket(client_sock);
			return -1;
		}
#ifdef _DEBUG
		printf("[I] Send username password authentication request:%d bytes. server -> target\n", sen);	
#endif
		

		// socks username_password_authentication_response	server <- target
		if(forward_proxy_flag == 1){	// http forward proxy
			if(socks5_over_tls_flag == 0){
				rec = recv_data_aes(forward_proxy_sock, buffer, BUFFER_SIZE, aes_key, aes_iv, tv_sec, tv_usec);
			}else{
				rec = recv_data_tls(forward_proxy_sock, target_ssl_socks5, buffer, BUFFER_SIZE, tv_sec, tv_usec);
			}
		}else{
			if(socks5_over_tls_flag == 0){
				rec = recv_data_aes(target_sock, buffer, BUFFER_SIZE, aes_key, aes_iv, tv_sec, tv_usec);
			}else{
				rec = recv_data_tls(target_sock, target_ssl_socks5, buffer, BUFFER_SIZE, tv_sec, tv_usec);
			}
		}
		if(rec <= 0){
#ifdef _DEBUG
			printf("[E] Receive username password authentication response. server <- target\n");
#endif
			fini_ssl(&ssl_param);
			if(forward_proxy_flag == 1){	// http forward proxy
				close_socket(forward_proxy_sock);
			}else{
				close_socket(target_sock);
			}
			close_socket(client_sock);
			return -1;
		}
#ifdef _DEBUG
		printf("[I] Receive username password authentication response:%d bytes. server <- target\n", rec);
#endif


		// socks username_password_authentication_response	client <- server
		sen = send_data(client_sock, buffer, rec, tv_sec, tv_usec);
		if(sen <= 0){
#ifdef _DEBUG
			printf("[E] Send username password authentication response. client <- server\n");
#endif
			fini_ssl(&ssl_param);
			if(forward_proxy_flag == 1){	// http forward proxy
				close_socket(forward_proxy_sock);
			}else{
				close_socket(target_sock);
			}
			close_socket(client_sock);
			return -1;
		}
#ifdef _DEBUG
		printf("[I] Send username password authentication response:%d bytes. client <- server\n", sen);
#endif
	}


	// socks socks_request	client -> server
	if((rec = recv_data(client_sock, buffer, BUFFER_SIZE, tv_sec, tv_usec)) <= 0){
#ifdef _DEBUG
		printf("[E] Receive socks request. client -> server\n");
#endif
		fini_ssl(&ssl_param);
		if(forward_proxy_flag == 1){	// http forward proxy
			close_socket(forward_proxy_sock);
		}else{
			close_socket(target_sock);
		}
		close_socket(client_sock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Receive socks request:%d bytes. client -> server\n", rec);
#endif


	// socks socks_request	server -> target
	if(forward_proxy_flag == 1){	// http forward proxy
		if(socks5_over_tls_flag == 0){
			sen = send_data_aes(forward_proxy_sock, buffer, rec, aes_key, aes_iv, tv_sec, tv_usec);
		}else{
			sen = send_data_tls(forward_proxy_sock, target_ssl_socks5, buffer, rec, tv_sec, tv_usec);
		}
	}else{
		if(socks5_over_tls_flag == 0){
			sen = send_data_aes(target_sock, buffer, rec, aes_key, aes_iv, tv_sec, tv_usec);
		}else{
			sen = send_data_tls(target_sock, target_ssl_socks5, buffer, rec, tv_sec, tv_usec);
		}
	}
	if(sen <= 0){
#ifdef _DEBUG
		printf("[E] Send socks request. server -> target\n");
#endif
		fini_ssl(&ssl_param);
		if(forward_proxy_flag == 1){	// http forward proxy
			close_socket(forward_proxy_sock);
		}else{
			close_socket(target_sock);
		}
		close_socket(client_sock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Send socks request:%d bytes. server -> target\n", sen);	
#endif
	

	// socks socks_response	server <- target
	if(forward_proxy_flag == 1){	// http forward proxy
		if(socks5_over_tls_flag == 0){
			rec = recv_data_aes(forward_proxy_sock, buffer, BUFFER_SIZE, aes_key, aes_iv, tv_sec, tv_usec);
		}else{
			rec = recv_data_tls(forward_proxy_sock, target_ssl_socks5, buffer, BUFFER_SIZE, tv_sec, tv_usec);
		}
	}else{
		if(socks5_over_tls_flag == 0){
			rec = recv_data_aes(target_sock, buffer, BUFFER_SIZE, aes_key, aes_iv, tv_sec, tv_usec);
		}else{
			rec = recv_data_tls(target_sock, target_ssl_socks5, buffer, BUFFER_SIZE, tv_sec, tv_usec);
		}
	}
	if(rec <= 0){
#ifdef _DEBUG
		printf("[E] Receive socks response. server <- target\n");
#endif
		fini_ssl(&ssl_param);
		if(forward_proxy_flag == 1){	// http forward proxy
			close_socket(forward_proxy_sock);
		}else{
			close_socket(target_sock);
		}
		close_socket(client_sock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Receive socks response:%d bytes. server <- target\n", rec);
#endif


	// socks socks_response	client <- server
	sen = send_data(client_sock, buffer, rec, tv_sec, tv_usec);
	if(sen <= 0){
#ifdef _DEBUG
		printf("[E] Send socks response. client <- server\n");
#endif
		fini_ssl(&ssl_param);
		if(forward_proxy_flag == 1){	// http forward proxy
			close_socket(forward_proxy_sock);
		}else{
			close_socket(target_sock);
		}
		close_socket(client_sock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Send socks response:%d bytes. client <- server\n", sen);
#endif


	// forwarder
#ifdef _DEBUG
	printf("[I] Forwarder.\n");
#endif
	if(forward_proxy_flag == 1){	// http forward proxy
		if(socks5_over_tls_flag == 0){
			err = forwarder_aes(client_sock, forward_proxy_sock, aes_key, aes_iv, forwarder_tv_sec, forwarder_tv_usec);
		}else{
			err = forwarder_tls(client_sock, forward_proxy_sock, target_ssl_socks5, forwarder_tv_sec, forwarder_tv_usec);
		}
	}else{
		if(socks5_over_tls_flag == 0){
			err = forwarder_aes(client_sock, target_sock, aes_key, aes_iv, forwarder_tv_sec, forwarder_tv_usec);
		}else{
			err = forwarder_tls(client_sock, target_sock, target_ssl_socks5, forwarder_tv_sec, forwarder_tv_usec);
		}
	}


#ifdef _DEBUG
	printf("[I] Worker exit.\n");
#endif
	sleep(5);
	fini_ssl(&ssl_param);
	if(forward_proxy_flag == 1){	// http forward proxy
		close_socket(forward_proxy_sock);
	}else{
		close_socket(target_sock);
	}
	close_socket(client_sock);

	return 0;
}

void usage(char *filename)
{
	printf("usage   : %s -h listen_ip -p listen_port -H target_socks5server_domainname -P target_socks5server_port\n", filename);
	printf("          [-s (target socks5 server https connection)] [-t (Socks5 over TLS)]\n");
	printf("          [-A recv/send tv_sec(timeout 0-10 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-300 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]\n");
	printf("          [-a forward proxy domainname] [-b forward proxy port] [-c forward proxy(1:http)]\n");
	printf("          [-d forward proxy authentication(1:basic 2:digest 3:ntlmv2 4:spnego(kerberos))]\n");
	printf("          [-e forward proxy username] [-f forward proxy password] [-g forward proxy user domainname] [-i forward proxy workstationname] [-j forward proxy service principal name]\n");
	printf("example : %s -h 0.0.0.0 -p 9050 -H 192.168.0.10 -P 80\n", filename);
	printf("        : %s -h 0.0.0.0 -p 9050 -H foobar.test -P 80 -t\n", filename);
	printf("        : %s -h 0.0.0.0 -p 9050 -H foobar.test -P 80 -t -A 3 -B 0 -C 3 -D 0\n", filename);
	printf("        : %s -h 0.0.0.0 -p 9050 -H foobar.test -P 80 -t -a 127.0.0.1 -b 3128 -c 1\n", filename);
	printf("        : %s -h 0.0.0.0 -p 9050 -H 192.168.0.10 -P 443 -s\n", filename);
	printf("        : %s -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -s -t\n", filename);
	printf("        : %s -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -s -t -A 3 -B 0 -C 3 -D 0\n", filename);
	printf("        : %s -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -s -t -a 127.0.0.1 -b 3128 -c 1 -d 1 -e forward_proxy_user -f forward_proxy_password\n", filename);
	printf("        : %s -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -s -t -a 127.0.0.1 -b 3128 -c 1 -d 2 -e forward_proxy_user -f forward_proxy_password\n", filename);
	printf("        : %s -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -s -t -a 127.0.0.1 -b 3128 -c 1 -d 3 -e forward_proxy_user -f forward_proxy_password -g forward_proxy_user_domainname -i forward_proxy_workstationname\n", filename);
	printf("        : %s -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -s -t -a 127.0.0.1 -b 3128 -c 1 -d 3 -e test01 -f p@ssw0rd -g test.local -i WORKSTATION -A 10\n", filename);
	printf("        : %s -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -s -t -a 127.0.0.1 -b 3128 -c 1 -d 4 -j forward_proxy_service_principal_name\n", filename);
	printf("        : %s -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -s -t -a 127.0.0.1 -b 3128 -c 1 -d 4 -j HTTP/proxy.test.local@TEST.LOCAL -A 10\n", filename);
}

int main(int argc, char **argv)
{
	int opt;
	const char* optstring = "h:p:H:P:stA:B:C:D:a:b:c:d:e:f:g:i:j:";
	opterr = 0;
	long tv_sec = 3;	// recv send
	long tv_usec = 0;	// recv send
	long forwarder_tv_sec = 3;
	long forwarder_tv_usec = 0;
	
	while((opt=getopt(argc, argv, optstring)) != -1){
		switch(opt){
		case 'h':
			socks5_server_ip = optarg;
			break;
			
		case 'p':
			socks5_server_port = optarg;
			break;
		
		case 'H':
			socks5_target_ip = optarg;
			break;
			
		case 'P':
			socks5_target_port = optarg;
			break;
			
		case 's':
			https_flag = 1;
			break;
			
		case 't':
			socks5_over_tls_flag = 1;
			break;
			
		case 'A':
			tv_sec = atol(optarg);
			break;
			
		case 'B':
			tv_usec = atol(optarg);
			break;
			
		case 'C':
			forwarder_tv_sec = atol(optarg);
			break;
			
		case 'D':
			forwarder_tv_usec = atol(optarg);
			break;
			
		case 'a':
			forward_proxy_ip = optarg;
			break;

		case 'b':
			forward_proxy_port = optarg;
			break;

		case 'c':
			forward_proxy_flag = atoi(optarg);
			break;

		case 'd':
			forward_proxy_authentication_flag = atoi(optarg);
			break;

		case 'e':
			forward_proxy_username = optarg;
			break;

		case 'f':
			forward_proxy_password = optarg;
			break;

		case 'g':
			forward_proxy_user_domainname = optarg;
			break;

		case 'i':
			forward_proxy_workstationname = optarg;
			break;

		case 'j':
			forward_proxy_spn = optarg;
			break;

		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if(socks5_server_ip == NULL || socks5_server_port == NULL || socks5_target_ip == NULL || socks5_target_port == NULL){
		usage(argv[0]);
		exit(1);
	}
	
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
	
	if(forward_proxy_flag < 0 && forward_proxy_flag > 1){
		usage(argv[0]);
		exit(1);
	}

	if(forward_proxy_flag > 0 && (forward_proxy_ip == NULL || forward_proxy_port == NULL)){
		usage(argv[0]);
		exit(1);
	}

	if(forward_proxy_authentication_flag < 0 && forward_proxy_authentication_flag > 4){
		usage(argv[0]);
		exit(1);
	}

	if((forward_proxy_authentication_flag >= 1 && forward_proxy_authentication_flag <= 3) && (forward_proxy_username == NULL || forward_proxy_password == NULL)){
		usage(argv[0]);
		exit(1);
	}

	if(forward_proxy_authentication_flag == 3 && (forward_proxy_user_domainname == NULL || forward_proxy_workstationname == NULL)){
		usage(argv[0]);
		exit(1);
	}

	if(forward_proxy_authentication_flag == 4 && forward_proxy_spn == NULL){
		usage(argv[0]);
		exit(1);
	}


	// load OSSL_PROVIDER legacy, default
	OSSL_PROVIDER *legacy = NULL;
	OSSL_PROVIDER *deflt = NULL;

	legacy = OSSL_PROVIDER_load(NULL, "legacy");
	if(legacy == NULL){
#ifdef _DEBUG
		printf("[E] OSSL_PROVIDER_load error:legacy\n");
#endif
		exit(-1);
	}

	deflt = OSSL_PROVIDER_load(NULL, "default");
	if(deflt == NULL){
#ifdef _DEBUG
		printf("[E] OSSL_PROVIDER_load error:default\n");
#endif
		exit(-1);
	}


	if(forward_proxy_flag == 0){
#ifdef _DEBUG
		printf("[I] Forward proxy:off\n");
#endif
	}else if(forward_proxy_flag == 1){	// http proxy
		if(forward_proxy_authentication_flag == 0){
#ifdef _DEBUG
			printf("[I] Forward proxy connection:http\n");
			printf("[I] Forward proxy authentication:no\n");
#endif
		}else if(forward_proxy_authentication_flag == 1){
#ifdef _DEBUG
			printf("[I] Forward proxy connection:http\n");
			printf("[I] Forward proxy authentication:basic\n");
#endif
		}else if(forward_proxy_authentication_flag == 2){
#ifdef _DEBUG
			printf("[I] Forward proxy connection:http\n");
			printf("[I] Forward proxy authentication:digest\n");
#endif
		}else if(forward_proxy_authentication_flag == 3){
#ifdef _DEBUG
			printf("[I] Forward proxy connection:http\n");
			printf("[I] Forward proxy authentication:ntlmv2\n");
#endif
		}else if(forward_proxy_authentication_flag == 4){
#ifdef _DEBUG
			printf("[I] Forward proxy connection:http\n");
			printf("[I] Forward proxy authentication:spnego(kerberos)\n");
#endif
		}
	}else{
#ifdef _DEBUG
//		printf("[I] Forward proxy connection:\n");
#endif
	}

	if(https_flag == 0){	// HTTP
#ifdef _DEBUG
		printf("[I] Socks5 server connection:http\n");
#endif
	}else{	// HTTPS
#ifdef _DEBUG
		printf("[I] Socks5 server connection:https\n");
#endif
	}
	
	if(socks5_over_tls_flag == 0){	// Socks5 over AES
#ifdef _DEBUG
		printf("[I] Socks5 over AES\n");
#endif
	}else{	// Socks5 over TLS
#ifdef _DEBUG
		printf("[I] Socks5 over TLS\n");
#endif
	}
	
#ifdef _DEBUG
	printf("[I] Timeout recv/send tv_sec(0-10 sec):%ld sec recv/send tv_usec(0-1000000 microsec):%ld microsec.\n", tv_sec, tv_usec);
	printf("[I] Timeout forwarder tv_sec(0-300 sec):%ld sec forwarder tv_usec(0-1000000 microsec):%ld microsec.\n", forwarder_tv_sec, forwarder_tv_usec);
#endif
	
	// ignore SIGPIPE
	signal(SIGPIPE, SIG_IGN);

	int server_sock, client_sock;
	struct sockaddr_in server_addr, client_addr;

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(socks5_server_ip);
	server_addr.sin_port = htons(atoi(socks5_server_port));
	
	server_sock = socket(AF_INET, SOCK_STREAM, 0);
	int reuse = 1;
	setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));
	
	// bind
	if(bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
#ifdef _DEBUG
		printf("[E] bind error.\n");
#endif
		return -1;
	}
	
	// listen
	listen(server_sock, 5);
#ifdef _DEBUG
	printf("[I] Listening port %d on %s.\n", ntohs(server_addr.sin_port), inet_ntoa(server_addr.sin_addr));
#endif

	// accept
	int client_addr_length = sizeof(client_addr);
	while((client_sock = accept(server_sock, (struct sockaddr *)&client_addr, (socklen_t *)&client_addr_length))){
#ifdef _DEBUG
		printf("[I] Connected from %s.\n", inet_ntoa(client_addr.sin_addr));
#endif
		enable_blocking_socket(client_sock);	// blocking
		
		pthread_t thread;
		struct worker_param *worker_param = (struct worker_param *)calloc(1, sizeof(struct worker_param));
		worker_param->client_sock = client_sock;
		worker_param->tv_sec = tv_sec;
		worker_param->tv_usec = tv_usec;
		worker_param->forwarder_tv_sec = forwarder_tv_sec;
		worker_param->forwarder_tv_usec = forwarder_tv_usec;
		
		if(pthread_create(&thread, NULL, (void *)worker, worker_param))
		{
#ifdef _DEBUG
			printf("[E] pthread_create failed.\n");
#endif
			close_socket(client_sock);
		}else{
			pthread_detach(thread);
		}
	}

	close_socket(server_sock);

	// unload OSSL_PROVIDER legacy, default
	OSSL_PROVIDER_unload(legacy);
	OSSL_PROVIDER_unload(deflt);

	return 0;
}

