#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <winsock2.h>
#include "openssl/rsa.h" 
#include "openssl/crypto.h"
#include "openssl/x509.h"
#include "openssl/pem.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/rand.h"
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"libeay32.lib")
#pragma comment(lib,"ssleay32.lib")
#define CERTF "client.crt" /*�ͻ��˵�֤��(�辭CAǩ��)*/
#define KEYF "client.key" /*�ͻ��˵�˽Կ(������ܴ洢)*/
#define CACERT "ca.crt" /*CA ��֤��*/
#define PORT 1111 /*����˵Ķ˿�*/
#define SERVER_ADDR "127.0.0.1" /*����ε�IP��ַ*/

#define CHK_NULL(x) if ((x)==NULL) exit (-1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(-2); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(-3); }
int main()
{
	int err;
	int sd;
	struct sockaddr_in sa;
	SSL_CTX* ctx;
	SSL* ssl;
	X509* server_cert;
	char buf[4096];
	char* str;
	const SSL_METHOD *meth;
	int seed_int[100]; /*����������*/

	WSADATA wsaData;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		printf("WSAStartup()fail:%d\n", GetLastError());
		return -1;
	}

	OpenSSL_add_ssl_algorithms(); /*��ʼ��*/
	SSL_load_error_strings(); /*Ϊ��ӡ������Ϣ��׼��*/

	meth = TLSv1_client_method(); /*����ʲôЭ��(SSLv2/SSLv3/TLSv1)�ڴ�ָ��*/
	ctx = SSL_CTX_new(meth);
	CHK_NULL(ctx);

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); /*��֤���*/
	SSL_CTX_load_verify_locations(ctx, CACERT, NULL); /*����֤,�����CA֤��*/


	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(-2);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(-3);
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		printf("Private key does not match the certificate public key\n");
		exit(-4);
	}

	/*������������ɻ���,WIN32ƽ̨����*/
	srand((unsigned)time(NULL));
	for (int i = 0; i < 100; i++)
		seed_int[i] = rand();
	RAND_seed(seed_int, sizeof(seed_int));

	/*������������TCP socket�������� .............................. */
	printf("Begin tcp socket...\n");

	sd = socket(AF_INET, SOCK_STREAM, 0); CHK_ERR(sd, "socket");

	memset(&sa, '\0', sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr(SERVER_ADDR); /* Server IP */
	sa.sin_port = htons(PORT); /* Server Port number */

	err = connect(sd, (struct sockaddr*) &sa,
		sizeof(sa));
	CHK_ERR(err, "connect");

	/* TCP �����ѽ���.��ʼ SSL ���ֹ���.......................... */
	printf("Begin SSL negotiation \n");

	ssl = SSL_new(ctx);
	CHK_NULL(ssl);

	SSL_set_fd(ssl, sd);
	err = SSL_connect(ssl);
	CHK_SSL(err);

	/*��ӡ���м����㷨����Ϣ(��ѡ)*/
	printf("SSL connection using %s\n", SSL_get_cipher(ssl));

	/*�õ�����˵�֤�鲢��ӡЩ��Ϣ(��ѡ) */
	server_cert = SSL_get_peer_certificate(ssl);
	CHK_NULL(server_cert);
	printf("Server certificate:\n");

	str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
	CHK_NULL(str);
	printf("\t subject: %s\n", str);
	free(str);

	str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
	CHK_NULL(str);
	printf("\t issuer: %s\n", str);
	free(str);

	X509_free(server_cert); /*�粻����Ҫ,�轫֤���ͷ� */

							/* ���ݽ�����ʼ,��SSL_write,SSL_read����write,read */
	printf("Begin SSL data exchange\n");

	err = SSL_write(ssl, "Hello World!", strlen("Hello World!"));
	CHK_SSL(err);

	err = SSL_read(ssl, buf, sizeof(buf) - 1);
	CHK_SSL(err);

	buf[err] = '\0';
	printf("Got %d chars:'%s'\n", err, buf);
	SSL_shutdown(ssl); /* send SSL/TLS close_notify */

					   /* ��β���� */
	shutdown(sd, 2);
	SSL_free(ssl);
	SSL_CTX_free(ctx);

	return 0;
}

