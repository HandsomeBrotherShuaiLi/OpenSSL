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
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"libeay32.lib")
#pragma comment(lib,"ssleay32.lib")
/*������Ҫ�Ĳ�����Ϣ���ڴ˴���#define����ʽ�ṩ*/
#define CERTF "server.crt" /*����˵�֤��(�辭CAǩ��)*/
#define KEYF "server.key" /*����˵�˽Կ(������ܴ洢)*/
#define CACERT "ca.crt" /*CA ��֤��*/
#define PORT 1111 /*׼���󶨵Ķ˿�*/

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

int main()
{
	int err;
	int listen_sd;
	int sd;
	struct sockaddr_in sa_serv;
	struct sockaddr_in sa_cli;
	int client_len;
	SSL_CTX* ctx;
	SSL* ssl;
	X509* client_cert;
	char* str;
	char buf[4096];
	const SSL_METHOD *meth;
	WSADATA wsaData;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		printf("WSAStartup()fail:%d\n", GetLastError());
		return -1;
	}

	SSL_load_error_strings(); /*Ϊ��ӡ������Ϣ��׼��*/
	OpenSSL_add_ssl_algorithms(); /*��ʼ��*/
	meth = TLSv1_server_method(); /*����ʲôЭ��(SSLv2/SSLv3/TLSv1)�ڴ�ָ��*/

	ctx = SSL_CTX_new(meth);
	CHK_NULL(ctx);

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); /*��֤���*/
	SSL_CTX_load_verify_locations(ctx, CACERT, NULL); /*����֤,�����CA֤��*/

	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(3);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(4);
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		printf("Private key does not match the certificate public key\n");
		exit(5);
	}

	SSL_CTX_set_cipher_list(ctx, "RC4-MD5");

	/*��ʼ������TCP socket����.................................*/
	printf("Begin TCP socket...\n");

	listen_sd = socket(AF_INET, SOCK_STREAM, 0);
	CHK_ERR(listen_sd, "socket");

	memset(&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons(PORT);

	err = bind(listen_sd, (struct sockaddr*) &sa_serv,
		sizeof(sa_serv));
	CHK_ERR(err, "bind");

	/*����TCP����*/
	err = listen(listen_sd, 5);
	CHK_ERR(err, "listen");

	client_len = sizeof(sa_cli);
	sd = accept(listen_sd, (struct sockaddr*) &sa_cli, &client_len);
	CHK_ERR(sd, "accept");
	closesocket(listen_sd);

	printf("Connection from %lx, port %x\n",
		sa_cli.sin_addr.s_addr, sa_cli.sin_port);


	/*TCP�����ѽ���,���з���˵�SSL����. */
	printf("Begin server side SSL\n");

	ssl = SSL_new(ctx);
	CHK_NULL(ssl);
	SSL_set_fd(ssl, sd);
	err = SSL_accept(ssl);
	printf("SSL_accept finished\n");
	CHK_SSL(err);


	/*��ӡ���м����㷨����Ϣ(��ѡ)*/
	printf("SSL connection using %s\n", SSL_get_cipher(ssl));

	/*�õ��ͻ��˵�֤�鲢��ӡЩ��Ϣ(��ѡ) */
	client_cert = SSL_get_peer_certificate(ssl);
	if (client_cert != NULL) {
		printf("�ͻ���֤����:\n");

		str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
		CHK_NULL(str);
		printf("\t subject: %s\n", str);
//		free(str);

		str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
		if (str == NULL)
			printf("issuer null");
		CHK_NULL(str);
		printf("\t issuer: %s\n", str);
//		free(str);


		X509_free(client_cert);/*�粻����Ҫ,�轫֤���ͷ� */
	}
	else
		printf("Client does not have certificate.\n");

	/* ���ݽ�����ʼ,��SSL_write,SSL_read����write,read */
	err = SSL_read(ssl, buf, sizeof(buf) - 1);
	CHK_SSL(err);
	buf[err] = '\0';
	printf("Got %d chars:'%s'\n", err, buf);

	err = SSL_write(ssl, "�������յ���.", strlen("�������յ���."));
	CHK_SSL(err);

	/* ��β����*/
	shutdown(sd, 2);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	system("pause");
	return 0;
}