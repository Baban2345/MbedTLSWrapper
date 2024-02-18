#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "mbedtls/x509_crt.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
mbedtls_ssl_context ssl;
mbedtls_ssl_config conf;
mbedtls_x509_crt cert;
mbedtls_pk_context pkey;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;

void generate_self_signed_cert() {
    mbedtls_x509_crt_init(&cert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    const char *pers = "ssl_gen_key";
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
    mbedtls_x509write_cert crt;
    mbedtls_x509write_crt_init(&crt);
    mbedtls_x509write_crt_set_subject_name(&crt, "CN=Self Signed Certificate");
    mbedtls_x509write_crt_set_issuer_name(&crt, "CN=Self Signed Certificate");
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_validity(&crt, "20010101000000", "20301231235959");
    mbedtls_x509write_crt_set_basic_constraints(&crt, 1, -1);
    mbedtls_x509write_crt_set_serial(&crt, 0);
    mbedtls_x509write_crt_set_key_usage(&crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE);
    mbedtls_x509write_crt_set_key(&crt, &pkey);
    mbedtls_x509write_crt_sign(&crt, &pkey, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), &cert);
}
void error(const char *msg)
{
    perror(msg);
    exit(1);
}
int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Port number not given. Program terminated \n");
        exit(1);
    }
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
	
    int sockfd, newsockfd, portno, n;
    char buffer[255];
    struct sockaddr_in serv_addr, cli_addr;
    socklen_t clilen;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        error("Error opening socket");
    }
    
//
	generate_self_signed_cert();
    mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_own_cert(&conf, &cert, &pkey);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    portno = atoi(argv[1]);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);
    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        error("Binding failed\n");
    }
    else{
    printf("binding succcess\n");
    }
    listen(sockfd, 5);
    clilen = sizeof(cli_addr);
    newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
    if (newsockfd < 0)
    {
        error("Error on accept");
    }
    else{
	printf("\nsocket accepted\n");
	}
    mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_setup(&ssl, &conf);
    mbedtls_ssl_set_bio(&ssl, &newsockfd, mbedtls_net_send, mbedtls_net_recv, NULL);
    mbedtls_ssl_handshake(&ssl);
    while (1)
    {
        bzero(buffer, 255);
        n = mbedtls_ssl_read(&ssl, buffer, 255);
        if (n < 0)
            error("Error on reading");
        printf("client : %s \n", buffer);
        bzero(buffer, 255);
        fgets(buffer, 255, stdin);
        n = mbedtls_ssl_write(&ssl, buffer, strlen(buffer));
        if (n < 0)
            error("Error on writing");
        int i = strncmp("Bye", buffer, 3);
        if (i == 0)
            break;
    }
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_ssl_free(&ssl);
    close(newsockfd);
    close(sockfd);
    return 0;
}
