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
mbedtls_ssl_context ssl;
mbedtls_ssl_config conf;
mbedtls_x509_crt cert;
mbedtls_pk_context pkey;
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
    mbedtls_x509_crt_init(&cert);
    mbedtls_pk_init(&pkey);
    int sockfd, newsockfd, portno, n;
    char buffer[255];
    struct sockaddr_in serv_addr, cli_addr;
    socklen_t clilen;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        error("Error opening socket");
    }
    
    // Load the server's certificate --> added code

   const char *cert_file_path = "./certificates/server_certificate.crt";
   const char *key_file_path="./certificates/server_private.key";
   int parse_result = mbedtls_x509_crt_parse_file(&cert, cert_file_path);
    int ret = mbedtls_pk_parse_keyfile(&pkey, key_file_path,NULL,NULL,NULL);
   if (parse_result == 0 && ret == 0 ) {
        printf("Certificate parsed successfully");
        //Further processing or usage of the parsed certificate
    } else {
        printf(" Error while parsing through certificates");
        // Handle the error based on the returned error code
    }
    
//
    
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
