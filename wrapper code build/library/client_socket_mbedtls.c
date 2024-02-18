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
void error(const char *msg)
{
    perror(msg);
    exit(1);
}
int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        fprintf(stderr, "Usage: %s ip_addr port \n", argv[0]);
        exit(0);
    }
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_pk_context pkey;
    mbedtls_x509_crt cacert;
    mbedtls_net_context server_fd;
    char buf[1024];
    const char *ip_addr = argv[1];
    const char *port = argv[2];
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_pk_init(&pkey);
    int retur = mbedtls_net_connect(&server_fd, ip_addr, port, MBEDTLS_NET_PROTO_TCP);
    if (retur != 0)
    {
        error("Failed to connect to server");
    }
    else
	{
	printf("server is connected successfully\n");
	}
    
    // Load CA certificate
    int ret = mbedtls_x509_crt_parse_file(&cacert, "./certificates/client_certificate.crt"); // Replace with actual CA certificate file
    if (ret != 0)
    {
        error("Failed to load certificate");
    }
    
    // Load private key if required
    ret = mbedtls_pk_parse_keyfile(&pkey, "./certificates/client_private.key", NULL,NULL,NULL);// Replace with actual private keyfile
    if (ret != 0)
    {
        error("Failed to load private key");
    }
    else{
    printf("key loaded successfully\n");
    }
    mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL); // Set certificate
    mbedtls_ssl_conf_own_cert(&conf, &cacert, &pkey); // Set own certificate and private key
    
    int retu = mbedtls_ssl_setup(&ssl, &conf);
    if (retu != 0) {
    printf("Failed to set up SSL: -0x%x\n", retu);
    error("SSL setup failed");
    }
    else if(retu ==0)
    {
    printf("SSL set up is successfull\n");
	}
    //mbedtls_ssl_setup(&ssl, &conf);
    
    mbedtls_ssl_set_hostname(&ssl, ip_addr);
    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
   /* int rett = mbedtls_ssl_handshake(&ssl);
    if (rett < 0)
    {
    	printf("%d",rett);
        error("Handshake failed");
        
    } */
    int rett;
	do {
    	rett = mbedtls_ssl_handshake(&ssl);
	} 
	while (rett == MBEDTLS_ERR_SSL_WANT_READ || rett == MBEDTLS_ERR_SSL_WANT_WRITE);
	if (rett != 0) {
    	printf("Handshake failed: -0x%x\n", rett);
    	error("Handshake failed");
	}
    	printf("Enter message: ");
    	bzero(buf, 1024);
    	fgets(buf, 1023, stdin);
    	ret = mbedtls_ssl_write(&ssl, (unsigned char *)buf, strlen(buf));
    	if (ret < 0)
    	{
        error("Write failed");
    }
    bzero(buf, 1024);
    ret = mbedtls_ssl_read(&ssl, (unsigned char *)buf, 1023);
    if (ret < 0)
    {
        error("Read failed");
    }
    printf("Server response: %s \n", buf);
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_ssl_free(&ssl);
    mbedtls_net_free(&server_fd);
    return 0;
}
