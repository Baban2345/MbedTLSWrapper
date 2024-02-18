#ifndef _S_SSL_LIBARY
#define _S_SSL_LIBRARY
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include "mbedtls/net_sockets.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ssl.h"
#include "mbedtls/error.h"

struct security_config
{
    const char *my_cert;
    const char *my_key;
    const char *ca_cert;
};
int verifyCA(mbedtls_ssl_config * conf,mbedtls_x509_crt *cacert,struct security_config certificates);
int s_connect(mbedtls_ssl_config * conf,mbedtls_x509_crt *cacert,mbedtls_net_context * server_fd,const char * host,const char * 	port,mbedtls_ssl_context * ssl,mbedtls_ctr_drbg_context * ctr_drbg);
int certVerify(struct security_config certificates,mbedtls_x509_crt *srvcert,mbedtls_pk_context *pkey);
int s_bind(mbedtls_net_context * ctx,const char * bind_ip,const char * 	port,int proto);
int s_write(mbedtls_ssl_context * ssl,unsigned char * buf,size_t len);
int s_read(mbedtls_ssl_context * ssl,unsigned char * buf,size_t len);
int s_accept(mbedtls_net_context * listen_fd,mbedtls_net_context * client_fd,mbedtls_ssl_context *ssl);
int sslSetUp(mbedtls_ssl_config * conf,mbedtls_x509_crt *srvcert,mbedtls_pk_context *pkey,mbedtls_ssl_context *ssl);
#endif
