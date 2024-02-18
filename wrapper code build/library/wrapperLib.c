#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "mbedtls/x509_crt.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "wrapperLib.h"

#define FAIL    -1

int verifyCA(mbedtls_ssl_config * conf,mbedtls_x509_crt *cacert,struct security_config certificates)
{
	uint32_t flags;
	printf("  . Loading the CA root certificate ...");
	int ret = mbedtls_x509_crt_parse_file(cacert, certificates.ca_cert);
	if (ret < 0) {
        printf(" failed loading  CA");
	return FAIL;
	}
	printf(" ok (%d skipped)\n", ret);
     	if (cacert != NULL) {
    mbedtls_ssl_conf_ca_chain(conf, cacert, NULL);
    printf("\nClient certificates configured successfully\n");
	}
   
}



int s_bind(mbedtls_net_context * ctx,const char * bind_ip,const char * 	port,int proto){
	if(mbedtls_net_bind(ctx,bind_ip,port,proto) != 0){
		printf(" failed\n  Unable to bind ");
		return FAIL;
	}
}
int s_read(mbedtls_ssl_context * ssl,unsigned char * buf,size_t len){
return mbedtls_ssl_read(ssl, buf, len);
}
int s_write(mbedtls_ssl_context * ssl,unsigned char * buf,size_t len){
return mbedtls_ssl_write(ssl, buf, len);
}


int certVerify(struct security_config certificates,mbedtls_x509_crt *srvcert,mbedtls_pk_context *pkey)
{
    printf("\n  . Loading the server cert. and key...");
   int ret = mbedtls_x509_crt_parse_file(srvcert,certificates.my_cert);
    if (ret != 0) {
        printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
        return FAIL;
    }
    else
    printf("\nserver certificate loaded successfully");
   
   ret = mbedtls_x509_crt_parse_file(srvcert,certificates.ca_cert);
    if (ret != 0) {
        printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
        return FAIL;
    }
    else
    printf("\nCA certificate loaded successfully");
    
    ret =mbedtls_pk_parse_keyfile(pkey, certificates.my_key, NULL,NULL,NULL);
    if (ret != 0) {
        printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
        return FAIL;
    }
    else
    printf("\n key loaded successfully");   
}


int sslSetUp(mbedtls_ssl_config * conf,mbedtls_x509_crt *srvcert,mbedtls_pk_context *pkey,mbedtls_ssl_context *ssl)
{
	printf("  . Setting up the SSL data....");
	int ret;
	if ((ret = mbedtls_ssl_config_defaults(conf,
                                           MBEDTLS_SSL_IS_SERVER,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) 
                                           {
        printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        return FAIL;
        }
        
        mbedtls_ssl_conf_ca_chain(conf, srvcert->next, NULL);
    	if ((ret = mbedtls_ssl_conf_own_cert(conf, srvcert, pkey)) != 0) 
    	{
        printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
       	return FAIL;
    	}

    	if ((ret = mbedtls_ssl_setup(ssl, conf)) != 0) {
        printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        return FAIL;
    	}

    printf(" ok\n");
}

int s_accept(mbedtls_net_context * listen_fd,mbedtls_net_context * client_fd,mbedtls_ssl_context *ssl)
{
	printf("  . Waiting for a remote connection ...");
	int ret;
	if ((ret = mbedtls_net_accept(listen_fd, client_fd,NULL, 0, NULL)) != 0) 
        {
        printf(" failed\n  ! mbedtls_net_accept returned %d\n\n", ret);
        return FAIL;
        }
       mbedtls_ssl_set_bio(ssl, client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    printf(" ok\n");
    
    // handshake
    printf("  . Performing the SSL/TLS handshake...");
    while ((ret = mbedtls_ssl_handshake(ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            printf(" failed\n  ! mbedtls_ssl_handshake returned %d\n\n", ret);
            return FAIL;
        }
    }
}

   
   int s_connect(mbedtls_ssl_config * conf,mbedtls_x509_crt *cacert,mbedtls_net_context * server_fd,const char * host,const char * 	port,mbedtls_ssl_context * ssl,mbedtls_ctr_drbg_context * ctr_drbg)
   {
   	mbedtls_ssl_conf_ca_chain(conf, cacert, NULL);
	 int ret;
	 uint32_t flags;
	 ret = mbedtls_net_connect(server_fd, host,port, MBEDTLS_NET_PROTO_TCP);
	 if(ret != 0)
        {
        printf(" failed\n  ! mbedtls_net_connect returned %d\n\n", ret);  
        }
       // else
      //printf("..........ok");
        printf("  . Setting up the SSL/TLS structure...");
        ret = mbedtls_ssl_config_defaults(conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT);
       if(ret != 0)
        {
       
       printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret); 	
      }
      else
      printf("..........ok\n");
      mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
      mbedtls_ssl_conf_ca_chain(conf, cacert, NULL);
      mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, ctr_drbg);
   // mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);
    if (ret = mbedtls_ssl_setup(ssl, conf)!= 0) {
       printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
    }

    if (ret = mbedtls_ssl_set_hostname(ssl, host) != 0) {
        printf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
     
    }

    mbedtls_ssl_set_bio(ssl, server_fd, mbedtls_net_send, mbedtls_net_recv, NULL); 
    
    printf("  . Performing the SSL/TLS handshake....");
   while ((ret = mbedtls_ssl_handshake(ssl)) != 0)
     {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n",
                           (unsigned int) -ret);  
   	}
    }
    printf(" ok\n");
}  
