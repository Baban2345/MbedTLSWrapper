#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "tls_api.h"

#define FAIL    -1
#define SERVER_CONTEXT 1
#define CLIENT_CONTEXT 0

struct list
{
   struct list *link;
   int fd;
   SSL *sl;
}List;

static struct list *ssl_fd_map_list = NULL;
static SSL_CTX *gCtx;

static SSL_CTX * s_initCTX(int ty);

static void insert_ssl_fd_map(struct list **list, int fd, SSL *ssl)
{
   struct list *tmp = *list;
   if(tmp == NULL)
   {
      tmp = (struct list *)malloc(sizeof(List));
      *list = tmp;
   }
   else
   {
      while(tmp->link != NULL)
      tmp = tmp->link;
      tmp->link = (struct list *)malloc(sizeof(List));
      tmp = tmp->link;
   }
   tmp->fd = fd;
   tmp->sl = ssl;
   tmp->link = NULL;
}

static SSL * get_ssl_from_fd(int fd)
{
   struct list *tmp = ssl_fd_map_list;
   SSL *ssl = NULL;

   while(tmp)
   {
      if(tmp->fd == fd)
      {
         ssl=tmp->sl;
         break;
      }
      else
      {
         tmp=tmp->link;
      }
   }

   return ssl;
}

int s_socket(int domain, int type, int protocol)
{
    int socket_dr;
    socket_dr = socket(domain, type, protocol);

    return socket_dr;
}

int s_bind(int sd, struct sockaddr *addr, unsigned int length)
{
   if (bind(sd, addr, length) < 0) 
   {
      close(sd);
      perror("\nUnable to bind");
      return FAIL;
   }

   return sd;
}

int s_listen(int sd, int num_connections)
{
   if (listen(sd, num_connections) < 0) 
   {
      close(sd);
      perror("\nUnable to listen");
      return FAIL;
   }
   
   return sd;
}

int s_read(int fd, char *buff, int length)
{
   SSL *ssl;
   ssl = get_ssl_from_fd(fd);
   length = SSL_read(ssl, buff, length);
   return length;
}

int s_write(int fd, char *buff, int length)
{
   SSL *ssl;
   ssl = get_ssl_from_fd(fd);
   length = SSL_write(ssl, buff, length);
   return length;
}
static int s_configure_context(SSL_CTX *ctx, const char *cert, const char *key);
static void s_showCerts(SSL* ssl);
int s_accept(int sd, struct sockaddr *adr, socklen_t *sln, struct security_config certificates)
{
   int csd;
   SSL *ssl=NULL;

   if(gCtx == NULL)
   {
      perror("\n Server Inside gCtx");
      gCtx = s_initCTX(SERVER_CONTEXT);
      if(gCtx == NULL)
         perror("\n gCtx is NULL");
  
      if(s_configure_context(gCtx, certificates.my_cert, certificates.my_key) == FAIL)
      {
         perror("\n s_configure_context problem");
         return FAIL;
      }

      if (SSL_CTX_load_verify_locations(gCtx, certificates.ca_cert, NULL) != 1)
      {
         perror("\n SSL_CTX_load_verify_locations problem");
         return FAIL;
      }

      STACK_OF(X509_NAME) *cert_names = SSL_load_client_CA_file(certificates.ca_cert);

      if(cert_names !=NULL)
      {
         SSL_CTX_set_client_CA_list(gCtx, cert_names);
         perror("\n certificates configured");
      }
      else
      {
         perror("Info: SSL_CTX_set_client_CA_list Failed.\n");
      }

     SSL_CTX_set_verify(gCtx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
      SSL_CTX_set_verify_depth(gCtx, 1);
   }

   csd = accept(sd, adr, sln);
   
   if (csd < 0) 
   {
      perror("\nUnable to accept");
      return FAIL;
   }

   ssl = SSL_new(gCtx);

   if(ssl == NULL)
      perror("\n SSL is NULL");

   SSL_set_fd(ssl, csd);

   if (SSL_accept(ssl) < 0)
   {
      perror("\n SSL accept probelm");
      close(csd);
      SSL_free(ssl);
      
      return FAIL;
   }

   s_showCerts(ssl);
   insert_ssl_fd_map(&ssl_fd_map_list, csd, ssl);

   return csd;
}

int s_connect(int sd, struct sockaddr *adr, int length, struct security_config certificates)
{
   SSL *ssl;
   int err;

   if(NULL == gCtx)
   {
      gCtx = s_initCTX(CLIENT_CONTEXT);

      if(gCtx == NULL)
         perror("\n gCtx is NULL");
   }

   if(s_configure_context(gCtx, certificates.my_cert, certificates.my_key) == FAIL)
   {
      perror("\n s_configure_context failed");
      return FAIL; 
   }
  
   if( (err = connect(sd, (struct sockaddr *)adr, length)) < 0)
   {
      perror("\n Normal connect failed");
      printf("\n Error code returned =%d", err);
      SSL_CTX_free(gCtx);
      close(sd);
      return FAIL;
   }

   ssl = SSL_new(gCtx);
   
   if(ssl == NULL)
   {
     perror("\n SSL is NULL");
   }

   SSL_set_fd(ssl, sd);

   if (SSL_connect(ssl) == FAIL )
   {
      close(sd);
      SSL_free(ssl);
      SSL_CTX_free(gCtx);
      perror("\n SSL_connect failed");
      return FAIL;
   }

   s_showCerts(ssl);
   insert_ssl_fd_map(&ssl_fd_map_list, sd, ssl);
   
   return sd;
}

void s_showCerts(SSL* ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl);

    if ( cert != NULL )
    {
       printf("certificates:\n");
       line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
       printf("Subject: %s\n", line);
       free(line);
       line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
       printf("Issuer: %s\n", line);
       free(line);
       X509_free(cert);
    }
    else
    {
       perror("Info: No client certificates configured.\n");
    }
}

int s_configure_context(SSL_CTX *ctx, const char *cert, const char *key)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) 
    {
       perror("\n Certificate probelm");
       return FAIL;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0 ) 
    {
       perror("\n Key probelm");
       return FAIL;
    }
}

static SSL_CTX * s_initCTX(int context_type)
{
    static int initialised = 0;
    SSL_CTX  *ctx;
    const SSL_METHOD *method;

    if(0 == initialised)
    {
       SSL_library_init();
       OpenSSL_add_ssl_algorithms();
       SSL_load_error_strings();  
    }

	if(context_type == SERVER_CONTEXT)
    {
		method = SSLv23_server_method();  /* Create new server-method instance */
        printf("\n SSLv23_server_method ");
    }
	else if(context_type == CLIENT_CONTEXT)
    {
       method = SSLv23_client_method();  /* Create new client-method instance */       
       printf("\n SSLv23_client_method");
    }
    else
    {
       perror("\n Invalid method request for context creation");
       return NULL;
    }
    
    ctx = SSL_CTX_new(method);  

    if(ctx == NULL)
    {
       perror("\n ctx is NULL");
       return NULL;
    }
    
    return ctx;
}
