#ifndef _S_SSL_LIBARY
#define _S_SSL_LIBRARY
#include <openssl/ssl.h>
#include <openssl/err.h>

struct security_config
{
    const char *my_cert;
    const char *my_key;
    const char *ca_cert;
};

int s_read(int fd, char *buff, int length);
int s_write(int fd, char *buff, int length);
int s_socket(int domain, int type, int protocol);
int s_bind(int sd, struct sockaddr *addr, unsigned int length);
int s_listen(int sd, int num_connections);
int s_accept(int sd, struct sockaddr *adr, socklen_t *sln, struct security_config certificates);
int s_connect(int sd, struct sockaddr *adr, int length, struct security_config certificates);
#endif
