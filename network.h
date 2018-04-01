#ifndef __NETWORK_H__
#define __NETWORK_H__
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

typedef struct sockaddr SA;
int Socket(int domain, int type, int protocol);
int Setsockopt(int fd, int level, int optname,
        const void *optval, socklen_t optlen);
int Bind(int sockfd, const struct sockaddr *my_addr, socklen_t addrlen);
int Listen(int socket, int backlog);
int Accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

/*convert ipv4/6 address, like 45.78.25.24 to internet format*/
int Inet_pton(int addressfamily, const char *src, void *dst);
const char * Inet_ntop(int addressfamily, const char *src, char *dst, socklen_t size);
char *Sock_ntop(const struct sockaddr *sa);

#endif
