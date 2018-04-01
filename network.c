#include "network.h"
/*all function now is NOT thread safe!*/

int Bind(int sockfd, const struct sockaddr *addr,
         socklen_t addrlen){
    int ret = bind(sockfd, addr,addrlen);
    if (-1 == ret){
        perror("Bind socket failed:");
    }
    return ret;

}

int Socket(int domain, int type, int protocol){
    int fd = socket(domain, type, protocol);
    if (-1 == fd){
        perror("Socket failed:");
    }
    return fd;
}

/*on success return 0*/
int Listen(int socket, int backlog){
    int ret = listen(socket, backlog);
    if (-1 == ret)perror("Listen failed:");
    return ret;
}

int Accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen){
    for(;;){
        int ret = accept(sockfd, addr, addrlen);
        if (-1 == ret){
            if(EINTR == errno || EWOULDBLOCK == errno){
                continue;
            }else{
               perror("Accept failed:");
               return ret;
            }
        }
        return ret;
    }
}

/*return 1 on sucess*/
int Inet_pton(int af, const char *src, void *dst){
    int ret = inet_pton(af, src, dst);
    if (1 != ret)perror("Inet_pton failed:");
    return ret;
}

const char * Inet_ntop(int af, const char *src, char *dst, socklen_t size){
    const char *ret = inet_ntop(af, src, dst, size);
    if (NULL == ret)perror("Inet_ntop failed:");
    return ret;
}

char *Sock_ntop(const struct sockaddr *sa){
    char port[8];
    static char address[128];
    switch(sa->sa_family){
        case AF_INET:{
            struct sockaddr_in *ipv4 = (struct sockaddr_in*)sa;
            if(inet_ntop(AF_INET, &ipv4->sin_addr, address, sizeof(address)) == NULL)
                return NULL;
            if(ntohs(ipv4->sin_port) != 0){
                snprintf(port, sizeof(port),":%d",
                         ntohs(ipv4->sin_port));
                strcat(address, port);
            }
            return address;
        }
        case AF_INET6:{
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6*)sa;
            if(inet_ntop(AF_INET6, &ipv6->sin6_addr, address, sizeof(address)) == NULL)
                return NULL;
            if(ntohs(ipv6->sin6_port) != 0){
                snprintf(port, sizeof(port), ":%d",
                         ntohs(ipv6->sin6_port));
                strcat(address, port);
            }
            return address;
        }
        default:
           return NULL;
        }
    return address;
}

