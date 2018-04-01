#include "protocol.h"
#include "../network.h"
#include "../iocontrol.h"
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <limits.h>
#include <fcntl.h>

#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define MAXLINE 1024
const char *USER_PASS[2][2]={{"anonymous",""}, {"ftp","ftp"}};
uint16_t CMD_PORT = 9876;
const int QueueMax = 1024;


static int ftp_init(FTP *, const char *address, const uint16_t port);
static void loop(FTP *);
static void ftp_exit(FTP *);

static void showresponse(FTP *);
static int getCmd(FTP *ftp, const char *s, int n);
static ssize_t getresponse(FTP *);
static ssize_t sendrequst(FTP *);
static ssize_t sendstring(FTP *ftp, const char* str);
static int checklogin(FTP *);
static int USER(FTP *);
static int PASS(FTP *);
static int BYE(FTP *);
/*directory operations*/

int LIST(FTP *);
static int CWD(FTP *);
static int PWD(FTP *);

/*ftp work mode*/

static int PASV(FTP *);
static int AUTH(FTP *);
static int CCC(FTP *);

/*file operation*/

static int RETR(FTP *);
static int STOR(FTP *);
//static int SIZE(FTP *);

static int changeSSLsocket(FTP *, int);

static int TLSinit(FTP *ftp){
    if(init_OpenSSL() != 0)return -1;
    seed_prng();
    if(setup_client_ctx(&(ftp->ctx)) != 0)return -1;

    if ((ftp->ssl = SSL_new(ftp->ctx)) == NULL){
        printf("Error creating SSL context\n");
        return -1;
    }

    return 0;
}

int init(FTP *ftp, const char *address, const uint16_t port){
    setbuf(stdout, NULL);

    ftp->socket_cmd = 0;
    ftp->socket_pasv_data = 0;
    ftp->ctx = NULL;
    ftp->ssl = NULL;
    ftp->AUTHMODE = 0;
    ftp->ccc = 0;
    ftp->f = NULL;
    ftp->ftp_exit = ftp_exit;
    ftp->loop = loop;
    ftp->dorequest = NULL;

    if(TLSinit(ftp) != 0){
        printf("initial TLS failed!\n");
        ftp->ssl = NULL;
        ftp->ctx = NULL;
    }
    ftp_init(ftp, address, port);
    ftp->loop(ftp);
    return 0;
}



static int ftp_init(FTP *ftp, const char *address, const uint16_t port){

    ftp->socket_cmd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serveraddr;

    bzero(&serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(port);
    if (0 == inet_aton(address, &serveraddr.sin_addr)){
        printf("address: %s is invalid\n", address);
    }

    if(0 == connect(ftp->socket_cmd, (SA *)&serveraddr, sizeof(serveraddr))){
        printf("connect to %s successed!\n", Sock_ntop((SA *)&serveraddr));
    }

    return ftp->socket_cmd;
}

static void ftp_exit(FTP *ftp){
    if(ftp->socket_cmd > 0){
        close(ftp->socket_cmd);
        ftp->socket_cmd = 0;
    }
    if(ftp->socket_pasv_data > 0){
        close(ftp->socket_pasv_data);
        ftp->socket_pasv_data = 0;
    }
    if(ftp->f != NULL)fclose(ftp->f);

    if(NULL != ftp->ssl)
        SSL_free(ftp->ssl);
    if(NULL != ftp->ctx)
        SSL_CTX_free(ftp->ctx);
    exit(0);
}

static void loop(FTP *ftp){
    int fdflag = fcntl(ftp->socket_cmd, F_GETFL, 0);
    fcntl(ftp->socket_cmd, F_SETFL, fdflag | O_NONBLOCK);

    getresponse(ftp);
    showresponse(ftp);
    if(ftp->code != 200 && ftp->code != 220){
        ftp->ftp_exit(ftp);
    }

    while(1){
            printf("\nftp> ");
            char cmd[11+PATH_MAX];
            char *p = cmd;
            size_t n = 11+PATH_MAX;
            getline(&p, &n, stdin);
            if(-1 == getCmd(ftp, p, n)){
                continue;
            }
            ftp->dorequest(ftp);
        }
}


static void showresponse(FTP *ftp){
    fflush(stdout);
    printf("%s\n", ftp->response);
}

static int getCmd(FTP *ftp, const char *s, int n){
    char cmd[11];//FTP cmd length <= 10
    char arg[256]; //linux file name lenghth <=255

    int i = 0, j = 0;
    while(i < min(10, n) && !isspace(s[i]) && s[i] != '\n'){
        cmd[i] = s[i];
        ++i;
    }
    if(i <= 11)cmd[i] = '\0';
    while(i < n && isspace(s[i]) && s[i] != '\n')++i;
    n -= i;
    while(j < 255 && i < min(255, n) && s[i] != '\n'){
        arg[j] = s[i];
        ++i, ++j;
    }
    if(j <= 256)arg[j] = '\0';
    //printf("ftp> %s %s\n", cmd, arg);

    if(!strncmp(cmd, "user", sizeof("user"))){
        strncpy(ftp->request, "USER ", sizeof("USER "));
        strncat(ftp->request, arg, j);
        strncat(ftp->request, "\r\n", sizeof("\r\n"));
        ftp->dorequest = USER;
    }else if(!strncmp(cmd, "pass", sizeof("pass"))){
        strncpy(ftp->request, "PASS ", sizeof("PASS "));
        strncat(ftp->request, arg, j);
        strncat(ftp->request, "\r\n", sizeof("\r\n"));
        ftp->dorequest = PASS;
    }else if(!strncmp(cmd, "bye", sizeof("bye"))){
        strncpy(ftp->request, "BYE ", sizeof("BYE "));
        //strncat(ftp->request, arg, j);
        strncat(ftp->request, "\r\n", sizeof("\r\n"));
        ftp->dorequest = BYE;
    }else if(!strncmp(cmd, "auth", sizeof("auth"))){
        strncpy(ftp->request, "AUTH ", sizeof("AUTH "));
        //strncat(ftp->request, arg, j);
        strncat(ftp->request, "\r\n", sizeof("\r\n"));
        ftp->dorequest = AUTH;
    }else if(!strncmp(cmd, "ccc", sizeof("ccc"))){
        strncpy(ftp->request, "CCC ", sizeof("CCC "));
        //strncat(ftp->request, arg, j);
        strncat(ftp->request, "\r\n", sizeof("\r\n"));
        ftp->dorequest = CCC;
    }else if(!strncmp(cmd, "passive", sizeof("passive"))){
        strncpy(ftp->request, "PASV ", sizeof("PASV "));
        //strncat(ftp->request, arg, j);
        strncat(ftp->request, "\r\n", sizeof("\r\n"));
        ftp->dorequest = PASV;
    }else if(!strncmp(cmd, "ls", sizeof("ls"))){
        strncpy(ftp->request, "LIST ", sizeof("LIST "));
        strncat(ftp->request, arg, j);
        strncat(ftp->request, "\r\n", sizeof("\r\n"));
        //printf("protocolstring: %s\n", protocolstring);
        ftp->dorequest = LIST;
    }else if(!strncmp(cmd, "pwd", sizeof("pwd"))){
        strncpy(ftp->request, "PWD ", sizeof("PWD "));
        //strncat(ftp->request, arg, j);
        strncat(ftp->request, "\r\n", sizeof("\r\n"));
        ftp->dorequest = PWD;
    }else if(!strncmp(cmd, "pwd", sizeof("pwd"))){
        strncpy(ftp->request, "PWD ", sizeof("PWD "));
        //strncat(ftp->request, arg, j);
        strncat(ftp->request, "\r\n", sizeof("\r\n"));
        ftp->dorequest = PWD;
    }else if(!strncmp(cmd, "cd", sizeof("cd"))){
        strncpy(ftp->request, "CWD ", sizeof("CWD "));
        strncat(ftp->request, arg, j);
        strncat(ftp->request, "\r\n", sizeof("\r\n"));
        ftp->dorequest = CWD;
    }else if(!strncmp(cmd, "get", sizeof("get"))){
        //test open file
        ftp->f = fopen(arg, "w");
        if(NULL == ftp->f){
            printf("can't create local file: %s\n", arg);
            return -1;
        }
        strncpy(ftp->filename, arg, strlen(arg)+1);

        strncpy(ftp->request, "RETR ", sizeof("RETR "));
        strncat(ftp->request, arg, j);
        strncat(ftp->request, "\r\n", sizeof("\r\n"));
        ftp->dorequest = RETR;
    }else if(!strncmp(cmd, "put", sizeof("put"))){
        FILE *f = fopen(arg, "r");
        if(NULL == f){
            printf("file: %s doesn't exsit\n", arg);
            return -1;
        }
        ftp->f = f;
        strncpy(ftp->filename, arg, strlen(arg)+1);

        strncpy(ftp->request, "STOR ", sizeof("STRO "));
        strncat(ftp->request, arg, j);
        strncat(ftp->request, "\r\n", sizeof("\r\n"));
        ftp->dorequest = STOR;
    }else {
        printf("Unknow command: %s\n", cmd);
        ftp->dorequest = NULL;
        return -1;
    }

    return 0;
}

/*return 0 on success, otherwise -1*/
/*requst end up with "\r\n"*/
static ssize_t sendrequst(FTP *ftp){

    return sendstring(ftp, ftp->request);
}

static ssize_t sendstring(FTP *ftp, const char* str){
    size_t bufsz = strlen(str);
    if(ftp->AUTHMODE && !ftp->ccc){
        if(0 != changeSSLsocket(ftp, ftp->socket_cmd)){
            printf("sendstring change to command channel error");
            return -1;
        }
        int ret = SSLWRITE(ftp->ssl, str, bufsz);
        if(0 != changeSSLsocket(ftp, ftp->socket_pasv_data)){
            printf("sendstring change to data channel error");
            return -1;
        }
        return ret;
    }else{
        return Writen(ftp->socket_cmd, str, bufsz);
    }
}

/*return 0 on success, otherwise -1*/
/*response endup with "\r\n"*/
static ssize_t getresponse(FTP *ftp){
    ERR_clear_error();
    fd_set rs;
    int trueblocking = 1;
    int fd = ftp->socket_cmd;
    char *buff = ftp->response;
    int sz = 1024;
    int bytesread = 0;
    int err;
    int fileerror = 0;
    if(ftp->AUTHMODE && !ftp->ccc){
        //clean errors of last data channel
        ERR_clear_error();
        //temporary change to command channel
        if(0 != changeSSLsocket(ftp, ftp->socket_cmd)){
            printf("getresponse: change to command channel error");
            return -1;
        }
        do{
            if(trueblocking){
                FD_ZERO(&rs);
                FD_SET(fd, &rs);
                select(fd+1, &rs, NULL, NULL, NULL);
            }
            err = SSL_read(ftp->ssl, buff+bytesread, 1);
            if (err <= 0){
                int ret = SSL_get_error(ftp->ssl, err);
                if (ret == SSL_ERROR_WANT_READ ||
                    ret == SSL_ERROR_WANT_WRITE ||
                    ret == SSL_ERROR_WANT_CONNECT ||
                    ret == SSL_ERROR_WANT_ACCEPT){
                    trueblocking = 1;
                    err = 0;
                    switch(ret){
                    case SSL_ERROR_WANT_READ:
                        //printf("SSL_ERROR_WANT_READ\n");
                        break;
                    case SSL_ERROR_WANT_WRITE:
                        //printf("SSL_ERROR_WANT_WRITE\n");
                        break;
                    case SSL_ERROR_WANT_CONNECT:
                        //printf("SSL_ERROR_WANT_CONNECT\n");
                        break;
                    case SSL_ERROR_WANT_ACCEPT:
                        //printf("SSL_ERROR_WANT_ACCEPT\n");
                        break;
                    }
                    continue;
                }else if(ret == SSL_ERROR_SYSCALL){
                    if(EINTR == errno ||
                       EWOULDBLOCK == errno ||
                       EAGAIN == errno){
                        trueblocking = 1;
                        err = 0;
                        switch(ret){
                        case EINTR:
                            //printf("EINTR\n");
                            break;
                        case EWOULDBLOCK:
                            //printf("EWOULDBLOCK\n");
                            break;
                        }
                        continue;
                    }else{
                        //socket closed, data transmition is over
                        //break;
                        return 0;
                    }
                }else if(ret == SSL_ERROR_ZERO_RETURN){
                    printf("SSL connection closed\n");
                    //break;
                    return -1;
                }else{
                    //quit other errors
                    //break;
                    return -1;
                }
            }
            trueblocking = 0;
            if(*(buff+bytesread) == '\n'){
                *(buff+bytesread) = '\0';
                char buf[4];
                strncpy(buf, ftp->response, 3);
                buf[3] = '\0';
                ftp->code = (uint16_t)atoi(buf);
                //change back to data channel
                if(0 != changeSSLsocket(ftp, ftp->socket_pasv_data)){
                    printf("getrequset: change to data channel error");
                    return -1;
                }
                return 0;
            }
            if(++bytesread > sz){
                printf("getrequest: bufsz is too small or bad request format...\n");
                return -1;
            }
        }while(1);
    }else {
        do{
            if(trueblocking){
                FD_ZERO(&rs);
                FD_SET(fd, &rs);
                select(fd+1, &rs, NULL, NULL, NULL);
            }
            err = read(fd, buff+bytesread, 1);
            if(err < 0){
                if(EINTR == errno){
                    trueblocking = 0;
                    continue;
                }else if(EWOULDBLOCK == errno){
                    trueblocking = 1;
                    continue;
                }else{
                    //or other bad error..
                    //break;
                    return -1;
                }
            }else if(err == 0){
                //socket closed
                //break;
                if(fileerror)return -2;
                return 0;
            }
            trueblocking = 0;

            if(*(buff+bytesread) == '\n'){
                *(buff+bytesread) = '\0';
                char buf[4];
                strncpy(buf, ftp->response, 3);
                buf[3] = '\0';
                ftp->code = (uint16_t)atoi(buf);
                return 0;
            }
            if(++bytesread > sz){
                printf("getrequest: bufsz is too small or bad request format...\n");
                return -1;
            }
        }while(1);
    }

}

/* at the end of LIST, STOR, RETR must
 * close all sockets except cmd channel socket
 * which means active or passive mode must be set
 * on everytime by client.
*/


static int checklogin(FTP *ftp){
    if(ftp->loged == 0x11)return 0;//loged in
    if(ftp->loged == 0)return -1;//need user&passwd
    if(ftp->loged == 0x10)return -2;//need passwd
    return -3;//bad format
}

/*login/logout*/
static int USER(FTP *ftp){
    sendrequst(ftp);
    getresponse(ftp);
    showresponse(ftp);
    if(ftp->code == 230 || ftp->code == 331){
        ftp->loged = 0x10;
        return 0;
    }
    return -1;
}

static int PASS(FTP *ftp){
    if(checklogin(ftp) != -2){
        printf("USER name first please!\n");
        return -1;
    }
    sendrequst(ftp);
    getresponse(ftp);
    showresponse(ftp);

    if(ftp->code == 230){
        ftp->loged = 0x11;
        return 0;
    }
    return -1;
}

static int BYE(FTP *ftp){
    if(0 != checklogin(ftp)){
        printf("not login ...\n");
        return -1;
    }
    sendrequst(ftp);
    getresponse(ftp);
    showresponse(ftp);
    ftp_exit(ftp);
    return 0;
}

/*directory operations*/

int LIST(FTP *ftp){
    if(0 != checklogin(ftp)){
        printf("not login ...\n");
        return -1;
    }
    setbuf(stdout, NULL);
    if(ftp->AUTHMODE){
        if(AUTH(ftp) != 0){
            printf("LIST failed on AUTH\n");
            return -1;
        }
    }else {
        if(PASV(ftp) != 0){
            printf("LIST connect to server failed\n");
            return -1;
        }
    }

    sendrequst(ftp);
    getresponse(ftp);//150
    showresponse(ftp);
    if(ftp->code == 550)goto LISTEND;
    if(ftp->code == 150){
        /*transmit data channel until receive a 226 code from command channel*/
        if(ftp->AUTHMODE){
            SSLREAD(ftp->ssl, stdout);
        }else {
            Read2F(ftp->socket_pasv_data, stdout);
        }
    }

LISTEND:
    getresponse(ftp);
    showresponse(ftp);
    close(ftp->socket_pasv_data);
    ftp->socket_pasv_data = 0;
    return 0;
}

static int CWD(FTP *ftp){
    if(0 != checklogin(ftp)){
        printf("not login ...\n");
        return -1;
    }
    sendrequst(ftp);
    getresponse(ftp);
    showresponse(ftp);
    if(ftp->code == 250)return 0;
    return -1;
}

static int PWD(FTP *ftp){
    if(0 != checklogin(ftp)){
        printf("not login ...\n");
        return -1;
    }
    sendrequst(ftp);
    getresponse(ftp);
    showresponse(ftp);
    if(ftp->code == 257)return 0;
    return -1;
}


/*ftp work mode*/
/*if data channel exsit/created successfully, return 0; otherwise -1*/
static int PASV(FTP *ftp){
    if(0 != checklogin(ftp)){
        printf("not login ...\n");
        return -1;
    }
    /*already connected*/
    if(ftp->socket_pasv_data > 0)return 0;
    char *cmd = "PASV \r\n";
    sendstring(ftp, cmd);
//    if(-1 == Writen(ftp->socket_cmd, "PASV \r\n", strlen("PASV \r\n"))){
//        printf("send PASV failed\n");
//        ftp_exit(ftp);
//    }
    getresponse(ftp);showresponse(ftp);
    if(ftp->code != 227){
        printf("PASV failed: %s", ftp->response);
        return -1;
    }

    /*extract ip & port from message: "%d Entering Passive Mode (%d,%d,%d,%d,%d,%d).\r\n"*/
    uint16_t buff[6];
    uint16_t port;
    uint32_t ip;
    ftp->socket_pasv_data = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serveraddr;

    char *p = strchr(ftp->response, '(');
    if (p == NULL){
        printf("not ip & port info");
        return -1;
    }
    ++p;
    for(int i = 0; i < 6; ++p, ++i){
        buff[i] = atoi(p);
        p = strchr(p, ',');
        if(p == NULL && i < 5){
            printf("ip & port bad info");
            return -1;
        }
    }

    //ip = *((uint32_t *)&buff[0]);
    //port = *((uint16_t *)&buff[4]);
    ip = (buff[0]<<24)|(buff[1]<<16)|(buff[2]<<8)|buff[3];
    port = (buff[4]<<8)|buff[5];
    bzero(&serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = port;
    serveraddr.sin_addr.s_addr = ip;

    if(0 !=connect(ftp->socket_pasv_data, (SA *)&serveraddr, sizeof(serveraddr))){
        perror("pasv connect failed:");
        return -1;
    }
    /*set passive data socket nonblocking*/
    int fdflag = fcntl(ftp->socket_pasv_data, F_GETFL, 0);
    fcntl(ftp->socket_pasv_data, F_SETFL, fdflag | O_NONBLOCK);
    return 0;
}

static int AUTH(FTP *ftp){
    if(0 != checklogin(ftp)){
        printf("not login ...\n");
        return -1;
    }
    if(ftp->AUTHMODE && ftp->socket_pasv_data > 0){
        printf("AUTHED!\n");
        return 0;
    }
    if(PASV(ftp) != 0){
        printf("AUTH connect to server failed\n");
        return -1;
    }


    if(ftp->ssl == NULL){
        printf("AUTH failed:TLS context is not initialed\n");
        return -1;
    }

    /*Trying... Checking.... server's supports...*/
    char *cmd = "AUTH \r\n";
    sendstring(ftp, cmd);
//    Writen(ftp->socket_cmd, "AUTH \r\n", strlen("AUTH \r\n"));
    getresponse(ftp);
    showresponse(ftp);

    if(ftp->code != 334){
        printf("Reasons about server failed to initilizae TLS:\n");
        goto AUTHFAILED;
    }

    /*Server is ready to accept connection*/
    BIO *bio = BIO_new_socket(ftp->socket_pasv_data, BIO_NOCLOSE);
    if(NULL == bio){
          printf("SSL_set_fd failed\n");
          goto AUTHFAILED;
    }
    SSL_set_bio(ftp->ssl, bio, bio);
//    if(0 == SSL_set_fd(ftp->ssl, ftp->socket_pasv_data)){
//        printf("SSL_set_fd failed\n");
//        goto AUTHFAILED;
//    }

    //blocking until connect
    for(;;){
        int ret = SSL_connect(ftp->ssl);
        if(ret <= 0){
            int err = SSL_get_error(ftp->ssl, ret);
            if(err == SSL_ERROR_NONE){
                //no error
                break;
            }else if (err == SSL_ERROR_ZERO_RETURN ){
                printf("SSL_connect: ssl connection closed\n");
                goto AUTHFAILED;;
            }else if (err == SSL_ERROR_WANT_READ ||
                      err == SSL_ERROR_WANT_WRITE ||
                      err == SSL_ERROR_WANT_CONNECT ||
                      err == SSL_ERROR_WANT_ACCEPT){
                //try again
                continue;
            }else if (err == SSL_ERROR_SYSCALL){
                //system error
                perror("SSL_connect system error:");
                if(EINTR == errno ||
                        EWOULDBLOCK == errno ||
                        EAGAIN == errno){
                    //socket not ready or interupted by system. try again.
                    ret = 0;
                    continue;
                }
            }else{
                printf("unkown error\n");
                goto AUTHFAILED;;
            }
        }else { //SSL handshake success
            break;
        }
    }
    /*SSL connection successed!*/
    ftp->AUTHMODE = 1;
    getresponse(ftp);
    showresponse(ftp);

    return 0;

AUTHFAILED:
    getresponse(ftp);
    showresponse(ftp);
    ftp->AUTHMODE = 0;
    return -1;
}

static int CCC(FTP *ftp){
    if(0 != checklogin(ftp)){
        printf("not login ...\n");
        return -1;
    }
    if(!ftp->AUTHMODE){
        printf("not auth yet!\n");
        return -1;
    }
    if(ftp->ccc){
        printf("already cancled command channel protection!\n");
        return -1;
    }
    sendrequst(ftp);
    getresponse(ftp);
    showresponse(ftp);
    if(ftp->code != 200){
        printf("CCC failed!\n");
        return -1;
    }else{
        ftp->ccc = 1;
        return 0;
    }
}


/*file operation*/

static int RETR(FTP *ftp){
    if(0 != checklogin(ftp)){
        printf("not login ...\n");
        return -1;
    }
    if(ftp->AUTHMODE){
        if(AUTH(ftp) != 0){
            printf("RETR failed on AUTH\n");
            return -1;
        }
    }else {
        if(PASV(ftp) != 0){
            printf("RETR connect to server failed\n");
            return -1;
        }
    }
    /*try to create file*/

    sendrequst(ftp);
    getresponse(ftp);
    showresponse(ftp);
    if(ftp->code != 150){
        //remove local created file
        fclose(ftp->f);
        ftp->f = NULL;
        remove(ftp->filename);

        close(ftp->socket_pasv_data);
        ftp->socket_pasv_data = 0;

        return -1;
    }
    if(ftp->code == 150){
        /*transmit data channel until receive a 226 code from command channel*/
        int ret;
        if(ftp->AUTHMODE){
            ret = SSLREAD(ftp->ssl, ftp->f);            
        }else {
            ret = Read2F(ftp->socket_pasv_data, ftp->f);
        }
        getresponse(ftp);//226
        showresponse(ftp);
    }

    fclose(ftp->f);
    ftp->f = NULL;

    close(ftp->socket_pasv_data);
    ftp->socket_pasv_data = 0;

    return 0;
}

static int STOR(FTP *ftp){
    if(0 != checklogin(ftp)){
        printf("not login ...\n");
        return -1;
    }
    if(ftp->AUTHMODE){
        if(AUTH(ftp) != 0){
            printf("RETR failed on AUTH\n");
            return -1;
        }
    }else {
        if(PASV(ftp) != 0){
            printf("STOR connect to server failed\n");
            return -1;
        }
    }

    sendrequst(ftp);
    getresponse(ftp);
    showresponse(ftp);

    if(ftp->code != 150){
        fclose(ftp->f);
        ftp->f = NULL;
        if(!ftp->AUTHMODE){
            close(ftp->socket_pasv_data);
            ftp->socket_pasv_data = 0;
        }
        return -1;
    }

    if(ftp->code == 150){
        char buff[BUFSIZ];
        int n;
        do{
            n = fread(buff, sizeof(char), BUFSIZ, ftp->f);
            if(ftp->AUTHMODE){
                SSLWRITE(ftp->ssl, buff, n);
            }else {
                if(-1 == Writen(ftp->socket_pasv_data, buff, n)){
                    printf("STOR write failed\n");
                    break;
                }
            }
        }while(!feof(ftp->f));

        close(ftp->socket_pasv_data);
        ftp->socket_pasv_data = 0;

        getresponse(ftp);//226
        showresponse(ftp);
    }

    return 0;
}

static int changeSSLsocket(FTP *ftp, int sockfd){
    ERR_clear_error();
    if(sockfd == SSL_get_fd(ftp->ssl))return 0;
    BIO *bio = BIO_new_socket(sockfd, BIO_NOCLOSE);
    if(bio == NULL)return -1;
    SSL_set_bio(ftp->ssl, bio, bio);
    return 0;
//    if(1 != SSL_set_fd(ftp->ssl, sockfd)){
//        printf("changeSSLsocket failed\n");
//        return -1;
//    }
}
