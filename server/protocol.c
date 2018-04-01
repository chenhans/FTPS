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
//#define MAXLINE 1024
const char *USER_PASS[2][2]={{"anonymous",""}, {"ftp","ftp"}};
uint16_t CMD_PORT = 9876;
const int QueueMax = 1024;

static void initPIDCHILD(PIDCHILD *p){
    p->size = 0;
    p->maxsize = 10;
    p->node = (pid_t *)malloc(p->maxsize);
}

static void addPIDCHIILD(pid_t id, PIDCHILD *p){
    if (p->size + 1 > p->maxsize ){
        pid_t *t = p->node;
        p->node = (pid_t *)malloc(p->maxsize + p->size);
        memcpy(p->node, t, p->size);
        p->size = p->maxsize + p->size;
        free(t);
    }
    *(p->node + p->size) = id;
    p->size += 1;
}

static void removePIDCHILD(pid_t id, PIDCHILD *p){
    for(int i = 0; i < p->size; ++i){
        if (*(p->node + i) == id){
            for (int j = i+1; j < p->size; ++j){
                *(p->node+j-1) = *(p->node+j);
            }
            p->size -= 1;
            printf("pid: %d removed!\n", id);
            fflush(stdout);
        }
    }
}

static void deletePIDCHILD(PIDCHILD *p){
    free(p->node);
    p->size = 0;
}

static int ftp_init(FTP *, const char *ftp_path);
static int parse_cmd(FTP *);
static void loop(FTP *);
static int ftp_handler(FTP *);
static void ftp_exit(FTP *);

static ssize_t sendresponse(FTP *);
static ssize_t sendstring(FTP *ftp, const char* str);
static ssize_t getrequst(FTP *);
static int pasvconn(FTP *);

static int closesocket(FTP *);

static int USER(FTP *);
static int PASS(FTP *);
static int BYE(FTP *);

static int LIST(FTP *);
static int CWD(FTP *);
static int PWD(FTP *);

static int PASV(FTP *);
static int AUTH(FTP *);
static int CCC(FTP *);

static int RETR(FTP *);
static int STOR(FTP *);
//static int SIZE(FTP *);

static int changeSSLsocket(FTP *ftp, int sockfd);


static int TLSinit(FTP *ftp){
    if(init_OpenSSL() != 0)return -1;
    seed_prng();
    if(setup_server_ctx(&(ftp->ctx)) != 0)return -1;

    if ((ftp->ssl = SSL_new(ftp->ctx)) == NULL){
        printf("Error creating SSL context\n");
        return -1;
    }

    return 0;
}


int init(FTP *ftp, const char *path){
    ftp->socket_client = 0;
    ftp->socket_listen = 0;
    ftp->socket_pasv_listen = 0;
    ftp->socket_pasv_conn = 0;
    //ftp->socket_tls = NULL;
    ftp->AUTHMODE = 0;//TLS is not enabled
    ftp->ccc = 0;
    ftp->user_passwd = 0;
    ftp->ftp_init = ftp_init;
    ftp->ftp_handler = ftp_handler;
    ftp->ftp_exit = ftp_exit;
    ftp->parse_cmd = parse_cmd;
    ftp->loop = loop;
    ftp->sendresponse = sendresponse;
    ftp->getrequst = getrequst;
    ftp->dorequest = NULL;

    if(TLSinit(ftp) != 0){
        printf("initial TLS failed!\n");
        ftp->ssl = NULL;
        ftp->ctx = NULL;
    }

    ftp->ftp_init(ftp, path);
    ftp->loop(ftp);
    return 0;
}

/*return 0 on success, otherwise -1*/
static ssize_t sendresponse(FTP *ftp){
    return sendstring(ftp, ftp->response);
}

static ssize_t sendstring(FTP *ftp, const char* str){
    size_t bufsz = strlen(str);
    if(ftp->AUTHMODE && !ftp->ccc){
        if(0 != changeSSLsocket(ftp, ftp->socket_client)){
            printf("sendstring change to command channel error");
            return -1;
        }
        int ret =  SSLWRITE(ftp->ssl, str, bufsz);
        if(0 != changeSSLsocket(ftp, ftp->socket_pasv_conn)){
            printf("sendstring change to data channel error");
            return -1;
        }
        return ret;
    }else{
        return Writen(ftp->socket_client, str, bufsz);
    }
}


/*success on 0, otherwise -1*/
/*request end with "\r\n"*/
static ssize_t getrequst(FTP *ftp){
    fd_set rs;
    int trueblocking = 1;
    int fd = ftp->socket_client;
    char *buff = ftp->request;
    int sz = 1024;
    int bytesread = 0;
    int err;

    if(ftp->AUTHMODE && !ftp->ccc){
        //clean errors of last data channel
        ERR_clear_error();
        //temporary change to command channel
        if(0 != changeSSLsocket(ftp, ftp->socket_client)){
            printf("getrequset: change to command channel error");
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
                        //socket closed
                        return -1;
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
                //change back to data channel
                if(0 != changeSSLsocket(ftp, ftp->socket_pasv_conn)){
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
                return -1;
            }
            trueblocking = 0;

            if(*(buff+bytesread) == '\n')return 0;
            if(++bytesread > sz){
                printf("getrequest: bufsz is too small or bad request format...\n");
                return -1;
            }
        }while(1);
    }
}


int ftp_init(FTP *ftp, const char *path){
    /*initial listen socket*/
    ftp->socket_listen = socket(AF_INET, SOCK_STREAM, 0);
    int on = 1;

    setsockopt(ftp->socket_listen, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    struct sockaddr_in serveraddr;

    bzero(&serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(CMD_PORT);
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind(ftp->socket_listen, (SA *)&serveraddr, sizeof(serveraddr));

    listen(ftp->socket_listen, QueueMax);
    printf("serveraddr: %s\n", Sock_ntop((struct sockaddr*)&serveraddr));

    /*init default ftp path*/
    Chdir(path);
    Getcwd(ftp->cur_dir, sizeof(ftp->cur_dir));
    return ftp->socket_listen;
}

static void ftp_exit(FTP *ftp){
    if(ftp->socket_client > 0)
        close(ftp->socket_client);
    if(ftp->socket_listen > 0)
        close(ftp->socket_listen);
    if(ftp->socket_pasv_conn > 0)
        close(ftp->socket_pasv_conn);
    if(ftp->socket_pasv_listen > 0)
        close(ftp->socket_pasv_listen);
    if(NULL != ftp->ssl)
        SSL_free(ftp->ssl);
    if(NULL != ftp->ctx)
        SSL_CTX_free(ftp->ctx);
    exit(0);
}

static void loop(FTP *ftp){
    /*init chidprocess management*/
    PIDCHILD children;
    initPIDCHILD(&children);

    while(1){
        /*father waiting for child die...*/
        pid_t cid;
        if((cid =
            waitpid(-1,         //wait for any child process
            NULL,    //no blocking
            WNOHANG)) > 0){
            printf("child: %d exited\n", cid);
            fflush(stdout);
            removePIDCHILD(cid, &children);
        }

        /*accept connections*/
        ftp->socket_client = Accept(ftp->socket_listen, NULL, NULL);
        if (-1 == ftp->socket_client)continue;
        pid_t child = fork();
        if(-1 == child){
            close(ftp->socket_client);
            continue;
        }else if (0 == child){
            /*in child, do ftp handler*/
            printf("child %d created\n", getpid());
            fflush(stdout);
            close(ftp->socket_listen);
            ftp->socket_listen = 0;
            chdir(ftp->cur_dir);
            ftp->ftp_handler(ftp);
        }


        close(ftp->socket_client);ftp->socket_client = 0;
        addPIDCHIILD(child, &children);

    }
}



static int parse_cmd(FTP *ftp){
    const char *buf = ftp->request;
    int n = 1024;
    int i, j;
    for (i = 0; i < min(10, n) && !isspace(buf[i]); ++i){
        ftp->cmd[i] = buf[i];
    }
    if(i < 10)ftp->cmd[i] = '\0';
    while(i < min(10, n) && buf[i] == ' ')++i;
    n -= i;
    for(j = 0; j < min(256, n) && buf[i] != '\r';++i, ++j ){
        ftp->arg[j] = buf[i];
    }
    if(j < 256)ftp->arg[j] = '\0';
    printf("cmd: %s\narg: %s\n", ftp->cmd, ftp->arg);

    if(!strncmp(ftp->cmd, "USER", sizeof("USER"))){
        ftp->dorequest = USER;
    }else if(!strncmp(ftp->cmd, "PASS", sizeof("PASS"))){
        ftp->dorequest = PASS;
    }else if(!strncmp(ftp->cmd, "BYE", sizeof("BYE"))){
        ftp->dorequest = BYE;
    }else if(!strncmp(ftp->cmd, "LIST", sizeof("LIST"))){
        ftp->dorequest = LIST;
    }else if(!strncmp(ftp->cmd, "CWD", sizeof("CWD"))){
        ftp->dorequest = CWD;
    }else if(!strncmp(ftp->cmd, "PWD", sizeof("PWD"))){
        ftp->dorequest = PWD;
    }else if(!strncmp(ftp->cmd, "PASV", sizeof("PASV"))){
        ftp->dorequest = PASV;
    }else if(!strncmp(ftp->cmd, "AUTH", sizeof("AUTH"))){
        ftp->dorequest = AUTH;
    }else if(!strncmp(ftp->cmd, "CCC", sizeof("CCC"))){
        ftp->dorequest = CCC;
    }else if(!strncmp(ftp->cmd, "RETR", sizeof("RETR"))){
        ftp->dorequest = RETR;
    }else if(!strncmp(ftp->cmd, "STOR", sizeof("STOR"))){
        ftp->dorequest = STOR;
    }else{
        ftp->dorequest = NULL;
        return -1;
    }
    return 0;
}

int ftp_handler(FTP *ftp){
    /*set the command socket noblocking*/
    int fdflag = fcntl(ftp->socket_client, F_GETFL, 0);
    fcntl(ftp->socket_client, F_SETFL, fdflag | O_NONBLOCK);

    strcpy(ftp->response, "200 welcome!\r\n");
    /*say hello to client*/
    ftp->sendresponse(ftp);

    while(1){
        /*get request*/
        if(0 != ftp->getrequst(ftp)){
            ftp_exit(ftp);
        }

        if(0 != parse_cmd(ftp)){
            strcpy(ftp->response, "500 Unsupported cmd\r\n");
        }else{
            ftp->dorequest(ftp);
        }
        //ftp->sendresponse(ftp);
    }
    return 0;
}

/* at the end of LIST, STOR, RETR must
 * close all sockets except cmd channel socket
 * which means active or passive mode must be set
 * on everytime by client.
*/
static int closesocket(FTP *ftp){
    if(ftp->socket_pasv_conn > 0){
        close(ftp->socket_pasv_conn);
        ftp->socket_pasv_conn = 0;
    }
    if(ftp->socket_pasv_listen > 0){
        close(ftp->socket_pasv_listen);
        ftp->socket_pasv_listen = 0;
    }
    return 0;
}

/*passive connection established until using data channel*/
static int pasvconn(FTP *ftp){
    if(ftp->socket_pasv_conn > 0)return ftp->socket_pasv_conn;
    if(ftp->socket_pasv_listen < 0){
        printf("pasv listen socket closed!\n");
        ftp_exit(ftp);
        return -1;
    }
    ftp->socket_pasv_conn = accept(ftp->socket_pasv_listen, NULL, NULL);
    if(ftp->socket_pasv_conn != -1){
        {
            struct sockaddr_in pasvaddr;
            socklen_t	pasvlen;
            getsockname(ftp->socket_pasv_conn, (SA *)&pasvaddr, &pasvlen);
            printf("child passive data channel port: %d\n", ntohs(pasvaddr.sin_port));
        }
        /*set passive data channel nonblocking*/
        int fdflag = fcntl(ftp->socket_pasv_conn, F_GETFL, 0);
        fcntl(ftp->socket_pasv_conn, F_SETFL, fdflag | O_NONBLOCK);
        return ftp->socket_pasv_conn;
    }
    printf("accept pasv connection failed\n");
    ftp_exit(ftp);
    return -1;
}

/*login/logout*/
static int USER(FTP *ftp){
    for (int i = 0; i < 2; ++i){
        if(!strcmp(USER_PASS[i][0], ftp->arg)){
            ftp->user_passwd = 0;
            ftp->user_passwd |= ((i+1)<<4);
            strcpy(ftp->response, "331 Please sepcify the password.\r\n");
            ftp->sendresponse(ftp);
            return 0;
        }
    }
    strcpy(ftp->response, "550 User is not found.\r\n");
    ftp->sendresponse(ftp);
    return -1;
}

static int PASS(FTP *ftp){
    if((ftp->user_passwd & 0x0F) != 0){
        strcpy(ftp->response, "530 alread loged. Try USER\r\n");
        ftp->sendresponse(ftp);
        return -1;
    }
    unsigned char index = ((ftp->user_passwd & 0xF0) >> 4)-1;

    if(!strcmp(USER_PASS[index][1], ftp->arg)){
        ftp->user_passwd |= (index+1);
        strcpy(ftp->response, "230 login success\r\n");
    }
    ftp->sendresponse(ftp);
    return 0;
}

static int BYE(FTP *ftp){
    strcpy(ftp->response, "221 Goodbye.\r\n");
    sendresponse(ftp);
    ftp_exit(0);
    return 0;
}

/*directory operations*/

int LIST(FTP *ftp){
    int		n;
    char	buff[BUFSIZ];
    char	tmp_dir_path[PATH_MAX];

    //check login missing;

    /*checking passive connection established or not*/
    if(ftp->AUTHMODE){
        if(ftp->ssl == NULL || ftp->socket_pasv_conn <= 0){
            printf("LIST: TLS not established\n");
            ftp->sendresponse(ftp);
            goto LISTFAILAUTH;
        }
    }else{
        pasvconn(ftp);
    }
    strcpy(ftp->response, "150 Here comes the directory listing.\r\n");
    sendresponse(ftp);


    int havearg = strlen(ftp->arg);
    if(havearg){ /*have file or directory arguments*/
        if (!checkdir(ftp->arg)) { /* maybe a file, check it */
            struct stat	st;
            if (-1 == stat(ftp->arg, &st) && ENOENT == errno) {
                /* file not exists */
                printf("file %s doesn't exsit\n", ftp->arg);
                goto LISTERR;

            }
            /*file exsit*/
            n = get_file_info(ftp->arg, buff, sizeof(buff));
            goto LISTOK;

        }
        /*if arg is a dir*/
        Getcwd(tmp_dir_path, sizeof(tmp_dir_path));
        Chdir(ftp->arg);
    }

        /*list current directory*/
    {
        DIR		*dir;
        struct dirent *dent;
        int		off = 0;
        char	*filename;

        dir = Opendir(".");
        buff[0] = '\0';
        while ((dent = readdir(dir)) != NULL) {
            filename = dent->d_name;
            if ('.' == filename[0])
                continue;
            off = get_file_info(filename, buff , sizeof(buff));
            if(ftp->AUTHMODE){
                if(ftp->ssl != NULL){
                    if(SSLWRITE(ftp->ssl, buff, off) < 0){
                        printf("SSLWRITE error\n");
                    }
                }
            }else{
                Writen(ftp->socket_pasv_conn, buff, off);
            }
        }
    }

    if (havearg){
        Chdir(tmp_dir_path);
    }
LISTOK:
    strcpy(ftp->response, "226 Directory send OK.\r\n");
    closesocket(ftp);
    ftp->sendresponse(ftp);
    return 0;
LISTERR:
    sprintf(ftp->response,
            "550 File \"%s\" specified not exists.\r\n", ftp->arg);
    closesocket(ftp);
    ftp->sendresponse(ftp);
    return -1;
LISTFAILAUTH:
    sprintf(ftp->response,
            "550 Failed on AUTH.\r\n");
    closesocket(ftp);
    ftp->sendresponse(ftp);
    return -1;
}

static int CWD(FTP *ftp){
    char	cur_dir[PATH_MAX];

    //check login missing;

    if (strlen(ftp->arg) < 1) {
        strcpy(ftp->response, "550 Missing dest dir-path.\r\n");
        ftp->sendresponse(ftp);
        return -1;
    }

    if (-1 == chdir(ftp->arg)) {
        strcpy(ftp->response, "550 Invalid dest dir-path.\r\n");
        ftp->sendresponse(ftp);
        return -1;
    }

    if(NULL == Getcwd(cur_dir, PATH_MAX)){
        strcpy(ftp->response, "550 can't access to dest diretory.\r\n");
        ftp->sendresponse(ftp);
        return -1;
    }
    strcpy(ftp->response, "250 Directory successfully changed.\r\n");
    ftp->sendresponse(ftp);
    return 0;
}

static int PWD(FTP *ftp){
    //check login missing;
    Getcwd(ftp->cur_dir, sizeof(ftp->cur_dir));
    sprintf(ftp->response, "257 %s\r\n", ftp->cur_dir);
    ftp->sendresponse(ftp);
    return 0;
}


/*ftp work mode*/

static int PASV(FTP *ftp){
    struct sockaddr_in pasvaddr;
    socklen_t	pasvlen;
    uint16_t port;
    uint32_t ip;
    if(ftp->socket_pasv_listen > 0){
        close(ftp->socket_pasv_listen);
        ftp->socket_pasv_listen = 0;
    }
    ftp->socket_pasv_listen = Socket(AF_INET, SOCK_STREAM, 0);
    pasvlen = sizeof(pasvaddr);
    getsockname(ftp->socket_client, (SA *)&pasvaddr, &pasvlen);
    pasvaddr.sin_port = htons(0);//let system choose
    Bind(ftp->socket_pasv_listen, (SA *)&pasvaddr, sizeof(pasvaddr));

    Listen(ftp->socket_pasv_listen, QueueMax);

    pasvlen = sizeof(pasvaddr);
    getsockname(ftp->socket_pasv_listen, (SA*)&pasvaddr, &pasvlen);
    ip = (uint32_t)(pasvaddr.sin_addr.s_addr);
    port = (uint16_t)(pasvaddr.sin_port);
    sprintf(ftp->response, "%d Entering Passive Mode (%d,%d,%d,%d,%d,%d).\r\n", 227,
            (ip >> 24) & 0xff,(ip >> 16) & 0xff, (ip >> 8) & 0xff,
            ip & 0xff, (port >> 8) & 0xff, port & 0xff);
    ftp->sendresponse(ftp);
    return 0;
}

static int AUTH(FTP *ftp){
    /*checking passive connection established or not*/
    pasvconn(ftp);

    /*TLS take charge socket_pasv_conn*/

    if(ftp->ssl == NULL){
        strcpy(ftp->response, "421 AUTH service offline.\r\n");
        sendresponse(ftp);
        goto AUTHFAILED;
    }

    /*TLS server*/
    BIO *bio = BIO_new_socket(ftp->socket_pasv_conn, BIO_NOCLOSE);
    if(NULL == bio){
          printf("SSL_set_fd failed\n");
          goto AUTHFAILED;
    }
    SSL_set_bio(ftp->ssl, bio, bio);
//    if(1 != SSL_set_fd(ftp->ssl, ftp->socket_pasv_conn)){
//        printf("SSL_set_fd failed\n");
//        goto AUTHFAILED;
//    }

    /*info client try to connect on ssl*/
    strcpy(ftp->response, "334 AUTHING...Please try connect\r\n");
    sendresponse(ftp);
    //blocking until accept
    for(;;){
        int ret = SSL_accept(ftp->ssl);
        if(ret <= 0){
            int err = SSL_get_error(ftp->ssl, ret);
            if(err == SSL_ERROR_NONE){
                //no error
                break;
            }else if (err == SSL_ERROR_ZERO_RETURN ){
                printf("SSLWRITE: ssl connection closed\n");
                goto AUTHFAILED;;
            }else if (err == SSL_ERROR_WANT_READ ||
                      err == SSL_ERROR_WANT_WRITE ||
                      err == SSL_ERROR_WANT_CONNECT ||
                      err == SSL_ERROR_WANT_ACCEPT){
                //try again
                continue;
            }else if (err == SSL_ERROR_SYSCALL){
                //system error
                perror("SSLWRITE system error:");
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

    /*set TLS mode*/
    ftp->AUTHMODE = 1;

    strcpy(ftp->response, "334 AUTH successed. Data channel will be take over by TLS.\r\n");
    ftp->sendresponse(ftp);
    return 0;

AUTHFAILED:
    strcpy(ftp->response, "421 AUTH FAILED\r\n");
    ftp->AUTHMODE = 0;
    ftp->sendresponse(ftp);
    return -1;
}

static int CCC(FTP *ftp){
    if(!ftp->AUTHMODE){
        strcpy(ftp->response, "550 Not authed yet.\r\n");
        ftp->sendresponse(ftp);
        return -1;
    }
    if(ftp->ccc){
        strcpy(ftp->response, "200 Already cancled.\r\n");
        ftp->sendresponse(ftp);
        return 0;
    }
    if(!ftp->ccc){
        strcpy(ftp->response, "200 Command channel protection cancled.\r\n");
        ftp->sendresponse(ftp);
        ftp->ccc = 1;
        return 0;
    }
	return -1;
}

/*file operation*/

static int RETR(FTP *ftp){
    char buff[BUFSIZ];
    size_t n;

    if(ftp->AUTHMODE){
        if(ftp->ssl == NULL || ftp->socket_pasv_conn <= 0){
            printf("RETR: TLS not established\n");
            goto RETRFAILAUTH;
        }
    }else{
        /*checking passive connection established or not*/
        pasvconn(ftp);
    }

    FILE *f = fopen(ftp->arg, "r");
    if(NULL == f){
        printf("RETR: %s don't exsit\n", ftp->arg);
        goto RETRERR;
    }

    strcpy(ftp->response, "150 Here comes the file.\r\n");
    sendresponse(ftp);


    do{
        n = fread(buff, sizeof(char), BUFSIZ, f);
        if(ferror(f)){
            perror("RETR fread failed:");
            break;
        }
        if(ftp->AUTHMODE){
            if(ftp->ssl != NULL){
                if(SSLWRITE(ftp->ssl, buff, n) < 0){
                    printf("SSLWRITE error\n");
                }
            }
        }else{
            Writen(ftp->socket_pasv_conn, buff, n);
        }
    }while(!feof(f));
    fclose(f);
    strcpy(ftp->response, "226 File send OK.\r\n");
    closesocket(ftp);
    ftp->sendresponse(ftp);
    return 0;

RETRERR:
    closesocket(ftp);
    sprintf(ftp->response,
            "550 File \"%s\" specified not exists.\r\n", ftp->arg);
    ftp->sendresponse(ftp);
    return -1;
RETRFAILAUTH:
    closesocket(ftp);
    sprintf(ftp->response,
            "550 RETR failed on AUTH.\r\n");
    ftp->sendresponse(ftp);
    return -1;
}

static int STOR(FTP *ftp){
    //ssize_t n;
    if(ftp->AUTHMODE){
        if(ftp->ssl == NULL || ftp->socket_pasv_conn <= 0){
            printf("STOR: TLS not established\n");
            goto STORFAILAUTH;
        }
    }else{
        /*checking passive connection established or not*/
        pasvconn(ftp);
    }

    FILE *f = fopen(ftp->arg, "w");
    if(NULL == f){
        printf("STOR: %s can't store\n", ftp->arg);
        goto STORERR;
    }

    strcpy(ftp->response, "150 Ready to accept file.\r\n");
    sendresponse(ftp);


    //char buff[1024];
    ssize_t ret;
    /*transmit data channel until receive a 226 code from command channel*/
    if(ftp->AUTHMODE){
        ret = SSLREAD(ftp->ssl, f);
    }else {
        ret = Read2F(ftp->socket_pasv_conn, f);
    }


    if(ret == 0){
        printf("STOR file success\n");
    }else if(ret == -1){
        printf("STOR: socket error\n");
    }else{
        printf("STOR file failed\n");
    }

    if(ferror(f)){
        fclose(f);
        goto STORERR;
    }
    fclose(f);
    strcpy(ftp->response, "226 File stored OK.\r\n");
    closesocket(ftp);
    ftp->sendresponse(ftp);
    return 0;

STORERR:
    closesocket(ftp);
    sprintf(ftp->response,
            "550 File \"%s\" file stored Failed.\r\n", ftp->arg);
    ftp->sendresponse(ftp);
    return -1;
STORFAILAUTH:
    closesocket(ftp);
    sprintf(ftp->response,
            "550 STRO failed on AUTH.\r\n");
    ftp->sendresponse(ftp);
    return -1;
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
