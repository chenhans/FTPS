#ifndef PROTOCOL_H
#define PROTOCOL_H

/* FTP commands format:
 *
 * Login/Logout:
            USER <SP> <username> <CRLF>
            PASS <SP> <password> <CRLF>
            ACCT <SP> <account-information> <CRLF>
            QUIT <CRLF>

 * Data Transport Modes:
            PASV <CRLF>


 * Directory Operations:
            PWD  <CRLF>

            CWD  <SP> <pathname> <CRLF>

 * File Operations:
            STOR <SP> <pathname> <CRLF>

            CDUP <CRLF>
            SMNT <SP> <pathname> <CRLF>
            REIN <CRLF>
            PORT <SP> <host-port> <CRLF>
            TYPE <SP> <type-code> <CRLF>
            STRU <SP> <structure-code> <CRLF>
            MODE <SP> <mode-code> <CRLF>
            RETR <SP> <pathname> <CRLF>
            STOU <CRLF>
            APPE <SP> <pathname> <CRLF>
            ALLO <SP> <decimal-integer>
                [<SP> R <SP> <decimal-integer>] <CRLF>
            REST <SP> <marker> <CRLF>
            RNFR <SP> <pathname> <CRLF>
            RNTO <SP> <pathname> <CRLF>
            ABOR <CRLF>
            DELE <SP> <pathname> <CRLF>
            RMD  <SP> <pathname> <CRLF>
            MKD  <SP> <pathname> <CRLF>
            LIST [<SP> <pathname>] <CRLF>
            NLST [<SP> <pathname>] <CRLF>
            SITE <SP> <string> <CRLF>
            SYST <CRLF>
            STAT [<SP> <pathname>] <CRLF>
            HELP [<SP> <string>] <CRLF>
            NOOP <CRLF>
*/

/* FTP process
 *
 *            SERVER                        CLIENT
 * (1)     listening ...
 * (2)                       <---         AUTH
 *
*/


/*
 *          Connection Establishment
               120
                  220
               220
               421
            Login
               USER <SP> <username> <CRLF>
                  230
                  530
                  500, 501, 421
                  331, 332
               PASS <SP> <password> <CRLF>
                  230
                  202
                  530
                  500, 501, 503, 421
                  332
               ACCT <SP> <account-information> <CRLF>
                  230
                  202
                  530
                  500, 501, 503, 421
               CWD  <SP> <pathname> <CRLF>
                  250
                  500, 501, 502, 421, 530, 550
               CDUP <CRLF> #change dir up to parent
                  200
                  500, 501, 502, 421, 530, 550
               SMNT <SP> <pathname> <CRLF>
                  202, 250
                  500, 501, 502, 421, 530, 550
            Logout
               REIN  <CRLF> #reinitialize, wish to reconnect
                  120
                     220
                  220
                  421
                  500, 502
               QUIT <CRLF> #quit directly
                  221
                  500

            Transfer parameters
               PORT <SP> <host-port> <CRLF>
                  200
                  500, 501, 421, 530
               PASV
                  227
                  500, 501, 502, 421, 530
               MODE <SP> <mode-code> <CRLF>
                  200
                  500, 501, 504, 421, 530
               TYPE
                  200
                  500, 501, 504, 421, 530
               STRU
                  200
                  500, 501, 504, 421, 530
            File action commands
               ALLO
                  200
                  202
                  500, 501, 504, 421, 530
               REST
                  500, 501, 502, 421, 530
                  350
               STOR
                  125, 150
                     (110)
                     226, 250
                     425, 426, 451, 551, 552
                  532, 450, 452, 553
                  500, 501, 421, 530
               STOU
                  125, 150
                     (110)
                     226, 250
                     425, 426, 451, 551, 552
                  532, 450, 452, 553
                  500, 501, 421, 530
               RETR
                  125, 150
                     (110)
                     226, 250
                     425, 426, 451
                  450, 550
                  500, 501, 421, 530
               LIST
                  125, 150
                     226, 250
                     425, 426, 451
                  450
                  500, 501, 502, 421, 530
               NLST
                  125, 150
                     226, 250
                     425, 426, 451
                  450
                  500, 501, 502, 421, 530
               APPE
                  125, 150
                     (110)
                     226, 250
                     425, 426, 451, 551, 552
                  532, 450, 550, 452, 553
                  500, 501, 502, 421, 530
               RNFR
                  450, 550
                  500, 501, 502, 421, 530
                  350
               RNTO
                  250
                  532, 553
                  500, 501, 502, 503, 421, 530
               DELE
                  250
                  450, 550
                  500, 501, 502, 421, 530
               RMD
                  250
                  500, 501, 502, 421, 530, 550
               MKD
                  257
                  500, 501, 502, 421, 530, 550
               PWD
                  257
                  500, 501, 502, 421, 550
               ABOR
                  225, 226
                  500, 501, 502, 421

            Informational commands
               SYST
                  215
                  500, 501, 502, 421
               STAT
                  211, 212, 213
                  450
                  500, 501, 502, 421, 530
               HELP
                  211, 214
                  500, 501, 502, 421
            Miscellaneous commands
               SITE
                  200
                  202
                  500, 501, 530
               NOOP
                  200
                  500 421

*/

#include "../tlssupport.h"
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>

/*child process management*/
typedef struct __PIDCHILD{
    pid_t *node;
    int size;
    int maxsize;
} PIDCHILD;
/*
static void initPIDCHILD(PIDCHILD *p);
static void addPIDCHIILD(pid_t id, PIDCHILD *p);
static void removePIDCHILD(pid_t id, PIDCHILD *p);
static void deletePIDCHILD(PIDCHILD *p);
*/

/*ftp paramenter*/
typedef struct __ftp{
    int socket_listen;//father
    int socket_client;//child(command channel)
    int socket_pasv_listen;//passive listen
    int socket_pasv_conn;//passive connection(data channel)
    //BIO *socket_tls;//passive connection based TLS socket
    SSL_CTX *ctx;//TLS context
    SSL *ssl;//TLS handler
    int AUTHMODE;// TLS is on or not
    int ccc; //cancle command protection
    int (*ftp_init)(struct __ftp *, const char *);
    char response[2048];
    char request[1024];
    char cmd[10];
    char arg[PATH_MAX];
    char cur_dir[PATH_MAX];
    char ftp_path[PATH_MAX];
    ssize_t (*sendresponse)(struct __ftp *);
    ssize_t (*getrequst)(struct __ftp *);
    int (*dorequest)(struct __ftp *);
    unsigned char user_passwd;//higher 4 bit for user, lower 4 bits for passwd
    int (*parse_cmd)(struct __ftp *);
    void (*loop)(struct __ftp *);
    int (*ftp_handler)(struct __ftp *);
    void (*ftp_exit)(struct __ftp *);
} FTP;

int init(FTP *, const char *ftp_path);
/*
static int ftp_init(FTP *, const char *ftp_path);
static int parse_cmd(FTP *, const char *, int);
static void loop(FTP *);
static int ftp_handler(FTP *);
static void ftp_exit(FTP *);

static ssize_t sendresponse(FTP *);
static ssize_t getrequst(FTP *);
static int pasvconn(FTP *)
*/
/* at the end of LIST, STOR, RETR must
 * close all sockets except cmd channel socket
 * which means active or passive mode must be set
 * on everytime by client.
*/
/*
static int closescoket(FTP *);
*/
/*login/logout*/
/*
static int USER(FTP *);
static int PASS(FTP *);
static int BYE(FTP *);
*/

/*directory operations*/
/*
static int LIST(FTP *);
static int CWD(FTP *);
static int PWD(FTP *);
*/

/*ftp work mode*/
/*
static int PASV(FTP *);
static int AUTH(FTP *);
*/

/*file operation*/
/*
static int RETR(FTP *);
static int STOR(FTP *);
static int SIZE(FTP *);
*/

#endif // PROTOCOL_H
