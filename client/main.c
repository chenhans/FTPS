#include "../network.h"
#include "protocol.h"
#include "../iocontrol.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))


int main(){
    FTP ftp;
    //init(&ftp, argv[2], atoi(argv[4]));
    init(&ftp, "127.0.0.1", 9876);
    return 0;
}
