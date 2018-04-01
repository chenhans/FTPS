#include "../network.h"
#include "protocol.h"
#include "../iocontrol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>


int main(/*int argc, char *argv[]*/)
{
    /*if (argc == 2){
        sscanf(argv[1], "%d", &CMD_PORT);
    }*/
    //const char *ftp_path = "/home/hans_chen/";
	const char *ftp_path = "/Users/hans_chen";
    FTP ftp;
    init(&ftp, ftp_path);

    return 0;
}
