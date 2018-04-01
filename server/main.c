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


int main()
{
    FTP ftp;
    init(&ftp, FTPPATH);

    return 0;
}
