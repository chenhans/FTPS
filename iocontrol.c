#include "iocontrol.h"
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <pwd.h>
#include <sys/stat.h>
#include <grp.h>
#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <dirent.h>


#define MAXLINE 1024

/*read wraper*/
ssize_t Read(int fd, void *buf, size_t count){
    ssize_t n;
    if(-1 == (n = read(fd, buf, count)))
        perror("Read error:");
    return n;
}

/*read n bytes from fd, on success return 0, else -1*/
int Readn(int fd, void *buf, size_t n){
    ssize_t bytesread;
    size_t bytes2read;
    char *ptr = NULL;

    for(bytes2read = n, ptr = buf; \
        bytes2read > 0; \
        ptr += bytesread, bytes2read -= bytesread){
        if((bytesread = read(fd, buf, bytes2read)) < 0){
            if(EINTR == errno)
                bytesread = 0;
            else
                return -1;
        }else if(0 == bytesread)
            break;
    }


    return bytes2read ? -1 : 0;
}


/*write wrapper*/
ssize_t Write(int fd, const void *buf, size_t count){
    ssize_t n;
    if(-1 == (n = write(fd, buf, count)))
        perror("Write error:");
    return n;
}

/*write n bytes from buf to fd, on success return 0, else -1*/
int Writen(int fd, const void *buf, size_t n){
    ssize_t bytewrite;
    size_t byte2write = n;
    const char *ptr = NULL;

    for(byte2write = n, ptr = buf; \
        byte2write > 0; \
        byte2write -= bytewrite, ptr += bytewrite){
        if((bytewrite = write(fd, ptr, byte2write)) < 0){
            if(EINTR == errno || EWOULDBLOCK == errno || EAGAIN == errno){
                bytewrite = 0;
            }else {
                perror("Writen error:");
                return -1;
            }
        }else if(bytewrite == 0){
            printf("Writen socket closed\n");
            break;
        }
    }

    return byte2write ? -1 : 0;
}

/*read until socket closed by peer.*/
/*return 0 on success, socket error -1, file error -2*/
ssize_t Read2F(int fd, FILE *f){
    char buff[BUFSIZ];
    fd_set rs;
    int trueblocking = 1;
    int err;
    int fileerror = 0;
    do{
        if(trueblocking){
            FD_ZERO(&rs);
            FD_SET(fd, &rs);
            select(fd+1, &rs, NULL, NULL, NULL);
        }
        err = read(fd, buff, sizeof(buff));
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
        fwrite(buff, sizeof(char), err, f);
        if(ferror(f)){
            perror("RETR fwrite error:");
            fileerror = 1;
        }
    }while(1);
}


/*file and directory*/
int checkdir(const char *path){
    DIR *dir;
    if(NULL == (dir = opendir(path)))return 0;
    closedir(dir);
    return 1;
}



int get_file_info(const char *filename, char buff[], size_t len)
{
    char	mode[] = "----------";
    char	timebuf[MAXLINE];
    int		timelen, off = 0;
    struct passwd *pwd;
    struct group *grp;
    struct tm *ptm;
    struct stat st;

    if (-1 == stat(filename, &st)) {
        perror("stat error:");
        return -1;
    }

    if (S_ISDIR(st.st_mode))
        mode[0] = 'd';
    if (st.st_mode & S_IRUSR)
        mode[1] = 'r';
    if (st.st_mode & S_IWUSR)
        mode[2] = 'w';
    if (st.st_mode & S_IXUSR)
        mode[3] = 'x';
    if (st.st_mode & S_IRGRP)
        mode[4] = 'r';
    if (st.st_mode & S_IWGRP)
        mode[5] = 'w';
    if (st.st_mode & S_IXGRP)
        mode[6] = 'x';
    if (st.st_mode & S_IROTH)
        mode[7] = 'r';
    if (st.st_mode & S_IWOTH)
        mode[8] = 'w';
    if (st.st_mode & S_IXOTH)
        mode[9] = 'x';
    mode[10] = '\0';
    off += snprintf(buff + off, len - off, "%s", mode);
    off += snprintf(buff + off, len - off, "%2d", 1);

    if (NULL == (pwd = getpwuid(st.st_uid))) {
        perror("getpwuid error:");
        return -1;
    }
    off += snprintf(buff + off, len - off, " %4s", pwd->pw_name);

    if (NULL == (grp = getgrgid(st.st_gid))) {
        perror("getgrgid error:");
        return -1;
    }
    off += snprintf(buff + off, len - off, " %4s",
            (char *) grp->gr_name);

    off += snprintf(buff + off, len - off, " %*d", 8,
            (int) st.st_size);

    ptm = localtime(&st.st_mtime);
    if (ptm != NULL
    && (timelen = strftime(timebuf, sizeof(timebuf), " %b %d %H:%S", ptm)) > 0) {
        timebuf[timelen] = '\0';
        off += snprintf(buff + off, len - off, "%s", timebuf);
    } else {
        perror("localtime error:");
        return -1;
    }
    off += snprintf(buff + off, len - off, " %s\r\n", filename);
    return off;
}

char *Getcwd(char *buf, size_t size)
{
    char	*ptr;

    if (NULL == (ptr = getcwd(buf, size)))
        perror("getcwd error");
    return ptr;
}

void Mkdir(const char *path, mode_t mode)
{
    if (-1 == mkdir(path, mode))
        perror("mkdir error");
}

void Rmdir(const char *path)
{
    if (-1 == rmdir(path))
        perror("rmdir error");
}

void Chdir(const char *path)
{
    if (-1 == chdir(path))
        perror("Chdir error");
}

DIR *Opendir(const char *dirname)
{
    DIR		*dirp;

    if (NULL == (dirp = opendir(dirname)))
        perror("Opendir error");
    return dirp;
}

void Closedir(DIR *dirp)
{
    if (-1 == closedir(dirp))
        perror("closedir error");
}

int listcurrentdir(char buff[], size_t len)
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
        off += get_file_info(filename, buff + off, len - off);
    }
    return off;
}
