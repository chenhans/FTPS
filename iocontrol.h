#ifndef IOCONTROL_H
#define IOCONTROL_H

#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/types.h>

/*read wraper*/
ssize_t Read(int fd, void *buf, size_t count);

/*read n bytes from fd to buf, on success return 0, else -1*/
int Readn(int fd, void *buf, size_t n);

/*write wrapper*/
ssize_t Write(int fd, const void *buf, size_t count);

/*write n bytes from buf to fd, on success return 0, else -1*/
int Writen(int fd, const void *buf, size_t n);

/*read to f*/
ssize_t Read2F(int fd, FILE *f);

/*file and directory*/
int checkdir(const char *path);
int get_file_info(const char *filename, char buff[], size_t len);
char *Getcwd(char *buf, size_t size);
void Mkdir(const char *path, mode_t mode);
void Rmdir(const char *path);
void Chdir(const char *path);
DIR *Opendir(const char *dirname);
void Closedir(DIR *dirp);
int listcurrentdir(char buff[], size_t len);

#endif // IOCONTROL_H
