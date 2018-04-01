#ifndef TLSSUPPORT_H
#define TLSSUPPORT_H

#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

/*
#define PORT            "16001"
#define SERVER          "localhost"
#define CLIENT          "localhost"
*/


#define int_error(msg)  handle_error(__FILE__, __LINE__, msg)
void handle_error(const char *file, int lineno, const char *msg);

int init_OpenSSL(void);

int verify_callback(int ok, X509_STORE_CTX *store);

void seed_prng(void);

int setup_client_ctx(SSL_CTX **);

int setup_server_ctx(SSL_CTX **);

ssize_t SSLREAD(SSL *ssl, FILE* f);
int SSLWRITE(SSL *ssl, const char *buf, int sz);

#endif // TLSSUPPORT_H
