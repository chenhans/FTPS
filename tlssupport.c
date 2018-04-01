#include "tlssupport.h"
void handle_error(const char *file, int lineno, const char *msg)
{
    fprintf(stderr, "** %s:%i %s\n", file, lineno, msg);
    ERR_print_errors_fp(stderr);
}

int init_OpenSSL(void)
{
    if (!SSL_library_init())
    {
        fprintf(stderr, "** OpenSSL initialization failed!\n");
        return -1;
    }
    SSL_load_error_strings();
    return 0;
}

int verify_callback(int ok, X509_STORE_CTX *store)
{
    char data[256];

    if (!ok)
    {
        X509 *cert = X509_STORE_CTX_get_current_cert(store);
        int  depth = X509_STORE_CTX_get_error_depth(store);
        int  err = X509_STORE_CTX_get_error(store);

        fprintf(stderr, "-Error with certificate at depth: %i\n", depth);
        X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
        fprintf(stderr, "  issuer   = %s\n", data);
        X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
        fprintf(stderr, "  subject  = %s\n", data);
        fprintf(stderr, "  err %i:%s\n", err, X509_verify_cert_error_string(err));
    }

    return ok;
}

void seed_prng(void)
{
  RAND_load_file("/dev/urandom", 1024);
}


#ifdef SERVER
DH *dh512 = NULL;
DH *dh1024 = NULL;

void init_dhparams(void)
{
    BIO *bio;

    bio = BIO_new_file(DHPATH"dh512.pem", "r");

    if (!bio)
        int_error("Error opening file dh512.pem");
    dh512 = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    if (!dh512)
        int_error("Error reading DH parameters from dh512.pem");
    BIO_free(bio);

    bio = BIO_new_file(DHPATH"dh1024.pem", "r");

    if (!bio)
        int_error("Error opening file dh1024.pem");
    dh1024 = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    if (!dh1024)
        int_error("Error reading DH parameters from dh1024.pem");
    BIO_free(bio);
}

DH *tmp_dh_callback(SSL *ssl, int is_export, int keylength)
{
    DH *ret;

    if (!dh512 || !dh1024)
        init_dhparams(  );

    switch (keylength)
    {
        case 512:
            ret = dh512;
            break;
        case 1024:
        default: /* generating DH params is too costly to do on the fly */
            ret = dh1024;
            break;
    }
    return ret;
}
#endif

#define CIPHER_LIST "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"
#define CAFILE "../rootcert.pem"
#define CADIR NULL

#ifdef SERVER
#define CERTFILE "server.pem"
#else
#define CERTFILE "client.pem"
#endif

#ifdef SERVER
int setup_server_ctx(SSL_CTX **ctx)
{
    *ctx = SSL_CTX_new(SSLv23_method(  ));
    if (SSL_CTX_load_verify_locations(*ctx, CAFILE, CADIR) != 1){
        int_error("Error loading CA file and/or directory");
        return -1;
    }
    if (SSL_CTX_set_default_verify_paths(*ctx) != 1){
        int_error("Error loading default CA file and/or directory");
        return -1;
    }
    if (SSL_CTX_use_certificate_chain_file(*ctx, CERTFILE) != 1){
        int_error("Error loading certificate from file");
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(*ctx, CERTFILE, SSL_FILETYPE_PEM) != 1){
        int_error("Error loading private key from file");
        return -1;
    }
    SSL_CTX_set_verify(*ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       verify_callback);
    SSL_CTX_set_verify_depth(*ctx, 4);
    SSL_CTX_set_options(*ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 |
                             SSL_OP_SINGLE_DH_USE);
    SSL_CTX_set_tmp_dh_callback(*ctx, tmp_dh_callback);
    if (SSL_CTX_set_cipher_list(*ctx, CIPHER_LIST) != 1){
        int_error("Error setting cipher list (no valid ciphers)");
        return -1;
    }
    return 0;
}
#endif

int setup_client_ctx(SSL_CTX **ctx)
{
    *ctx = SSL_CTX_new(SSLv23_method(  ));
    if (SSL_CTX_load_verify_locations(*ctx, CAFILE, CADIR) != 1){
        int_error("Error loading CA file and/or directory");
        return -1;
    }
    if (SSL_CTX_set_default_verify_paths(*ctx) != 1){
        int_error("Error loading default CA file and/or directory");
        return -1;
    }
    if (SSL_CTX_use_certificate_chain_file(*ctx, CERTFILE) != 1){
        int_error("Error loading certificate from file");
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(*ctx, CERTFILE, SSL_FILETYPE_PEM) != 1){
        int_error("Error loading private key from file");
        return -1;
    }
    SSL_CTX_set_verify(*ctx, SSL_VERIFY_PEER, verify_callback);
    SSL_CTX_set_verify_depth(*ctx, 4);
    SSL_CTX_set_options(*ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
    if (SSL_CTX_set_cipher_list(*ctx, CIPHER_LIST) != 1){
        int_error("Error setting cipher list (no valid ciphers)");
        return -1;
    }
    return 0;
}

ssize_t SSLREAD(SSL *ssl, FILE* f){
    char buff[BUFSIZ];
    fd_set rs;
    int rfd = SSL_get_fd(ssl);
    int trueblocking = 1;
    int err;
    do
    {
        if(trueblocking){
            FD_ZERO(&rs);
            FD_SET(rfd, &rs);
            select(rfd+1, &rs, NULL, NULL, NULL);
        }
        err = SSL_read(ssl, buff, sizeof(buff));
        if (err <= 0){
            int ret = SSL_get_error(ssl, err);
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
        fwrite(buff, sizeof(char), err, f);
        if(ferror(f)){
            perror("RETR fwrite error:");
            return -1;
        }
    }while (err >= 0);
    return -1;
}

/*blocking write sz bytes*/
/*return 0 on success, otherwise -1*/
int SSLWRITE(SSL *ssl, const char *buf, int sz)
{
    int  ret, nwrite;

    //blocking until sz bytes written
    for (nwrite = 0;  nwrite < sz;  nwrite += ret)
    {
        ERR_clear_error();
        ret = SSL_write(ssl, buf + nwrite, sz - nwrite);
        if (ret <= 0){
            int err = SSL_get_error(ssl, ret);
            ret = 0;
            if(err == SSL_ERROR_NONE){
                //no error
            }else if (err == SSL_ERROR_ZERO_RETURN ){
                printf("SSLWRITE: ssl connection closed\n");
                return -1;
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
                    continue;
                }
            }else if(ret == SSL_ERROR_SSL){
                printf("SSL protocol error\n");
                return -1;
            }else{
                printf("unkown error\n");
                return -1;
            }

        }
    }
    return 0;
}

