#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include "ssl_dane.h"

void    print_errors(void)
{
    unsigned long err;
    char buffer[1024];
    const char *file;
    const char *data;
    int line;
    int flags;
    unsigned long thread;

    thread = CRYPTO_thread_id();
    while ((err = ERR_get_error_line_data(&file, &line, &data, &flags)) != 0) {
	ERR_error_string_n(err, buffer, sizeof(buffer));
	if (flags & ERR_TXT_STRING)
	    fprintf(stderr, "Error: %lu:%s:%s:%d:%s\n",
		    thread, buffer, file, line, data);
	else
	    fprintf(stderr, "Error: %lu:%s:%s:%d\n",
		    thread, buffer, file, line);
    }
}

static int cert_digest(
    const char *argv[],
    unsigned char *mdbuf,
    unsigned int *mdlen,
    uint8_t *usage,
    uint8_t *selector
)
{
    const EVP_MD *md;
    X509 *cert = 0;
    BIO *bp;
    unsigned char *buf;
    unsigned char *buf2;
    int len;

    *usage = atoi(argv[1]);
    *selector = atoi(argv[2]);

    if ((bp = BIO_new_file(argv[4], "r")) == NULL) {
	fprintf(stderr, "error opening %s: %m", argv[4]);
	return (0);
    }
    if (!PEM_read_bio_X509(bp, &cert, 0, 0)) {
	BIO_free(bp);
	return (0);
    }
    BIO_free(bp);

    /*
     * Extract ASN.1 DER form of certificate or public key.
     */
    switch (*selector) {
    case SSL_DANE_SELECTOR_CERT:
	len = i2d_X509(cert, NULL);
	buf2 = buf = (unsigned char *) OPENSSL_malloc(len);
	if (buf)
	    i2d_X509(cert, &buf2);
	break;
    case SSL_DANE_SELECTOR_SPKI:
	len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), NULL);
	buf2 = buf = (unsigned char *) OPENSSL_malloc(len);
	if (buf)
	    i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &buf2);
	break;
    }
    if (buf == NULL) {
	perror("malloc");
	return 0;
    }
    OPENSSL_assert(buf2 - buf == len);

    if ((md = EVP_get_digestbyname(argv[3])) == 0) {
	fprintf(stderr, "Invalid certificate digest: %s", argv[3]);
	return 0;
    }
    return EVP_Digest(buf, len, mdbuf, mdlen, md, 0);
}

static int connect_host_port(const char *host, const char *port)
{
    struct addrinfo *ai = 0;
    struct addrinfo *a;
    struct addrinfo hints;
    int err;
    int fd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    err = getaddrinfo(host, port, &hints, &ai);
    if (err != 0) {
	fprintf(stderr, "getaddrinfo: %s:%s: %s\n",
		host, port, gai_strerror(err));
	exit(EXIT_FAILURE);
    }

    for (a = ai; a; a = a->ai_next) {
	fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
	if (fd < 0)
	   continue;
	if (connect(fd, a->ai_addr, a->ai_addrlen) >= 0) {
	    printf("connected to %s:%s\n", host, port);
	    break;
	}
	fprintf(stderr, "warning: %s:%s", host, port);
	perror("connect");
	(void) close(fd);
	fd = -1;
    }
    freeaddrinfo(ai);
    return fd;
}

void usage(const char *progname)
{
    fprintf(stderr, "Usage: %s u s m certfile cafile"
	    " service hostname [certname ...]\n", progname);
    exit(1);
}

int main(int argc, const char *argv[])
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    SSL_CTX *sctx;
    SSL *ssl;
    int fd;
    unsigned int dlen;
    uint8_t u;
    uint8_t s;

    if (argc < 8)
	usage(argv[0]);

    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    SSL_library_init();
    SSL_dane_library_init();

    if (!cert_digest(argv, digest, &dlen, &u, &s))
	exit(1);

    sctx = SSL_CTX_new(SSLv23_method());
    SSL_CTX_load_verify_locations(sctx, argv[5], 0);

    SSL_CTX_dane_init(sctx);
    ssl = SSL_new(sctx);
    SSL_dane_init(ssl, argv[7], argv+7);
    SSL_dane_add_tlsa(ssl, u, s, argv[3], digest, dlen);

    if ((fd = connect_host_port(argv[7], argv[6])) >= 0 &&
	SSL_set_fd(ssl, fd) && SSL_connect(ssl)) {
	printf("verify status: %ld\n", SSL_get_verify_result(ssl));
	if (SSL_shutdown(ssl) == 0)
	    SSL_shutdown(ssl);
    }
    SSL_dane_cleanup(ssl);
    SSL_free(ssl);
    SSL_CTX_free(sctx);

    print_errors();

    EVP_cleanup();
    ERR_remove_state(0);
    ENGINE_cleanup();
    CONF_modules_unload(1);
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();

    return 0;
}
