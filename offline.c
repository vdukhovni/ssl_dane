#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509.h>

#include "ssl_dane.h"

/* Cut/paste from OpenSSL 1.0.1: ssl/ssl_cert.c */

static int ssl_verify_cert_chain(SSL *s, STACK_OF(X509) *sk)
{
    X509 *x;
    int i;
    X509_STORE_CTX ctx;

    if ((sk == NULL) || (sk_X509_num(sk) == 0))
	return(0);

    x=sk_X509_value(sk,0);
    if(!X509_STORE_CTX_init(&ctx,s->ctx->cert_store,x,sk)) {
	SSLerr(SSL_F_SSL_VERIFY_CERT_CHAIN,ERR_R_X509_LIB);
	return(0);
    }
    X509_STORE_CTX_set_ex_data(&ctx,SSL_get_ex_data_X509_STORE_CTX_idx(),s);

    /* We need to inherit the verify parameters. These can be determined by
     * the context: if its a server it will verify SSL client certificates
     * or vice versa.
     */

    X509_STORE_CTX_set_default(&ctx, s->server ? "ssl_client" : "ssl_server");
    /* Anything non-default in "param" should overwrite anything in the
     * ctx.
     */
    X509_VERIFY_PARAM_set1(X509_STORE_CTX_get0_param(&ctx), s->param);

    if (s->verify_callback)
	X509_STORE_CTX_set_verify_cb(&ctx, s->verify_callback);

    if (s->ctx->app_verify_callback != NULL)
#if 1 /* new with OpenSSL 0.9.7 */
	i=s->ctx->app_verify_callback(&ctx, s->ctx->app_verify_arg);
#else
	i=s->ctx->app_verify_callback(&ctx); /* should pass app_verify_arg */
#endif
    else {
#ifndef OPENSSL_NO_X509_VERIFY
	i=X509_verify_cert(&ctx);
#else
	i=0;
	ctx.error=X509_V_ERR_APPLICATION_VERIFICATION;
	SSLerr(SSL_F_SSL_VERIFY_CERT_CHAIN,SSL_R_NO_VERIFY_CALLBACK);
#endif
    }

    s->verify_result=ctx.error;
    X509_STORE_CTX_cleanup(&ctx);

    return(i);
}

void    print_errors(void)
{
    unsigned long err;
    char buffer[1024];
    const char *file;
    const char *data;
    int line;
    int flags;

    while ((err = ERR_get_error_line_data(&file, &line, &data, &flags)) != 0) {
	ERR_error_string_n(err, buffer, sizeof(buffer));
	if (flags & ERR_TXT_STRING)
	    fprintf(stderr, "Error: %s:%s:%d:%s\n", buffer, file, line, data);
	else
	    fprintf(stderr, "Error: %s:%s:%d\n", buffer, file, line);
    }
}

static int add_tlsa(SSL *ssl, const char *argv[])
{
    const EVP_MD *md = 0;
    unsigned char mdbuf[EVP_MAX_MD_SIZE];
    unsigned int mdlen;
    const unsigned char *tlsa_data;
    X509 *cert = 0;
    BIO *bp;
    unsigned char *buf;
    unsigned char *buf2;
    int len;
    uint8_t u = atoi(argv[1]);
    uint8_t s = atoi(argv[2]);
    const char *mdname = *argv[3] ? argv[3] : 0;
    int ret = 0;

    if ((bp = BIO_new_file(argv[4], "r")) == NULL) {
	fprintf(stderr, "error opening %s: %m", argv[4]);
	return 0;
    }
    if (!PEM_read_bio_X509(bp, &cert, 0, 0)) {
	print_errors();
	BIO_free(bp);
	return 0;
    }
    BIO_free(bp);

    /*
     * Extract ASN.1 DER form of certificate or public key.
     */
    switch (s) {
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

    if (mdname) {
	if ((md = EVP_get_digestbyname(mdname)) == 0) {
	    fprintf(stderr, "Invalid certificate digest: %s\n", mdname);
	    return 0;
	}
	EVP_Digest(buf, len, mdbuf, &mdlen, md, 0);
	tlsa_data = mdbuf;
	len = mdlen;
    } else {
	tlsa_data = buf;
    }
    ret = SSL_dane_add_tlsa(ssl, u, s, mdname, tlsa_data, len);
    OPENSSL_free(buf);
    return ret;
}

static int verify_callback(int ok, X509_STORE_CTX *ctx)
{
    char    buf[8192];
    X509   *cert;
    int     err;
    int     depth;

    cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);

    if (cert)
	X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf));
    else
	strcpy(buf, "<unknown>");
    printf("depth=%d verify=%d err=%d subject=%s\n", depth, ok, err, buf);
    return 1;
}

STACK_OF(X509) *load_chain(const char *chainfile)
{
    BIO *bp;
    char *name = 0;
    char *header = 0;
    unsigned char *data = 0;
    long len;
    int count;
    char *errtype = 0;		/* if error: cert or pkey? */
    STACK_OF(X509) *chain;
    typedef X509 *(*d2i_X509_t)(X509 **, const unsigned char **, long);

    if ((chain = sk_X509_new_null()) == 0) {
	perror("malloc");
	exit(1);
    }

    /*
     * On each call, PEM_read() wraps a stdio file in a BIO_NOCLOSE bio,
     * calls PEM_read_bio() and then frees the bio.  It is just as easy to
     * open a BIO as a stdio file, so we use BIOs and call PEM_read_bio()
     * directly.
     */
    if ((bp = BIO_new_file(chainfile, "r")) == NULL) {
	fprintf(stderr, "error opening chainfile: %s: %m\n", chainfile);
	exit(1);
    }
    /* Don't report old news */
    ERR_clear_error();

    for (count = 0;
	 errtype == 0 && PEM_read_bio(bp, &name, &header, &data, &len);
	 ++count) {
	const unsigned char *p = data;

	if (strcmp(name, PEM_STRING_X509) == 0
	    || strcmp(name, PEM_STRING_X509_TRUSTED) == 0
	    || strcmp(name, PEM_STRING_X509_OLD) == 0) {
	    d2i_X509_t d = strcmp(name, PEM_STRING_X509_TRUSTED) ?
		d2i_X509_AUX : d2i_X509;
	    X509 *cert = d(0, &p, len);

	    if (cert && (p - data) != len)
		errtype = "certificate";
	    else if (sk_X509_push(chain, cert) == 0) {
		perror("malloc");
		exit(1);
	    }
	} else {
	    fprintf(stderr, "unexpected chain file object: %s\n", name);
	    exit(1);
	}

	/*
	 * If any of these were null, PEM_read() would have failed.
	 */
	OPENSSL_free(name);
	OPENSSL_free(header);
	OPENSSL_free(data);
    }
    BIO_free(bp);

    if (errtype) {
	print_errors();
	fprintf(stderr, "error reading: %s: malformed %s", chainfile, errtype);
	exit(1);
    }
    if (ERR_GET_REASON(ERR_peek_last_error()) == PEM_R_NO_START_LINE) {
	/* Reached end of PEM file */
	ERR_clear_error();
	if (count > 0)
	    return chain;
	fprintf(stderr, "no certificates found in: %s\n", chainfile);
	exit(1);
    }
    /* Some other PEM read error */
    print_errors();
    fprintf(stderr, "error reading: %s\n", chainfile);
    exit(1);
}

void usage(const char *progname)
{
    fprintf(stderr, "Usage: %s certificate-usage selector matching-type"
	    " certfile \\\n\t\tCAfile chainfile hostname [certname ...]\n",
	    progname);
    fprintf(stderr, "  where, certificate-usage = TLSA certificate usage,\n");
    fprintf(stderr, "\t selector = TLSA selector,\n");
    fprintf(stderr, "\t matching-type = empty string or OpenSSL digest algorithm name,\n");
    fprintf(stderr, "\t PEM certfile provides certificate association data,\n");
    fprintf(stderr, "\t PEM CAfile contains any usage 0/1 trusted roots,\n");
    fprintf(stderr, "\t PEM chainfile = server chain file to verify\n");
    fprintf(stderr, "\t hostname = destination hostname,\n");
    fprintf(stderr, "\t each certname augments the hostname for name checks.\n");
    exit(1);
}

int main(int argc, const char *argv[])
{
    STACK_OF(X509) *chain;
    SSL_CTX *sctx;
    SSL *ssl;
    long ok;

    if (argc < 8)
	usage(argv[0]);

    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    SSL_library_init();
    SSL_dane_library_init();

    sctx = SSL_CTX_new(SSLv23_method());
    SSL_CTX_load_verify_locations(sctx, argv[5], 0);
    SSL_CTX_set_verify(sctx, SSL_VERIFY_NONE, verify_callback);

    chain = load_chain(argv[6]);

    SSL_CTX_dane_init(sctx);
    ssl = SSL_new(sctx);
    SSL_dane_init(ssl, argv[7], argv+7);
    if (!add_tlsa(ssl, argv)) {
	fprintf(stderr, "error adding TLSA RR\n");
	print_errors();
	exit(1);
    }
    SSL_set_connect_state(ssl);
    /* XXX non-public interface */
    ssl_verify_cert_chain(ssl, chain);

    printf("verify status: %ld\n", ok = SSL_get_verify_result(ssl));
    SSL_dane_cleanup(ssl);
    SSL_free(ssl);
    SSL_CTX_free(sctx);

    print_errors();

    EVP_cleanup();
    ENGINE_cleanup();
    CONF_modules_unload(1);
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();

    return ok == X509_V_OK ? 0 : 1;
}
