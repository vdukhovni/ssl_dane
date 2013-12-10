#ifndef HEADER_SSL_DANE_H
#define HEADER_SSL_DANE_H

#include <stdint.h>
#include <openssl/ssl.h>

/*-
 * Certificate usages:
 * https://tools.ietf.org/html/rfc6698#section-2.1.1
 */
#define SSL_DANE_USAGE_LIMIT_ISSUER	0
#define SSL_DANE_USAGE_LIMIT_LEAF	1
#define SSL_DANE_USAGE_TRUSTED_CA	2
#define SSL_DANE_USAGE_FIXED_LEAF	3
#define SSL_DANE_USAGE_LAST		SSL_DANE_USAGE_FIXED_LEAF

/*-
 * Selectors:
 * https://tools.ietf.org/html/rfc6698#section-2.1.2
 */
#define SSL_DANE_SELECTOR_CERT		0
#define SSL_DANE_SELECTOR_SPKI		1
#define SSL_DANE_SELECTOR_LAST		SSL_DANE_SELECTOR_SPKI

extern int SSL_dane_library_init(void);
extern int SSL_CTX_dane_init(SSL_CTX *);
extern int SSL_dane_init(SSL *, const char *, const char **);
extern void SSL_dane_cleanup(SSL *);
extern int SSL_dane_add_tlsa(SSL *, uint8_t, uint8_t, const char *,
			     unsigned const char *, size_t);
#endif
