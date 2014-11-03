/*
 *  Author: Viktor Dukhovni
 *  License: THIS CODE IS IN THE PUBLIC DOMAIN.
 */
#ifndef HEADER_DANESSL_H
#define HEADER_DANESSL_H

#include <stdint.h>
#include <openssl/ssl.h>

/*-
 * Certificate usages:
 * https://tools.ietf.org/html/rfc6698#section-2.1.1
 */
#define DANESSL_USAGE_PKIX_TA	0
#define DANESSL_USAGE_PKIX_EE	1
#define DANESSL_USAGE_DANE_TA	2
#define DANESSL_USAGE_DANE_EE	3
#define DANESSL_USAGE_LAST		DANESSL_USAGE_DANE_EE

/*-
 * Selectors:
 * https://tools.ietf.org/html/rfc6698#section-2.1.2
 */
#define DANESSL_SELECTOR_CERT		0
#define DANESSL_SELECTOR_SPKI		1
#define DANESSL_SELECTOR_LAST		DANESSL_SELECTOR_SPKI

extern int DANESSL_library_init(void);
extern int DANESSL_CTX_init(SSL_CTX *);
extern int DANESSL_init(SSL *, const char *, const char **);
extern void DANESSL_cleanup(SSL *);
extern int DANESSL_add_tlsa(SSL *, uint8_t, uint8_t, const char *,
			    unsigned const char *, size_t);
extern int DANESSL_get_match_cert(SSL *, X509 **, const char **, int *);

#endif
