Work-in progress.  DANE support for OpenSSL.

This generalizes the SMTP specific DANE support in Postfix by
supporting all certificate usages and more versions of OpenSSL.

Documentation for now consists of the header file, and the example
ssl_dane_test.c program.  Real applications will get TLSA data from
DNS, rather than certificate files in the file-system.

On the other hand, certificate files make testing much easier, since
one can test TLSA records not found in the wild.
