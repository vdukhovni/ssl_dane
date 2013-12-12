#! /bin/bash

set -e
cd $(dirname "$0")/pems/
ROOT=eqfax
DOMAIN=gmail.com
HOST=imap.gmail.com
CHAIN=$HOST
TEST=../offline

sscert() {
    local tmp=$(mktemp "$2.XXXXXX")
    openssl req -sha256 -new 2>/dev/null \
	-config <(
	    printf "[req]\n%s\n[dn]\n%s\n[exts]\n%s\n[alts]\n%s\n" \
		   "$(printf "%s\n%s\n%s\n" \
		       "prompt = no" \
		       "distinguished_name = dn" \
		       "x509_extensions = exts")" \
		   "$(printf "CN=%s\n" "$1")" \
		   "$(printf "%s\n%s\n%s\n%s\n%s" \
		     "basicConstraints        = CA:true" \
		     "extendedKeyUsage        = serverAuth, clientAuth" \
		     "subjectKeyIdentifier    = hash" \
		     "authorityKeyIdentifier  = keyid:always,issuer:always" \
		     "subjectAltName=@alts")" \
		   "DNS=$1") \
	 -newkey param:<(openssl ecparam -name prime256v1) \
	   -keyout /dev/null -nodes \
	 -x509 -set_serial 1 -days 30 >> "$tmp" &&
    mv "$tmp" "$2.pem"
}

runtest() {
    local desc="$1"; shift
    local usage="$1"; shift
    local selector="$1"; shift
    local mtype="$1"; shift
    local tlsa="$1"; shift
    local ca="$1"; shift
    local chain="$1"; shift
    local digest

    case $mtype in
    0) digest="";;
    1) digest=sha256;;
    2) digest=sha512;;
    *) echo "bad mtype: $mtype"; exit 1;;
    esac

    printf "%d %d %d %-24s %s: " "$usage" "$selector" "$mtype" "$tlsa" "$desc"

    case $ca in /dev/null) ;; *) ca="$ca.pem";; esac
    "$TEST" "$usage" "$selector" "$digest" "$tlsa.pem" "$ca" "$chain.pem" \
    	"$@" > /dev/null
}

checkpass() { runtest "$@" && { echo pass; } || { echo fail; exit 1; }; }
checkfail() { runtest "$@" && { echo fail; exit 1; } || { echo pass; }; }

#---------

ss=sscert; rm -f "$ss.pem"; sscert "$HOST" "$ss"

# Usage 0 tests:
#
for s in 0 1; do for m in 0 1 2; do

    for t in "1.${HOST}" "2.${HOST}" "${ROOT}"; do
	checkpass "valid CA" 0 "$s" "$m" "$t" "$ROOT" "$CHAIN" \
	    "$HOST"
	checkpass "sub-domain match" 0 "$s" "$m" "$t" "$ROOT" "$CHAIN" \
	    whatever ".$DOMAIN"
	checkfail "wrong name" 0 "$s" "$m" "$t" "$ROOT" "$CHAIN" \
	    "whatever"
	checkfail "null CA" 0 "$s" "$m" "$t" /dev/null "$CHAIN" "$HOST"
	checkfail "non-root CA" 0 "$s" "$m" "$t" "2.$HOST" "$CHAIN" \
	    "$HOST"
	checkfail "non-CA" 0 "$s" "$m" "$t" "0.$HOST" "$CHAIN" \
	    "$HOST"
	checkpass "depth 0 CA" 0 "$s" "$m" "$ss" "$ss" "$ss" "${HOST}" 
	checkfail "depth 0 CA namecheck" 2 "$s" "$m" "$ss" "$ss" "$ss" \
	    whatever
    done

    for tlsa in "1.${HOST}" "2.${HOST}"; do
	checkpass "valid TA" 2 "$s" "$m" "$tlsa" /dev/null "$CHAIN" \
	    "$HOST"
	checkpass "valid TA+CA" 2 "$s" "$m" "$tlsa" "$ROOT" "$CHAIN" \
	    "$HOST"
	checkpass "sub-domain match" 2 "$s" "$m" "$tlsa" /dev/null "$CHAIN" \
	    whatever ".$DOMAIN"
	checkfail "wrong name" 2 "$s" "$m" "$tlsa" /dev/null "$CHAIN" \
	    "whatever"
	checkfail "non-TA" 2 "$s" "$m" "0.$HOST" /dev/null "$CHAIN" \
	    "$HOST"
	checkpass "depth 0 TA" 2 "$s" "$m" "$ss" /dev/null "$ss" "${HOST}" 
	checkfail "depth 0 TA namecheck" 2 "$s" "$m" "$ss" /dev/null "$ss" \
	    whatever
    done

    checkpass "valid EE" 1 "$s" "$m" "0.$HOST" "$ROOT" "$CHAIN" "$HOST"
    checkpass "sub-domain match" 1 "$s" "$m" "0.$HOST" "$ROOT" "$CHAIN" \
    	whatever ".$DOMAIN"
    checkfail "wrong name" 1 "$s" "$m" "0.$HOST" "$ROOT" "$CHAIN" \
    	whatever
    checkfail "null CA" 1 "$s" "$m" "0.$HOST" /dev/null "$CHAIN" "$HOST"
    checkfail "non-root CA" 1 "$s" "$m" "0.$HOST" "2.$HOST" "$CHAIN" \
    	"$HOST"
    checkpass "depth 0 ss-CA EE" 1 "$s" "$m" "$ss" "$ss" "$ss" "${HOST}" 
    checkfail "depth 0 ss-CA EE namecheck" 1 "$s" "$m" "$ss" "$ss" "$ss" \
    	whatever

    checkpass "valid EE" 3 "$s" "$m" "0.$HOST" /dev/null "$CHAIN" whatever
    checkfail "wrong EE" 3 "$s" "$m" "1.$HOST" /dev/null "$CHAIN" whatever

done; done

rm "$ss.pem"
