#! /bin/sh

set -e
cd $(dirname $0)/pems/
ROOT=eqfax
DOMAIN=gmail.com
HOST=imap.gmail.com

# Usage 0 tests:
#
for ca in "1.${HOST}" "2.${HOST}" "${ROOT}"
do
for m in 0 1 2
do
case $m in
0) d="";;
1) d=sha256;;
2) d=sha512;;
esac
for s in 0 1
do
    printf "%d %d %d %-24s valid CA: " 0 "${s}" "${m}" "${ca}"
    ../offline 0 "${s}" "${d}" "${ca}.pem" "${ROOT}.pem" "${HOST}.pem" \
	"${HOST}" > /dev/null &&
	{ echo pass; } ||
	{ echo fail; exit 1; }
done
done
done

# Usage 0 tests:
#
for ca in "1.${HOST}" "2.${HOST}" "${ROOT}"
do
for m in 0 1 2
do
case $m in
0) d="";;
1) d=sha256;;
2) d=sha512;;
esac
for s in 0 1
do
    printf "%d %d %d %-24s sub-domain match: " 0 "${s}" "${m}" "${ca}"
    ../offline 0 "${s}" "${d}" "${ca}.pem" "${ROOT}.pem" "${HOST}.pem" \
	whatever ".${DOMAIN}" > /dev/null &&
	{ echo pass; } ||
	{ echo fail; exit 1; }
done
done
done

# Usage 2 tests:
#
for ca in "1.${HOST}" "2.${HOST}"
do
for m in 0 1 2
do
case $m in
0) d="";;
1) d=sha256;;
2) d=sha512;;
esac
for s in 0 1
do
    printf "%d %d %d %-24s valid TA: " 2 "${s}" "${m}" ${ca}
    ../offline 2 "${s}" "${d}" "${ca}.pem" /dev/null "${HOST}.pem" \
	"${HOST}" > /dev/null &&
	{ echo pass; } ||
	{ echo fail; exit 1; }
done
done
done

# Usage 1 tests:
#
for ee in "0.${HOST}"
do
for m in 0 1 2
do
case $m in
0) d="";;
1) d=sha256;;
2) d=sha512;;
esac
for s in 0 1
do
    printf "%d %d %d %-24s valid EE: " 1 "${s}" "${m}" ${ca}
    ../offline 1 "${s}" "${d}" "${ee}.pem" "${ROOT}.pem" "${HOST}.pem" \
	"${HOST}" > /dev/null &&
	{ echo pass; } ||
	{ echo fail; exit 1; }
done
done
done

# Usage 3 tests:
#
for ee in "0.${HOST}"
do
for m in 0 1 2
do
case $m in
0) d="";;
1) d=sha256;;
2) d=sha512;;
esac
for s in 0 1
do
    printf "%d %d %d %-24s valid EE: " 3 "${s}" "${m}" ${ca}
    ../offline 3 "${s}" "${d}" "${ee}.pem" /dev/null "${HOST}.pem" \
	"whatever" >/dev/null &&
	{ echo pass; } ||
	{ echo fail; exit 1; }
done
done
done

#---   Should fail!

# Usage 0 tests:
#
for ca in "1.${HOST}" "2.${HOST}" "${ROOT}"
do
for m in 0 1 2
do
case $m in
0) d="";;
1) d=sha256;;
2) d=sha512;;
esac
for s in 0 1
do
    printf "%d %d %d %-24s null CAfile: " 0 "${s}" "${m}" ${ca}
    ../offline 0 "${s}" "${d}" "${ca}.pem" /dev/null "${HOST}.pem" \
	"${HOST}" > /dev/null &&
	{ echo fail; exit 1; } ||
	echo pass
done
done
done

# Usage 0 tests:
#
for ca in "1.${HOST}" "2.${HOST}" "${ROOT}"
do
for m in 0 1 2
do
case $m in
0) d="";;
1) d=sha256;;
2) d=sha512;;
esac
for s in 0 1
do
    printf "%d %d %d %-24s non-root CAfile: " 0 "${s}" "${m}" ${ca}
    ../offline 0 "${s}" "${d}" "${ca}.pem" "2.{$HOST}.pem" "${HOST}.pem" \
	"${HOST}" > /dev/null &&
	{ echo fail; exit 1; } ||
	echo pass
done
done
done

# Usage 0 tests:
#
for ca in "1.${HOST}" "2.${HOST}" "${ROOT}"
do
for m in 0 1 2
do
case $m in
0) d="";;
1) d=sha256;;
2) d=sha512;;
esac
for s in 0 1
do
    printf "%d %d %d %-24s wrong hostname: " 0 "${s}" "${m}" ${ca}
    ../offline 0 "${s}" "${d}" "${ca}.pem" "${ROOT}.pem" "${HOST}.pem" \
	"whatever" > /dev/null &&
	{ echo fail; exit 1; } ||
	echo pass
done
done
done

# Usage 0 tests:
#
for ca in "0.${HOST}"
do
for m in 0 1 2
do
case $m in
0) d="";;
1) d=sha256;;
2) d=sha512;;
esac
for s in 0 1
do
    printf "%d %d %d %-24s EE data: " 0 "${s}" "${m}" ${ca}
    ../offline 0 "${s}" "${d}" "${ca}.pem" "${ROOT}.pem" "${HOST}.pem" \
	"${HOST}" > /dev/null &&
	{ echo fail; exit 1; } ||
	echo pass
done
done
done
