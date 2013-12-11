CFLAGS	= -Wall -Werror -g
LDFLAGS	= -lssl -lcrypto

PROG=ssl_dane_test
OBJS=ssl_dane_test.o ssl_dane.o

all: ${PROG}

${PROG}: ${OBJS}
	$(CC) -o $@ ${OBJS} ${LDFLAGS}

clean:
	$(RM) ${PROG} ${OBJS}
