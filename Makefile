CFLAGS	= -g -I/opt/local/include
LDFLAGS	= -L/opt/local/lib -lssl -lcrypto

PROG=ssl_dane_test
OBJS=ssl_dane_test.o ssl_dane.o

all: ${PROG}

${PROG}: ${OBJS}
	$(CC) -o $@ ${OBJS} ${LDFLAGS}

clean:
	$(RM) ${PROG} ${OBJS}
