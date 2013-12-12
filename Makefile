CFLAGS	= -Wall -Werror -g
LDFLAGS	= -lssl -lcrypto

PROG1	= connected
PROG2 	= offline
OBJS	= ssl_dane.o

all: ${PROG1} ${PROG2}

${PROG1}: ${PROG1}.o ${OBJS}
	$(CC) -o $@ ${PROG1}.o ${OBJS} ${LDFLAGS}

${PROG2}: ${PROG2}.o ${OBJS}
	$(CC) -o $@ ${PROG2}.o ${OBJS} ${LDFLAGS}

clean:
	$(RM) ${PROG1} ${PROG2} *.o
