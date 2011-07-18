PLATFORM=-D ECHOEV_PLATFORM_MACOSX
#PLATFORM=-D ECHOEV_PLATFORM_LINUX
#PLATFORM=-D ECHOEV_PLATFORM_BSD

CC=gcc
INCLUDES=-I /usr/local/include
CFLAGS=-O2 -Wall -g $(INCLUDES) $(PLATFORM)

LD=gcc
LIBS=-L /usr/local/lib
LDFLAGS=$(LIBS) -g

all:	echoev echoevc

help:
	@echo "Targets:"
	@echo
	@echo "all - build echoev binary."
	@echo "help - this message."

echoev: logging.o echoev.o ringbuf.o
	$(LD) -o echoev $(LDFLAGS) -lev $^

echoevc: logging.o echoevc.o ringbuf.o
	$(LD) -o echoevc $(LDFLAGS) -lev $^

logging.o: logging.c logging.h
	$(CC) $(CFLAGS) -c $< -o $@

ringbuf.o: ringbuf.c ringbuf.h
	$(CC) $(CFLAGS) -c $< -o $@

echoev.o: echoev.c logging.h
	$(CC) $(CFLAGS) -c $< -o $@

echoevc.o: echoevc.c logging.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f echoev echoevc *.o

.PHONY:	clean
