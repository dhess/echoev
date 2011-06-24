PLATFORM=-D ECHOEV_PLATFORM_MACOSX
#PLATFORM=-D ECHOEV_PLATFORM_LINUX
#PLATFORM=-D ECHOEV_PLATFORM_BSD

CC=gcc
INCLUDES=-I /usr/local/include
CFLAGS=-O2 -Wall -g $(INCLUDES) $(PLATFORM)

LD=gcc
LIBS=-L /usr/local/lib
LDFLAGS=$(LIBS) -g

all:	echoev

help:
	@echo "Targets:"
	@echo
	@echo "all - build echoev binary."
	@echo "help - this message."

echoev: logging.o echoev.o ringbuf.o
	$(LD) -o echoev $(LDFLAGS) -lev $^

logging.o: logging.c logging.h
	$(CC) $(CFLAGS) -c $< -o $@

ringbuf.o: ringbuf.c ringbuf.h
	$(CC) $(CFLAGS) -c $< -o $@

echoev.o: echoev.c logging.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f echoev *.o

.PHONY:	clean
