PLATFORM=-D ECHOEV_PLATFORM_MACOSX
#PLATFORM=-D ECHOEV_PLATFORM_LINUX
#PLATFORM=-D ECHOEV_PLATFORM_BSD

CC=gcc
INCLUDES=-I /usr/local/include
CFLAGS=-O2 -Wall -Wno-strict-aliasing -g $(INCLUDES) $(PLATFORM)

LD=gcc
LIBS=-L /usr/local/lib
LDFLAGS=$(LIBS) -g

all:	echoev echoevc

help:
	@echo "Targets:"
	@echo
	@echo "all - build echoev binary."
	@echo "help - this message."

echoev: logging.o echoev.o ringbuf.o echo-common.o
	$(LD) -o echoev $(LDFLAGS) -lev $^

echoevc: logging.o echoevc.o ringbuf.o echo-common.o
	$(LD) -o echoevc $(LDFLAGS) -lev $^

echo-common.o: echo-common.c echo-common.h ringbuf.h
	$(CC) $(CFLAGS) -c $< -o $@

logging.o: logging.c logging.h
	$(CC) $(CFLAGS) -c $< -o $@

ringbuf.o: ringbuf.c ringbuf.h
	$(CC) $(CFLAGS) -c $< -o $@

echoev.o: echoev.c logging.h ringbuf.h echo-common.h
	$(CC) $(CFLAGS) -c $< -o $@

echoevc.o: echoevc.c logging.h ringbuf.h echo-common.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f echoev echoevc *.o

.PHONY:	clean
