PLATFORM=-D ECHOEV_PLATFORM_MACOSX
#PLATFORM=-D ECHOEV_PLATFORM_LINUX
#PLATFORM=-D ECHOEV_PLATFORM_BSD

CC=gcc
INCLUDES=-I /usr/local/include
CFLAGS=-O2 -Wall -g $(INCLUDES) $(PLATFORM)

LD=gcc
LIBS=-L /usr/local/lib
LDFLAGS=$(LIBS)

all:	echoev

help:
	@echo "Targets:"
	@echo
	@echo "all - build echoev binary."
	@echo "help - this message."

echoev: echoev.o
	$(LD) -o echoev $(LDFLAGS) -lev $<

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f echoev *.o

.PHONY:	clean
