#
# Makefile for test crash apps (Windows)
#
# notes
# - no d-gui (gtk + pkg-config on win32 creates a ton of dependencies)
# - no e/f socket examples (although fuzzing network services on win32 is supported)
# - see event viewer -> windows logs -> application for Error logs (crashes)
#

CC = gcc
CFLAGS = -w

all: a b c

a: ../a.c
	$(CC) $(CFLAGS) -o a ../a.c

b: ../b.c
	$(CC) $(CFLAGS) -o b ../b.c

c: ../c.c
	$(CC) $(CFLAGS) -o c ../c.c

clean:
	del a.exe b.exe c.exe
