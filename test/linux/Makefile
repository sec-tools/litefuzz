#
# Makefile for test crash apps (Linux)
#

CC = gcc
CFLAGS = -w # -fsanitize=address
GTKFLAGS = `pkg-config --cflags --libs gtk+-3.0`

all: a b c d-gui e f

a: ../a.c
	$(CC) $(CFLAGS) -o a ../a.c

b: ../b.c
	$(CC) $(CFLAGS) -o b ../b.c

c: ../c.c
	$(CC) $(CFLAGS) -o c ../c.c

d-gui: ../d-gui.c
	$(CC) $(CFLAGS) -o d-gui ../d-gui.c $(GTKFLAGS)

e: ../e.c
	$(CC) $(CFLAGS) -o e ../e.c

f: ../f.c
	$(CC) $(CFLAGS) -o f ../f.c

clean:
	rm a b c d-gui e f
