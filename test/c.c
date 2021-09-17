/*
crash test app #3

heap corruption

OS-specific notes to catch the crash

linux: LD_PRELOAD=/usr/lib/libefence.so ./c
mac: DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib ./c
windows: turn on pageheap
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char *buf = malloc(32);
    memset(buf, 'B', sizeof(buf) + 26);
	free(buf);
    return 0;
}
