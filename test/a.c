/*
crash test app #1

null ptr deref
*/
#include <stdio.h>

int main() {
    *((int *)0) = 0;
    return 0;
}
