/*
test crash app #2

div-by-zero

note: doesn't crash on mac, but exits code 160
*/

#include <stdio.h>

int main() {
    return 1 / 0;
}
