#include <stdlib.h>
#include <string.h>

#define BUF_LENGTH 8

int main(int argc, char *argv[]) {
    char *dest;
    char *src;


    // Destination buffer
    dest = (char *) calloc(BUF_LENGTH, sizeof(char));

    // Source buffer (will be symbolized)
    src = (char *) calloc(BUF_LENGTH, sizeof(char));

    // Testing memcpy
    memcpy(dest, src, BUF_LENGTH);

    if(strlen(dest) == 2) {
        return -1;
    }
    return 0;
}