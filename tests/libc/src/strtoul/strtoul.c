#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define BUF_LENGTH 8

int main() {
    char *nptr;
    char *endptr;
    const int base = 10;
    unsigned long ret;

    // Buffer (will be symbolized)
    nptr = (char *) calloc(BUF_LENGTH, sizeof(char));

    // Testing strtoul
    ret = strtoul(nptr, &endptr, base);
    printf("nptr    = %p: '%s'\n", nptr, nptr);
    printf("*endptr = %p: '%s'\n", endptr, endptr);
    printf("ret     = %lu\n", ret);
    if(ret == 22) {
        return -1;
    }
    return 0;
}