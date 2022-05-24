#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define BUF_LENGTH 8

int main() {
    char *nptr;
    char *endptr;
    unsigned long ret;

    // Buffer (will be symbolized)
    nptr = (char *) calloc(BUF_LENGTH, sizeof(char));

    // Testing strtoul
    ret = strtoul(nptr, &endptr, 0);
    printf("nptr    = %p: '%s'\n", nptr, nptr);
    printf("*endptr = %p: '%s'\n", endptr, endptr);
    printf("ret     = %lu\n", ret);
    if(ret == 2) {
        return -1;
    }
    return 0;
}