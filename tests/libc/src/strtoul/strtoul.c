#include <stdlib.h>
#include <string.h>

#define BUF_LENGTH 8

int main() {
    char *nptr;
    char *endptr;

    // Buffer (will be symbolized)
    nptr = (char *) calloc(BUF_LENGTH, sizeof(char));

    // Testing strtoul
    if(strtoul(nptr, &endptr, 0) == 2) {
        return -1;
    }
    return 0;
}