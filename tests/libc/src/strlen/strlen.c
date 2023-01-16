#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_LENGTH 8

/*
 * size_t strlen(const char *s);
 */

int main(int argc, char *argv[]) {
    char *s;

    // Buffer (will be symbolised)
    s = (char *) calloc(BUF_LENGTH, sizeof(char));

    // Testing strlen
    if(strlen(s) == 2) {
        printf("strlen('%s') == 2\n", s);
        return EXIT_SUCCESS;
    }
    printf("strlen('%s') != 2\n", s);
    return EXIT_SUCCESS;
}