#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_LEN 16

/* 
 * unsigned long strtoul(
 *      const char *restrict nptr,
 *      char **restrict endptr,
 *      int base
 * );
 */

int main(int argc, char *argv[]) {

    char *nptr, *endptr;
    int  base;
    unsigned long result;

    // Usage
    if(argc != 3) {
        printf("Usage: %s <string> <base>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Parse arguments (ensure fix string address)
    nptr = (char *) malloc(MAX_BUF_LEN * sizeof(char));
    strncpy(nptr, argv[1], MAX_BUF_LEN-1);
    nptr[MAX_BUF_LEN-1] = '\0';
    base = atoi(argv[2]);

    // Testing strtoul
    result = strtoul(nptr, &endptr, base);
    if(result < 10){
        printf("%lu <  10\n", result);
    } else {
        printf("%lu >= 10\n", result);
    }

    // Debug output
    printf("nptr    = %p: '%s'\n", nptr, nptr);
    printf("*endptr = %p: '%s'\n", endptr, endptr);
    printf("base    = %p: '%d'\n", &base, base);
    printf("result  = %p: '%lu'\n", &result, result);

    // Cleanup
    free(nptr);
    return EXIT_SUCCESS;
}