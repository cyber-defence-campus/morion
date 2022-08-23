#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_LEN 16

/*
 * void *memcpy(
 *      void *restrict dest,
 *      const void *restrict src,
 *      size_t n
 * );
 */

int main(int argc, char *argv[]) {

    char  *dest, *src;
    size_t n;
    char  *result;

    // Usage
    if(argc != 3) {
        printf("Usage: %s <src> <n>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Parse arguments (ensure fix string address)
    dest = (char *) malloc(MAX_BUF_LEN * sizeof(char));
    src  = (char *) malloc(MAX_BUF_LEN * sizeof(char));
    strncpy(src, argv[1], MAX_BUF_LEN-1);
    src[MAX_BUF_LEN-1] = '\0';
    n = atoi(argv[2]);

    // Testing memcpy
    result = memcpy(dest, src, n);
    if(strlen(result) < 10){
        printf("strlen('%s') <  10\n", result);
    } else {
        printf("strlen('%s') >= 10\n", result);
    }
    
    return EXIT_SUCCESS;
}