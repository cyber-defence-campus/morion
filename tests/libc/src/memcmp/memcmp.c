#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_LEN 16

/*
 * int memcmp(
 *      const void *s1,
 *      const void *s2,
 *      size_t n
 * );
 */

int main(int argc, char *argv[]) {

    char  *s1, *s2;
    size_t n;
    int result;

    // Usage
    if(argc != 4) {
        printf("Usage: %s <s1> <s2> <n>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Parse arguments (ensure fix string address)
    s1 = (char *) malloc(MAX_BUF_LEN * sizeof(char));
    strncpy(s1, argv[1], MAX_BUF_LEN-1);
    s1[MAX_BUF_LEN-1] = '\0';
    s2 = (char *) malloc(MAX_BUF_LEN * sizeof(char));
    strncpy(s2, argv[2], MAX_BUF_LEN-1);
    s2[MAX_BUF_LEN-1] = '\0';
    n = atoi(argv[3]);

    // Testing memcmp
    result = memcmp(s1, s2, n);
    if(result < 0) {
        printf("memcmp('%s', '%s', '%d') <  0\n", s1, s2, n);
        printf("result = %d\n", result);
    } else if(result > 0) {
        printf("memcmp('%s', '%s', '%d') >  0\n", s1, s2, n);
        printf("result = %d\n", result);
    } else {
        printf("memcmp('%s', '%s', '%d') == 0\n", s1, s2, n);
        printf("result = %d\n", result);
    }
    
    return EXIT_SUCCESS;
}