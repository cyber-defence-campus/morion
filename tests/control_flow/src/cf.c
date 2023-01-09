#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_LEN 16

int main(int argc, char *argv[]) {

    char  *buf;
    size_t n, len;

    // Usage
    if(argc != 3) {
        printf("Usage: %s <buf> <n>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Parse arguments (ensure fix string address)
    buf  = (char *) malloc(MAX_BUF_LEN * sizeof(char));
    strncpy(buf, argv[1], MAX_BUF_LEN-1);
    buf[MAX_BUF_LEN-1] = '\0';
    n = atoi(argv[2]);

    // Start symbolic analysis from here
    // Make `buf` and integer `n` symbolic

    // Testring branches
    if(n > 0) {
        printf("[+] Branch 1 (n>0)\n");
        len = strlen(buf);
        // Nested branch
        if(len > MAX_BUF_LEN/2) {
            printf("[+] Branch 2 (n>0 && len>8)\n");
            len = MAX_BUF_LEN;
        } else {
            printf("[-] Branch 2 (n>0 && len<=8)\n");
        }
        // Loop
        for(size_t i=0; i<n; i++) {
            printf("[+] Branch 3 (n>0 && i<n)\n");
            // Branch dependent on loop variable
            if(i == n-2) {
                printf("[+] Branch 4 (n>0 && i==n-2)\n");
            } else {
                printf("[-] Branch 4 (n>0 && i!=n-2)\n");
            }
            // Non-reachable branch
            if(i > MAX_BUF_LEN) {
                printf("[+] Branch 5 (n>0 && i>8)\n");
            } else {
                printf("[-] Branch 5 (n>0 && i<=8)\n");
            }
        }
        printf("[-] Branch 3 (n>0 && i>=0)\n");
    } else {
        printf("[-] Branch 1 (n<=0)\n");
    }

    return EXIT_SUCCESS;
}