#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define HASH_LENGTH 4

void forward (char *hash);
void reverse (char *hash);
void hash    (char *src, char *dst);

static struct {
    void (*functions[2])(char *);
    char hash[HASH_LENGTH+1];
} icall;


int main(int argc, char *argv[]) {

    unsigned long idx = 0;

    icall.functions[0] = forward;
    icall.functions[1] = reverse;

    // Usage
    if(argc < 2 || argc == 3 || (argc > 3 && strcmp(argv[2], "-c") != 0)) {
        printf("Usage: %s <password> [-c <command>]\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Hash and validate password
    hash(argv[1], icall.hash);
    if(strncmp(icall.hash, "cannnot_be_equal", HASH_LENGTH) == 0) {
        if(setgid(getegid())) perror("setguid");
        if(setuid(geteuid())) perror("setuid");
        execl("/bin/sh", "bin/sh", (char *)NULL);
        return EXIT_SUCCESS;
    }

    // Print unauthorized message
    if(argc > 3) {
        idx = strtoul(argv[3], NULL, 10);
    }
    printf("[INVALID PASSWORD] Status Code: ");
    icall.functions[idx](icall.hash);
    return EXIT_SUCCESS;
}

void forward(char *hash) {
    int i;

    printf("F-ID-");
    for(i=0; i<HASH_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

void reverse(char *hash) {
    int i;

    printf("R-ID-");
    for(i=HASH_LENGTH-1; i>=0; i--) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

void hash(char *src, char *dst) {
    int i, j;

    for(i=0; i<HASH_LENGTH; i++) {
        dst[i] = 31 + (char)i;
        for(j=i; j<strlen(src); j+=4) {
            dst[i] ^= src[j] + (char)j;
            if(i > 1) dst[i] ^= dst[i-2];
        }
    }
    dst[HASH_LENGTH] = '\0';
}