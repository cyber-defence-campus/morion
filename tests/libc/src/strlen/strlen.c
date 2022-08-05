#include <stdlib.h>
#include <string.h>

#define BUF_LENGTH 8

int main() {
    char *s;

    // Buffer (will be symbolised)
    s = (char *) calloc(BUF_LENGTH, sizeof(char));

    // Testing strlen
    if(strlen(s) == 2) {
        return -1;
    }
    return 0;
}