#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_LEN 128

/*
 * Trigger Segmentation Fault
 * ./strcpy `python3 -c 'print("A"*132)'`
 */

void vuln_func(char *s) {
    char buf[BUF_LEN];
    strcpy(buf, s);
    puts(buf);
}

int main(int argc, char *argv[]) {

    // Usage
    if(argc != 2) {
        printf("Usage: %s <string>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Call vulnerable function
    vuln_func(argv[1]);

    return EXIT_SUCCESS;
}