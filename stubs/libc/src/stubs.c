#include <stddef.h>

size_t strlen(const char* s) {
    register const char* p;
    for(p=s; *p; p++);
    return p-s;
}