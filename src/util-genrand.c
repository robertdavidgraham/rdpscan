#define _CRT_SECURE_NO_WARNINGS 1
#include "util-genrand.h"
#include <stdio.h>

/* Generate a 32-byte random for the secure transport code. */
void
generate_random(unsigned char * random)
{
    FILE *fp;
    
    /* If we have a kernel random device, try that first */
    fp = fopen("/dev/urandom", "rb");
    if (fp == NULL)
        fp = fopen("/dev/random", "rb");
    if (fp != NULL) {
        size_t n = fread(random, 1, 32, fp);
        fclose(fp);
        if (n == 32)
            return;
    }
}

