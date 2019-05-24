#include "util-time.h"

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>

unsigned long long
util_nanotime(void)
{
    unsigned long long time1 = 0, freq = 0;
    double seconds;
    QueryPerformanceCounter((LARGE_INTEGER *) &time1);
    QueryPerformanceFrequency((LARGE_INTEGER *)&freq);
    seconds = (double)time1/(double)freq;
    return (unsigned long long)(seconds * 1000000000.0);
}

#else
#include <time.h>

unsigned long long
util_nanotime(void)
{
    int x;
    struct timespec tv;

#ifdef CLOCK_MONOTONIC_RAW
    x = clock_gettime(CLOCK_MONOTONIC_RAW, &tv);
#else
    x = clock_gettime(CLOCK_MONOTONIC, &tv);
#endif
    if (x != 0) {
        ;//printf("clock_gettime() err %d\n", errno);
    }

    return tv.tv_sec * 1000000000 + tv.tv_nsec;
}

#endif
