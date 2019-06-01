#include "util-time.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>

unsigned long long
util_microtime(void)
{
    unsigned long long time1 = 0, freq = 0;
    double seconds;
    QueryPerformanceCounter((LARGE_INTEGER *) &time1);
    QueryPerformanceFrequency((LARGE_INTEGER *)&freq);
    seconds = (double)time1/(double)freq;
    return (unsigned long long)(seconds * 1000000.0);
}

#else
#include <time.h>
#include <sys/time.h>

unsigned long long
util_microtime(void)
{
    int x;
    struct timeval tv;

    x = gettimeofday(&tv, 0);
    if (x != 0) {
        ;//printf("clock_gettime() err %d\n", errno);
    }

    return tv.tv_sec * 1000000ULL + tv.tv_usec;
}

#endif
