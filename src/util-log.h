#ifndef UTIL_LOG_H
#define UTIL_LOG_H
#include <stdio.h>

void RESULT(const char *format, ...);

void STATUS(int lvl, const char *format, ...);
void error(char *format, ...);
void warning(char *format, ...);
void unimpl(char *format, ...);
void hexdump(unsigned char *p, size_t len);

#endif

