#ifndef UTIL_LOG_H
#define UTIL_LOG_H

void error(char *format, ...);
void warning(char *format, ...);
void unimpl(char *format, ...);
void hexdump(unsigned char *p, unsigned int len);

#endif

