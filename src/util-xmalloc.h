#ifndef UTIL_XMALLOC_H
#define UTIL_XMALLOC_H
#include <stdio.h> /* size_t */

void *xmalloc(size_t size);
void exit_if_null(void *ptr);
char *xstrdup(const char *s);
void *xrealloc(void *oldmem, size_t size);
void xfree(void *mem);

#endif

