#include "util-xmalloc.h"
#include "util-log.h"
#include <stdlib.h>
#include <string.h>

#ifndef EX_UNAVAILABLE
#define EX_UNAVAILABLE (69)
#endif

void *
xmalloc(size_t size)
{
    void *mem = malloc(size);
    if (mem == NULL)
    {
        error("xmalloc %d\n", size);
        exit(EX_UNAVAILABLE);
    }
    return mem;
}

/* Exit on NULL pointer. Use to verify result from XGetImage etc */
void
exit_if_null(void *ptr)
{
    if (ptr == NULL)
    {
        error("unexpected null pointer. Out of memory?\n");
        exit(EX_UNAVAILABLE);
    }
}

/* strdup */
char *
xstrdup(const char *s)
{
    char *mem;
#ifdef _WIN32
#define strdup(x) _strdup(x)
#endif
    mem = strdup(s);
    if (mem == NULL)
    {
        perror("strdup");
        exit(EX_UNAVAILABLE);
    }
    return mem;
}

/* realloc; exit if out of memory */
void *
xrealloc(void *oldmem, size_t size)
{
    void *mem;
    
    if (size == 0)
        size = 1;
    mem = realloc(oldmem, size);
    if (mem == NULL)
    {
        error("xrealloc %ld\n", size);
        exit(EX_UNAVAILABLE);
    }
    return mem;
}

/* free */
void
xfree(void *mem)
{
    free(mem);
}
