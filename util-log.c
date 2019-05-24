#include "util-log.h"
#include <stdarg.h>
#include <stdio.h>

/* report an error */
void
error(char *format, ...)
{
    va_list ap;
    
    fprintf(stderr, "[-] ");
    
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
}

/* report a warning */
void
warning(char *format, ...)
{
    va_list ap;
    
    fprintf(stderr, "[ ] ");
    
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
}

/* report an unimplemented protocol feature */
void
unimpl(char *format, ...)
{
    va_list ap;
    
    fprintf(stderr, "[-] NOT IMPLEMENTED: ");
    
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
}

/* produce a hex dump */
void
hexdump(unsigned char *p, unsigned int len)
{
    unsigned char *line = p;
    int i, thisline, offset = 0;
    
    while (offset < len)
    {
        printf("%04x ", offset);
        thisline = len - offset;
        if (thisline > 16)
            thisline = 16;
        
        for (i = 0; i < thisline; i++)
            printf("%02x ", line[i]);
        
        for (; i < 16; i++)
            printf("   ");
        
        for (i = 0; i < thisline; i++)
            printf("%c", (line[i] >= 0x20 && line[i] < 0x7f) ? line[i] : '.');
        
        printf("\n");
        offset += thisline;
        line += thisline;
    }
}


