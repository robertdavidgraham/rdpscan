#include "util-log.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

int g_log_level = 1;
extern char g_targetaddr[];
extern char g_targetport[];

void
RESULT(const char *format, ...)
{
    va_list ap;
    
    if (format[0] == '[' && format[1] != '\0' && format[2] == ']' && format[3] == ' ') {
        fprintf(stdout, "[%c] ", format[1]);
        format += 4;
    }
    fprintf(stdout, "[%s]:%s - ", g_targetaddr, g_targetport);
    
    va_start(ap, format);
    vfprintf(stdout, format, ap);
    va_end(ap);
    
    exit(0);
}

void
STATUS(int lvl, const char *format, ...)
{
    va_list ap;
    
    if (lvl > g_log_level)
        return;
    
    if (format[0] == '[' && format[1] != '\0' && format[2] == ']' && format[3] == ' ') {
        fprintf(stderr, "[%c] ", format[1]);
        format += 4;
    }
    fprintf(stderr, "[%s]:%s - ", g_targetaddr, g_targetport);
    
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
}

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
hexdump(unsigned char *p, size_t len)
{
    unsigned char *line = p;
    size_t i, thisline;
    size_t offset = 0;
    
    while (offset < len)
    {
        printf("%04x ", (unsigned)offset);
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


