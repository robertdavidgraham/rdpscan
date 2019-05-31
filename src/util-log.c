#define _CRT_SECURE_NO_WARNINGS 1
#include "util-log.h"
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#ifdef WIN32
#include <malloc.h> /* alloca() */
#define snprintf _snprintf
#endif

int g_log_level = 0;
extern char g_targetaddr[];
extern char g_targetport[];

void
RESULT(const char *format, ...)
{
    va_list ap;
    char *newfmt;
    int newfmt_length;
    int x;
    char datetime[128];
    time_t now = time(0);
    struct tm *tm = NULL;
    extern int g_is_gmtime;
    extern int g_is_localtime;


    if (g_is_gmtime) {
        tm = gmtime(&now);
    } else if (g_is_localtime)
        tm = localtime(&now);

    if (tm)
        strftime(datetime, sizeof(datetime), "%Y-%m-%d %H:%M:%S - ", tm);
    else
        datetime[0] = '\0';
    
    /* We want a single atomic write, due to multiple processes trying
     * to write output at the same time. Therefore, instead of multiple
     * fprintf() statements, we are going to combine into a single
     * statement. This means creating a new format string. */
    newfmt_length = 14+1; /* strlen("[-] []: - ") */
    newfmt_length += (int)strlen(g_targetaddr);
    newfmt_length += (int)strlen(format);
    newfmt_length += (int)strlen(datetime);
    
    /* Kludge: format string attack protection */
    {
        size_t i;
        for (i=0; g_targetaddr[i]; i++) {
            if (g_targetaddr[i] == '%')
                g_targetaddr[i] = ' ';
        }
    }
    
    /* Create the new format string */
    newfmt = alloca(newfmt_length);
    x = snprintf(newfmt, newfmt_length, "%s%s - %s", datetime, g_targetaddr, format);
    
    /* Now do the single atomi print */
    va_start(ap, format);
    vfprintf(stdout, newfmt, ap);
    va_end(ap);

    exit(0);
}

static void
vSTATUS(int lvl, char plus, const char *format, va_list ap)
{
    char *newfmt;
    int newfmt_length;
    int x;
    
    /* Only print messages that are at the current diag-level or lower.
     * Thus, higher settings of the diagnostics level will create more
     * verbose output */
    if (lvl > g_log_level)
        return;
    
    /* We are going to print a status indicator of [+], [-], or [ ]
     * for all output, even if the caller didn't specify one */
    if (format[0] == '[' && format[1] != '\0' && format[2] == ']' && format[3] == ' ') {
        plus = format[1];
        if (plus == '%')
            plus = '*';
        format += 4;
    }
    
    /* We want a single atomic write, due to multiple processes trying
     * to write output at the same time. Therefore, instead of multiple
     * fprintf() statements, we are going to combine into a single
     * statement. This means creating a new format string. */
    newfmt_length = 14+1; /* strlen("[-] []: - ") */
    newfmt_length += (int)strlen(g_targetaddr);
    newfmt_length += (int)strlen(g_targetport);
    newfmt_length += (int)strlen(format);
    
    /* Kludge: format string attack protection */
    {
        size_t i;
        for (i=0; g_targetaddr[i]; i++) {
            if (g_targetaddr[i] == '%')
                g_targetaddr[i] = ' ';
        }
        for (i=0; g_targetport[i]; i++) {
            if (g_targetaddr[i] == '%')
                g_targetaddr[i] = ' ';
        }
    }
    
    /* Create the new format string */
    newfmt = alloca(newfmt_length);
    x = snprintf(newfmt, newfmt_length, "[%c] [%s]:%s - %s", plus, g_targetaddr, g_targetport, format);
    
    /* Now do the single atomi print */
    vfprintf(stderr, newfmt, ap);
    fflush(stderr);
}

void
STATUS(int lvl, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    vSTATUS(lvl, ' ', format, ap);
    va_end(ap);
}

/* report an error */
void
error(char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    vSTATUS(0, '-', format, ap);
    va_end(ap);
}

/* report a warning */
void
warning(char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    vSTATUS(1, ' ', format, ap);
    va_end(ap);
}

/* report an unimplemented protocol feature */
void
unimpl(char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    vSTATUS(1, '#', format, ap);
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


