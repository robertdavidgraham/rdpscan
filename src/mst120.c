#include "rdesktop.h"
#include "util-xmalloc.h"
#include "util-log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#define MST120_SEND_MAX 5
const unsigned MST120_TIMEOUT = 6;  // in seconds

static VCHANNEL *mst120_channel;
static int g_check_count;
time_t g_first_check;

static void
mst120_process(STREAM s)
{
    // pass
}

RD_BOOL
mst120_check_init()
{
    //printf("[+] Registering MS_T120 channel.\n");

    g_check_count = 0;
    g_first_check = 0;

    mst120_channel = channel_register("MS_T120",
      CHANNEL_OPTION_INITIALIZED | CHANNEL_OPTION_COMPRESS_RDP,
      mst120_process);

    return (mst120_channel != NULL);
}

void
mst120_send_check_packet(size_t size, size_t offset)
{
    char *buff = xmalloc(size);
    STREAM s;
    static int is_printed = 0;
    
    if (is_printed++ == 0)
    {
        STATUS(1, "[+] Sending MS_T120 check packet\n");
    }
    else
    {
        STATUS(4, "[+] Sending MS_T120 check packet (size: 0x%lx - offset: 0x%lx)\n",
               size, offset);
    }

    memset(buff, 0, size);

    buff[offset] = 2;

    s = channel_init(mst120_channel, (unsigned)size);
    out_uint8p(s, buff, size);
    s_mark_end(s);
    channel_send(s, mst120_channel);

    xfree(buff);
}

void
mst120_check(int is_send)
{
    if (g_check_count > MST120_SEND_MAX)
    {
        static int is_printed = 0;
        if (is_printed++ == 0)
            STATUS(1, "[-] Max sends reached, waiting...\n");
        
        if (g_first_check == 0)
            g_first_check = time(0);
        
        if ((time(0) - g_first_check) > MST120_TIMEOUT)
        {
            RESULT("SAFE - Target appears patched\n");
            exit(0);
        }
        return;
    }

    if (is_send)
    {
        ++g_check_count;
        mst120_send_check_packet(0x20, 8);
        mst120_send_check_packet(0x10, 4);
    }
}
