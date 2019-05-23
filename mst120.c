#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "rdesktop.h"

#define MST120_SEND_MAX 5
#define MST120_TIMEOUT 5  // in seconds

static VCHANNEL *mst120_channel;
static int check_count;
static int first_check;

static void
mst120_process(STREAM s)
{
    // pass
}

RD_BOOL
mst120_check_init()
{
    //printf("[+] Registering MS_T120 channel.\n");

    check_count = 0;
    first_check = 0;

    mst120_channel = channel_register("MS_T120",
      CHANNEL_OPTION_INITIALIZED | CHANNEL_OPTION_COMPRESS_RDP,
      mst120_process);

    return (mst120_channel != NULL);
}

void
mst120_send_check_packet(size_t size, size_t offset)
{
    printf("[+] Sending MS_T120 check packet (size: 0x%lx - offset: 0x%lx)\n", size, offset);

    char *buff = (char*)malloc(size);

    if (!buff)
        return;

    memset(buff, 0, size);

    buff[offset] = 2;

    STREAM s = channel_init(mst120_channel, (unsigned)size);
    out_uint8p(s, buff, size);
    s_mark_end(s);
    channel_send(s, mst120_channel);

    free(buff);
}

void
mst120_check()
{
    if (check_count > MST120_SEND_MAX)
    {
        printf("[-] Max sends reached, please wait for race condition to be sure...\n");
        while (1)
        {
            int now = time(0);

            if (first_check == 0)
            {
                first_check = now;
            }
            else
            {
                if ((now - first_check) > MST120_TIMEOUT)
                {
                    printf("[*] Target appears patched.\n");
                    exit(0);
                }
            }
        }
        return;
    }

    ++check_count;
    mst120_send_check_packet(0x20, 8);
    mst120_send_check_packet(0x10, 4);
}
