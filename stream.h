#ifndef STREAM_H
#define STREAM_H

/* Parser state */
typedef struct stream
{
    unsigned char *p;
    unsigned char *end;
    unsigned char *data;
    unsigned int size;
    
    /* Offsets of various headers */
    unsigned char *iso_hdr;
    unsigned char *mcs_hdr;
    unsigned char *sec_hdr;
    unsigned char *rdp_hdr;
    unsigned char *channel_hdr;
    
} *STREAM;

#endif

