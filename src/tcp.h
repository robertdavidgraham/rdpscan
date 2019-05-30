#ifndef RDESK_TCP_H
#define RDESK_TCP_H

#include "stream.h"
#include "types.h"

extern char g_targetaddr[];
extern char g_targetport[];

/* tcp.c */
STREAM tcp_init(uint32 maxlen);
void tcp_send(STREAM s);
STREAM tcp_recv(STREAM s, uint32 length);
RD_BOOL tcp_connect(char *server);
void tcp_disconnect(void);
char *tcp_get_address(void);
RD_BOOL tcp_is_connected(void);
void tcp_reset_state(void);
RD_BOOL tcp_tls_connect(void);
RD_BOOL tcp_tls_get_server_pubkey(STREAM s);
void tcp_run_ui(RD_BOOL run);

#endif

