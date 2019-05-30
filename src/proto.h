/* -*- c-basic-offset: 8 -*-
   rdesktop: A Remote Desktop Protocol client.
   Copyright (C) Matthew Chapman 1999-2008

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef RDESKTOP_PROTO_H
#define RDESKTOP_PROTO_H

/* *INDENT-OFF* */
#ifdef __cplusplus
extern "C" {
#endif
/* *INDENT-ON* */

/* channels.c */
VCHANNEL *channel_register(char *name, uint32 flags, void (*callback) (STREAM));
STREAM channel_init(VCHANNEL * channel, uint32 length);
void channel_send(STREAM s, VCHANNEL * channel);
void channel_process(STREAM s, uint16 mcs_channel);
/* cliprdr.c */
void cliprdr_send_simple_native_format_announce(uint32 format);
void cliprdr_send_native_format_announce(uint8 * formats_data, uint32 formats_data_length);
void cliprdr_send_data_request(uint32 format);
void cliprdr_send_data(uint8 * data, uint32 length);
void cliprdr_set_mode(const char *optarg);
RD_BOOL cliprdr_init(void);
/* ctrl.c */
int ctrl_init(const char *user, const char *domain, const char *host);
void ctrl_cleanup(void);
RD_BOOL ctrl_is_slave(void);
int ctrl_send_command(const char *cmd, const char *args);
//void ctrl_add_fds(int *n, fd_set * rfds);
//void ctrl_check_fds(fd_set * rfds, fd_set * wfds);

/* disk.c */
int disk_enum_devices(uint32 * id, char *optarg);
RD_NTSTATUS disk_query_information(RD_NTHANDLE handle, uint32 info_class, STREAM out);
RD_NTSTATUS disk_set_information(RD_NTHANDLE handle, uint32 info_class, STREAM in, STREAM out);
RD_NTSTATUS disk_check_notify(RD_NTHANDLE handle);
RD_NTSTATUS disk_create_notify(RD_NTHANDLE handle, uint32 info_class);
RD_NTSTATUS disk_query_volume_information(RD_NTHANDLE handle, uint32 info_class, STREAM out);
RD_NTSTATUS disk_query_directory(RD_NTHANDLE handle, uint32 info_class, char *pattern, STREAM out);
/* mppc.c */
int mppc_expand(uint8 * data, uint32 clen, uint8 ctype, uint32 * roff, uint32 * rlen);
/* ewmhints.c */
int get_current_workarea(uint32 * x, uint32 * y, uint32 * width, uint32 * height);
void ewmh_init(void);
/* iso.c */
STREAM iso_init(int length);
void iso_send(STREAM s);
STREAM iso_recv(uint8 * rdpver);
RD_BOOL iso_connect(char *server, char *username, char *domain, char *password, RD_BOOL reconnect,
		    uint32 * selected_protocol);
void iso_disconnect(void);
void iso_reset_state(void);
/* cssp.c */
RD_BOOL cssp_connect(char *server, char *user, char *domain, char *password, STREAM s);
/* licence.c */
void licence_process(STREAM s);
/* mcs.c */
STREAM mcs_init(int length);
void mcs_send_to_channel(STREAM s, uint16 channel);
void mcs_send(STREAM s);
STREAM mcs_recv(uint16 * channel, uint8 * rdpver);
RD_BOOL mcs_connect_start(char *server, char *username, char *domain, char *password,
			  RD_BOOL reconnect, uint32 * selected_protocol);
RD_BOOL mcs_connect_finalize(STREAM s);
void mcs_disconnect(void);
void mcs_reset_state(void);
/* orders.c */
void process_orders(STREAM s, uint16 num_orders);
void reset_order_state(void);
/* parallel.c */
int parallel_enum_devices(uint32 * id, char *optarg);
/* printer.c */
int printer_enum_devices(uint32 * id, char *optarg);
/* printercache.c */
int printercache_load_blob(char *printer_name, uint8 ** data);
void printercache_process(STREAM s);
/* pstcache.c */
void pstcache_touch_bitmap(uint8 cache_id, uint16 cache_idx, uint32 stamp);
RD_BOOL pstcache_load_bitmap(uint8 cache_id, uint16 cache_idx);
RD_BOOL pstcache_save_bitmap(uint8 cache_id, uint16 cache_idx, uint8 * key, uint8 width,
			     uint8 height, uint16 length, uint8 * data);
int pstcache_enumerate(uint8 id, HASH_KEY * keylist);
RD_BOOL pstcache_init(uint8 cache_id);
/* rdesktop.c */

//char *next_arg(char *src, char needle);
void toupper_str(char *p);
RD_BOOL str_startswith(const char *s, const char *prefix);
RD_BOOL str_handle_lines(const char *input, char **rest, str_handle_lines_t linehandler,
			 void *data);
RD_BOOL subprocess(char *const argv[], str_handle_lines_t linehandler, void *data);
char *l_to_a(long N, int base);
int load_licence(unsigned char **data);
void save_licence(unsigned char *data, int length);
void rd_create_ui(void);
RD_BOOL rd_pstcache_mkdir(void);
int rd_open_file(char *filename);
void rd_close_file(int fd);
int rd_read_file(int fd, void *ptr, int len);
int rd_write_file(int fd, void *ptr, int len);
int rd_lseek_file(int fd, int offset);
RD_BOOL rd_lock_file(int fd, int start, int len);
/* rdp5.c */
void rdp5_process(STREAM s);
/* rdp.c */
void rdp_out_unistr(STREAM s, char *string, int len);
void rdp_in_unistr(STREAM s, int in_len, char **string, uint32 * str_size);
void rdp_send_input(uint32 time, uint16 message_type, uint16 device_flags, uint16 param1,
		    uint16 param2);
void rdp_send_client_window_status(int status);
void process_colour_pointer_pdu(STREAM s);
void process_new_pointer_pdu(STREAM s);
void process_cached_pointer_pdu(STREAM s);
void process_system_pointer_pdu(STREAM s);
void process_bitmap_updates(STREAM s);
void process_palette(STREAM s);
void process_disconnect_pdu(STREAM s, uint32 * ext_disc_reason);
void rdp_main_loop(RD_BOOL * deactivated, uint32 * ext_disc_reason);
RD_BOOL rdp_loop(RD_BOOL * deactivated, uint32 * ext_disc_reason);
RD_BOOL rdp_connect(char *server, uint32 flags, char *domain, char *password, char *command,
		    char *directory, RD_BOOL reconnect);
void rdp_reset_state(void);
void rdp_disconnect(void);
/* rdpdr.c */
int get_device_index(RD_NTHANDLE handle);
void convert_to_unix_filename(char *filename);
void rdpdr_send_completion(uint32 device, uint32 id, uint32 status, uint32 result, uint8 * buffer,
			   uint32 length);
RD_BOOL rdpdr_init(void);
//void rdpdr_add_fds(int *n, fd_set * rfds, fd_set * wfds, struct timeval *tv, RD_BOOL * timeout);
struct async_iorequest *rdpdr_remove_iorequest(struct async_iorequest *prev,
					       struct async_iorequest *iorq);
//void rdpdr_check_fds(fd_set * rfds, fd_set * wfds, RD_BOOL timed_out);
RD_BOOL rdpdr_abort_io(uint32 fd, uint32 major, RD_NTSTATUS status);
/* rdpsnd.c */
void rdpsnd_record(const void *data, unsigned int size);
RD_BOOL rdpsnd_init(char *optarg);
void rdpsnd_show_help(void);
//void rdpsnd_add_fds(int *n, fd_set * rfds, fd_set * wfds, struct timeval *tv);
//void rdpsnd_check_fds(fd_set * rfds, fd_set * wfds);
struct audio_packet *rdpsnd_queue_current_packet(void);
RD_BOOL rdpsnd_queue_empty(void);
void rdpsnd_queue_next(unsigned long completed_in_us);
int rdpsnd_queue_next_tick(void);
void rdpsnd_reset_state(void);
/* secure.c */
void sec_hash_to_string(char *out, int out_size, uint8 * in, int in_size);
void sec_hash_sha1_16(uint8 * out, uint8 * in, uint8 * salt1);
void sec_hash_48(uint8 * out, uint8 * in, uint8 * salt1, uint8 * salt2, uint8 salt);
void sec_hash_16(uint8 * out, uint8 * in, uint8 * salt1, uint8 * salt2);
void buf_out_uint32(uint8 * buffer, uint32 value);
void sec_sign(uint8 * signature, int siglen, uint8 * session_key, int keylen, uint8 * data,
	      int datalen);
void sec_decrypt(uint8 * data, int length);
STREAM sec_init(uint32 flags, int maxlen);
void sec_send_to_channel(STREAM s, uint32 flags, uint16 channel);
void sec_send(STREAM s, uint32 flags);
void sec_process_mcs_data(STREAM s);
STREAM sec_recv(uint8 * rdpver);
RD_BOOL sec_connect(char *server, char *username, char *domain, char *password, RD_BOOL reconnect);
void sec_disconnect(void);
void sec_reset_state(void);
/* serial.c */
int serial_enum_devices(uint32 * id, char *optarg);
RD_BOOL serial_get_event(RD_NTHANDLE handle, uint32 * result);
RD_BOOL serial_get_timeout(RD_NTHANDLE handle, uint32 length, uint32 * timeout,
			   uint32 * itv_timeout);




/* *INDENT-OFF* */
#ifdef __cplusplus
}
#endif
/* *INDENT-ON* */

#endif
