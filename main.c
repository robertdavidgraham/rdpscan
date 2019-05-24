//struct stream {int x;}
#include "rdesktop.h"
#include "orders.h"
#include "mst120.h"
#include "tcp.h"


uint8 g_static_rdesktop_salt_16[16] = {
    0xb8, 0x82, 0x29, 0x31, 0xc5, 0x39, 0xd9, 0x44,
    0x54, 0x15, 0x5e, 0x14, 0x71, 0x38, 0xd5, 0x4d
};

//char g_title[64] = "";
char g_password[64] = "";
char g_hostname[16] = "";
char g_keymapname[PATH_MAX] = "";
unsigned int g_keylayout = 0x409;    /* Defaults to US keyboard layout */
int g_keyboard_type = 0x4;    /* Defaults to US keyboard layout */
int g_keyboard_subtype = 0x0;    /* Defaults to US keyboard layout */
int g_keyboard_functionkeys = 0xc;    /* Defaults to US keyboard layout */
int g_sizeopt = 0;        /* If non-zero, a special size has been
                           requested. If 1, the geometry will be fetched
                           from _NET_WORKAREA. If negative, absolute value
                           specifies the percent of the whole screen. */
int g_width = 800;
int g_height = 600;
int g_xpos = 0;
int g_ypos = 0;
int g_pos = 0;            /* 0 position unspecified,
                           1 specified,
                           2 xpos neg,
                           4 ypos neg  */
extern int g_tcp_port_rdp;
int g_server_depth = -1;
int g_win_button_size = 0;    /* If zero, disable single app mode */
RD_BOOL g_network_error = False;
RD_BOOL g_bitmap_compression = True;
RD_BOOL g_sendmotion = True;
RD_BOOL g_bitmap_cache = True;
RD_BOOL g_bitmap_cache_persist_enable = False;
RD_BOOL g_bitmap_cache_precache = True;
RD_BOOL g_use_ctrl = True;
RD_BOOL g_encryption = True;
RD_BOOL g_encryption_initial = True;
RD_BOOL g_packet_encryption = True;
RD_BOOL g_desktop_save = True;    /* desktop save order */
RD_BOOL g_polygon_ellipse_orders = True;    /* polygon / ellipse orders */
RD_BOOL g_fullscreen = False;
RD_BOOL g_grab_keyboard = True;
RD_BOOL g_hide_decorations = False;
RDP_VERSION g_rdp_version = RDP_V5;    /* Default to version 5 */
RD_BOOL g_rdpclip = True;
RD_BOOL g_console_session = False;
RD_BOOL g_numlock_sync = False;
RD_BOOL g_lspci_enabled = False;
RD_BOOL g_owncolmap = False;
RD_BOOL g_ownbackstore = True;    /* We can't rely on external BackingStore */
RD_BOOL g_seamless_rdp = False;
RD_BOOL g_use_password_as_pin = False;
char g_seamless_shell[512];
char g_seamless_spawn_cmd[512];
RD_BOOL g_seamless_persistent_mode = True;
RD_BOOL g_user_quit = False;
uint32 g_embed_wnd;
uint32 g_rdp5_performanceflags =
RDP5_NO_WALLPAPER | RDP5_NO_FULLWINDOWDRAG | RDP5_NO_MENUANIMATIONS | RDP5_NO_CURSOR_SHADOW;
/* Session Directory redirection */
RD_BOOL g_redirect = False;
char *g_redirect_server;
uint32 g_redirect_server_len;
char *g_redirect_domain;
uint32 g_redirect_domain_len;
char *g_redirect_username;
uint32 g_redirect_username_len;
uint8 *g_redirect_lb_info;
uint32 g_redirect_lb_info_len;
uint8 *g_redirect_cookie;
uint32 g_redirect_cookie_len;
uint32 g_redirect_flags = 0;
uint32 g_redirect_session_id = 0;

uint32 g_reconnect_logonid = 0;
char g_reconnect_random[16];
time_t g_reconnect_random_ts;
RD_BOOL g_has_reconnect_random = False;
RD_BOOL g_reconnect_loop = False;
uint8 g_client_random[SEC_RANDOM_SIZE];
RD_BOOL g_pending_resize = False;

#ifdef WITH_RDPSND
RD_BOOL g_rdpsnd = False;
#endif

#ifdef HAVE_ICONV
char g_codepage[16] = "";
#endif

char *g_sc_csp_name = NULL;    /* Smartcard CSP name  */
char *g_sc_reader_name = NULL;
char *g_sc_card_name = NULL;
char *g_sc_container_name = NULL;

extern RDPDR_DEVICE g_rdpdr_device[];
extern uint32 g_num_devices;
extern char *g_rdpdr_clientname;

int
load_licence(unsigned char **data)
{
    return 0;
}


void
save_licence(unsigned char *data, int length)
{

}



/* My custom globals */
char *g_username = "rdpscan";

int main(int argc, char *argv[])
{
    unsigned flags = 0;
    char domain[32] = "";
    char shell[32] = "";
    char directory[32] = "";
    RD_BOOL g_reconnect_loop = False;
    int i;
    
    flags = RDP_INFO_MOUSE | RDP_INFO_DISABLECTRLALTDEL
     | RDP_INFO_UNICODE | RDP_INFO_MAXIMIZESHELL | RDP_INFO_ENABLEWINDOWSKEY;
    
    if (argc <= 1) {
        fprintf(stderr, "Usage:\n rdpscan <target>\n");
        return 1;
    }
    
    if (!mst120_check_init())
    {
        printf("[-] Failed to initialize MS_T120 channel!\n");
    }

    for (i=1; i<argc; i++) {
        int err;
        char *server = argv[i];
        
        err = rdp_connect(server,
                          flags,
                          domain,
                          g_password,
                          shell,
                          directory,
                          g_reconnect_loop);
        
        /* By setting encryption to False here, we have an encrypted login
         packet but unencrypted transfer of other packets */
        if (!g_packet_encryption)
            g_encryption_initial = g_encryption = False;
        
        DEBUG(("Connection successful.\n"));
        
        //rd_create_ui();
        tcp_run_ui(True);
        
        {
            RD_BOOL deactivated = False;
            unsigned ext_disc_reason = 0;
            g_reconnect_loop = False;
            rdp_main_loop(&deactivated, &ext_disc_reason);
        }
        
        tcp_run_ui(False);
        
        DEBUG(("Disconnecting...\n"));
        rdp_disconnect();

    }
    
    return 0;
}
