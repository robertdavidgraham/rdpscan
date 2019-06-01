#define _CRT_SECURE_NO_WARNINGS 1
#include "rdesktop.h"
#include "orders.h"
#include "mst120.h"
#include "tcp.h"
#include "util-time.h"
#include "util-xmalloc.h"
#include "util-log.h"
#include "workers.h"
#include "ranges.h"         /* from masscan */
#include "rand-blackrock.h" /* from masscan */
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#ifdef WIN32
#define snprintf _snprintf
#endif

/* My custom globals */
char *g_username;
char g_hostname[16] = "rdpscan";
int g_result_quiet = 0;
int g_result_verbose = 0;

/* Whether or not we should print the date/time on resuls */
int g_is_gmtime = 0;
int g_is_localtime = 0;

/* Whether to enable CredSSP/NLA on the connection. By enabling
 * this, we can grab information about the domain on the other
 * side */
int g_is_credssp_enabled = 0;

/* Whether to enable SSL as an encrypted transport. The default
 * behavior is to enable it. */
int g_is_ssl_enabled = 1;

uint8 g_static_rdesktop_salt_16[16] = {
    0xb8, 0x82, 0x29, 0x31, 0xc5, 0x39, 0xd9, 0x44,
    0x54, 0x15, 0x5e, 0x14, 0x71, 0x38, 0xd5, 0x4d
};

//char g_title[64] = "";
char g_password[64] = "";
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


/**
 * Whether an address is a range of addresses. There are
 * two formats for ranges, two addresses separated by a
 * dash, or a CIDR spec. This is only a rough approx
 * and does not validate the address. It's primarily checking
 * that it's NOT a valid IPv4 address, IPv6 address, or
 * DNS name.
 */
static int
is_ipv4_range(const char *addr)
{
    size_t i;
    size_t count_dash = 0;
    size_t count_slash = 0;
    
    for (i=0; addr[i]; i++) {
        if (addr[i] == '-')
            count_dash++;
        else if (addr[i] == '/')
            count_slash++;
        else if (!isdigit(addr[i]) && addr[i] != '.')
            return 0;
    }
    
    if (count_dash == 0 && count_slash == 1)
        return 1;
    if (count_dash == 1 && count_slash == 0)
        return 1;
    
    return 0;
}


/**
 * Generate a random username on startup, because systems reject
 * repeated use of the same username
 */
static char *
randomize_username(void)
{
    unsigned long long x = util_microtime();
    size_t i;
    char *result;

    result = xmalloc(10);

    for (i=0; i<8 && x; i++, x /= 32) {
        static const char chars[] = "abcdfghijklmnopqrsuvwxyz0123456789";
        result[i] = chars[x % 32];
    }
    result[i] = '\0';
    return result;
}

struct command_line
{
    int debug_level;
    const char *list_filename;
    char **targets;
    size_t target_count;
    
    /** Maximum number of worker processes when scanning
     * multiple targets/ranges. Default is around 100. */
    int max_workers;
};


char *g_socks5_server = 0;
unsigned g_socks5_port = 9150;

/**
 * After a configuration parameter, this finds the next argument.
 * We allow arguments to either be combined or separate. In other
 * words, here are some examples:
 * --port 1234
 * --port=1234
 * --port:1234
 */
static char *
next_arg(int argc, char *argv[], int *index)
{
    char *arg = argv[*index];
    size_t len;
    
    /* Find the length of the named parameter */
    for (len=0; arg[len]; len++) {
        if (!isalnum(arg[len]) && arg[len] != '-' && arg[len] != '_')
            break;
    }
    if (arg[len] == ':' || arg[len] == '=')
        return arg + len + 1;
    if (arg[len] != '\0' || (*index) + 1 >= argc) {
        fprintf(stderr, "[-] %.*s: expected following parameter\n", (unsigned)len, arg);
        exit(1);
    }
    return argv[++(*index)];
}

/**
 * This matches the name of a double-dash input parameter,
 * like --port. It's a bit tricky because the name can
 * be combined with additional data, like "--port=1234".
 * Therefore, we have to match up to the first of several
 * possible terminators. Also, we allow the parameters to
 * be configured in either order.
 */
static int
MATCH(const char *lhs, const char *rhs)
{
    if (*lhs != '-')
        return 0;
    while (*lhs == '-')
        lhs++;
    while (*rhs == '-')
        rhs++;
    while (*rhs && *lhs && *rhs == *lhs) {
        rhs++;
        lhs++;
    }
    if (*rhs == '\0') {
        if (*lhs == '-')
            return 0;
        if (*lhs == '_')
            return 0;
        if (isalnum(*lhs))
            return 0;
        return 1;
    }
    if (*lhs == '\0') {
        if (*rhs == '-')
            return 0;
        if (*rhs == '_')
            return 0;
        if (isalnum(*rhs))
            return 0;
        return 1;
    }
    return 0;
}

/**
 * Print help on the command-line. This function will cause the program
 * to exit without returning. This can be riggered a number of ways:
 *  -?
 *  -h
 *  --help
 * (no command line parameters, argc==1)
 */
static void
print_help(void)
{
    fprintf(stderr, "---- https://github.com/robertdavidgraham/rdpscan ----\n");
    fprintf(stderr, "This program scans for the Microsoft Remote Desktop vuln CVE-2019-0708\n");
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, " rdpscan <addr> [<addr> ...]\n");
    fprintf(stderr, " rdpscan --file <filename>\n");
    fprintf(stderr, "This will scan for the addresses specified, either on the command-line\n");
    fprintf(stderr, "or from a file. Some additional parameters are:\n");
    fprintf(stderr, " -p <n> or --port <n>\n  The port number (default 3389)\n");
    fprintf(stderr, " -d or -dd or -ddd\n  Print diagnostic information to stderr\n");
    fprintf(stderr, " -q quiet, don't print result for non-existent systems (default=many addresses)\n");
    fprintf(stderr, " -v verbose, do print result for non-existent systems (default=single address)\n");
    exit(1);
}

void
set_parameter(struct command_line *cfg, int argc, char *argv[], int *index)
{
    char *arg = argv[*index];
    size_t len;
    
    /* Find the length of the named parameter */
    for (len=0; arg[len]; len++) {
        if (!isalnum(arg[len]) && arg[len] != '-' && arg[len] != '_')
            break;
    }
        
    if (MATCH("--list", arg) || MATCH("--file", arg)) {
        arg = next_arg(argc, argv, index);
        cfg->list_filename = xstrdup(arg);
    } else if (MATCH(arg, "--help")) {
        print_help();
    } else if (MATCH(arg, "--gmtime")) {
        g_is_gmtime = 1;
    } else if (MATCH(arg, "--localtime")) {
        g_is_localtime = 1;
    } else if (MATCH(arg, "--credssp")) {
        g_is_credssp_enabled = 1;
    } else if (MATCH(arg, "--nossl")) {
        g_is_ssl_enabled = 0;
    } else if (MATCH(arg, "--noencrypt")) {
        g_encryption_initial = False;
        g_encryption = False;
    } else if (MATCH(arg, "--socks5")) {
        arg = next_arg(argc, argv, index);
        g_socks5_server = xstrdup(arg);
    } else if (MATCH(arg, "--socks5port")) {
        arg = next_arg(argc, argv, index);
        g_socks5_port = atoi(arg);
    } else if (MATCH(arg, "--port")) {
        /* The port which we should scan on. If not specified, this will
         * be 3389, the defined RDP port. However, servers can be configured
         * for other ports instead */
        arg = next_arg(argc, argv, index);
        g_tcp_port_rdp = atoi(arg);
        if (g_tcp_port_rdp <= 0 || 65536 <= g_tcp_port_rdp) {
            fprintf(stderr, "[-] invalid port: %s\n", arg);
            exit(1);
        }
    } else if (MATCH(arg, "--workers")) {
        /* When scanning ranges or multiple addresses, we have to spawn
         * worker processes (because the original rdesktop code uses
         * a lot of global variables). This setting determines
         * how many workers we can spawn. The default is 100 workers.
         * Larger values can either hit operating system limits
         * (e.g. 700 workers for macOS), or hit practical resource
         * constraints making the operating system extremely slow. */
        arg = next_arg(argc, argv, index);
        cfg->max_workers = atoi(arg);
        if (cfg->max_workers <= 0 || 65536 <= cfg->max_workers) {
            fprintf(stderr, "[-] invalid workers: %s\n", arg);
            exit(1);
        }
    } else {
        fprintf(stderr, "[-] unknown param: %s\n", arg);
        exit(1);
    }
}

void
parse_commandline(struct command_line *cfg, int argc, char *argv[])
{
    int i;
    
    for (i=1; i<argc; i++) {
        const char *arg = argv[i];
        
        if (arg[0] == '-') {
            switch (arg[1]) {
                case 'd':
                {
                    int j;
                    for (j=0; arg[j]; j++) {
                        extern int g_log_level;
                        if (arg[j] == 'd') {
                            cfg->debug_level++;
                            g_log_level++;
                        }
                    }
                }
                    break;
                case 'p':
                    if (arg[2] == '\0')
                        arg = argv[++i];
                    else
                        arg = arg + 2;
                    if (i >= argc) {
                        fprintf(stderr, "[-] expected port number after -p\n");
                        exit(1);
                    }
                    g_tcp_port_rdp = atoi(arg);
                    if (g_tcp_port_rdp <= 0 || 65536 <= g_tcp_port_rdp) {
                        fprintf(stderr, "[-] invalid port: %s\n", arg);
                        exit(1);
                    }
                    break;

                case '-':
                    set_parameter(cfg, argc, argv, &i);
                    break;
                case '\0':
                    break;
                case 'q':
                    g_result_quiet = 1;
                    break;
                case 'v':
                    g_result_quiet = 0;
                    g_result_verbose = 1;
                    break;
                case 'h':
                case '?':
                    print_help();
                    break;
                default:
                    fprintf(stderr, "[-] unknown parameter: %s\n", argv[i]);
                    exit(1);
                    break;
            }
        } else {
            cfg->targets = xrealloc(cfg->targets, (cfg->target_count+2) * sizeof(char*));
            cfg->targets[cfg->target_count++] = xstrdup(argv[i]);
            cfg->targets[cfg->target_count] = NULL; /* null termiante this list */
        }
    }
    

}

int main(int argc, char *argv[])
{
    unsigned flags = 0;
    char domain[32] = "";
    char shell[32] = "";
    char directory[32] = "";
    RD_BOOL g_reconnect_loop = False;
    struct command_line cfg = {0};
    int err;
    
    /* Parse the command-line. Note that this puts some things in our
     * configuration structure, but puts other things in global variables.
     * This program use A LOT of global variables. */
    if (argc <= 1)
        print_help();
    cfg.max_workers = 100; /* default */
    parse_commandline(&cfg, argc, argv);
    if (cfg.list_filename == NULL && cfg.target_count == 0)
        print_help();
    
    /* See if we have a single IPv4 range, in which case we expand
     * this into a larger range */
    if (cfg.list_filename == NULL && cfg.target_count == 1 && is_ipv4_range(cfg.targets[0])) {
        char *string = cfg.targets[0];
        unsigned index = 0;
        struct Range range;
        struct RangeList list = {0};
        size_t i;
        uint64_t count;
        struct BlackRock br;
        
        /* Free the old list and reset it to NULL */
        free(cfg.targets);
        cfg.targets = 0;
        cfg.target_count = 0;
        
        /* Parse the range */
        range = range_parse_ipv4(string, &index, (unsigned)strlen(string));
        if (!range_is_valid(range)) {
            fprintf(stderr, "[-] %s: invalid range\n", string);
            exit(1);
        }
        
        /* Create an internal array of addresses */
        rangelist_add_range(&list, range.begin, range.end);
        rangelist_sort(&list);
        rangelist_optimize(&list);
        
        /* Now grab all the individual IP addresses in our range and
         * add them to the list. */
        count = rangelist_count(&list);
        blackrock_init(&br, count, time(0), 3);

        for (i=0; i<count; i++) {
            char ipstr[16];
            unsigned ip = rangelist_pick(&list, blackrock_shuffle(&br, i));

            snprintf(ipstr, sizeof(ipstr), "%u.%u.%u.%u",
                     (ip>>24) & 0xFF,
                     (ip>>16) & 0xFF,
                     (ip>> 8) & 0xFF,
                     (ip>> 0) & 0xFF
                     );
            cfg.targets = xrealloc(cfg.targets, (cfg.target_count+2) * sizeof(char*));
            cfg.targets[cfg.target_count++] = xstrdup(ipstr);
            cfg.targets[cfg.target_count] = NULL; /* null termiante this list */
        }
        
        rangelist_remove_all(&list);
    }
    
    /* If a file of many IP addresses was specified, then instead of
     * scannign them in ths process, spawn worker processes to scan them.
     * that's because this program was designed with lots of global variables,
     * so we can't scan them all in this process */
    if (cfg.list_filename || cfg.target_count > 1)
        return spawn_workers(argv[0],
                             cfg.list_filename,
                             cfg.targets,
                             cfg.debug_level,
                             g_tcp_port_rdp,
                             cfg.max_workers);
    
    /* RDP servers will cache the cookie and reject connections with the same
     * cookie. Therefore, every connection should have it's own cookie */
    if (g_username == NULL)
        g_username = randomize_username();
    
    /* This is the start of the CVE-2019-0708 check, it creates a T120 channel
     * that it will then attempt to receive data on */
    if (!mst120_check_init())
    {
        printf("[-] Failed to initialize MS_T120 channel!\n");
    }

    /* Do the RDP connection. This is where all the interesting stuff happens */
    flags = RDP_INFO_MOUSE | RDP_INFO_DISABLECTRLALTDEL
    | RDP_INFO_UNICODE | RDP_INFO_MAXIMIZESHELL | RDP_INFO_ENABLEWINDOWSKEY;
    err = rdp_connect(cfg.targets[0],
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

    if (g_network_error) {
        RESULT("UNKNOWN - network error\n");
    } else {
        RESULT("UNKNOWN - unknown condition\n");
    }
    return 0;
}
