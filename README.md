[![Windows download](/badges/binary-windows.svg)](https://github.com/robertdavidgraham/rdpscan/files/3226661/rdpscan-windows.zip)
[![macOS download](/badges/binary-macos.svg)](https://github.com/robertdavidgraham/rdpscan/files/3226663/rdpscan-macos.zip)
[![Linux download](/badges/source-linux.svg)](https://github.com/robertdavidgraham/rdpscan/archive/v0.0.2.zip)
[![Follow](/badges/erratarob.svg)](https://twitter.com/intent/follow?screen_name=erratarob)

# rdpscan for CVE-2019-0708 bluekeep vuln

This is a quick-and-dirty scanner for the CVE-2019-0708 vulnerability in Microsoft Remote Desktop.
Right now, there are about 900,000 machines on the public Internet vulnerable to this vulnerability,
so many are expect a worm soon like WannaCry and notPetya. Therefore, scan your networks and
patch (or at least, enable NLA) on vulnerable systems.

This is a command-line tool. You can download the source and compile it
yourself, or you can download one of the pre-compiled binaries for 
Windows or macOS from the link above.

This tool is based entirely on the `rdesktop` patch from https://github.com/zerosum0x0/CVE-2019-0708.
I've simply trimmed the code so that I can easily compile on macOS and Windows,
as well as added the ability to scan multiple targets.

## Status

This is only a few days old and experimental. However, I am testing it by scanning
the entire Internet (with the help of `masscan`, so I'm working through a lot of problems
pretty quickly. You can try contacting me on twttier(@erratarob) for help/comments.

 - 2019-05-38 - Better output result descriptions, as well as documentation what they mean (see below).
 - 2019-05-27 - Windows and macOS binaries released (click on badges above).
 - 2019-05-26 - fixing the Windows networking issues
 - 2019-05-25 - Linux and macOS working well, Windows has a few network errors
 - 2019-05-24 - works on Linux and macOS, Windows has a few compilation bugs
 - 2019-05-23 - currently working on macOS within XCode
 
 ## Primary use
 
 To scan a network, run it like the following:
 
    rdpscan 192.168.1.1-192.168.1.255
    
This produces one of 3 results for each address:
  - SAFE - if target has determined bot be *patched* or at least require *CredSSP/NLA*
  - VULNERABLE - if the target has been confirmed to be vulnerable
  - UNKNOWN - if the target doesn't respond or has some protocol failure

When nothing exists at a target IP address, the older versions pritned the
message "*UNKNOWN - connection timed out*". When scanning large networks,
this produces an overload of too much information about systems you don't
care about. Therefore, the new version by default doesn't produce this
information unless you add *-v* (for verbose) on the command-line.

You can increase the speed at which it scans large networks by increasing
the number of workers:

    rdpscan --workers 10000 10.0.0.0/8

However, on my computer, it only produces about 1500 workers, because
of system limitations, no matter how high I configure this parameter.

You can increase the speed even more by using this in conjunction
with `masscan`, described in the second below.

## Interpreting the results

There are three general responses:
  - *SAFE* - which means the target is probably patched or otherwise
        not vulnerable to the bug.
  - *VULNERABLE*: which means we've confirmed the target is vulnerable
        to this bug, and that when the worm hits, will likely get
        infected.
  - *UNKNOWN*: means we can't confirm either way, usually because
        the target doesn't respond or isn't running RDP, which is
        the vast majority of responses. Also, when targets are out
        of resources or experiencing network problems, we'll get
        a lot of these. Finally, protocol errors are responsble
        for a lot.
While the three main responses are *SAFE*, *VULNERABLE*, and *UNKNOWN*,
they contain additional text explaining the diagnosis. This section
describes the various strings you'll see.

### SAFE

There are three main reaons we think a target is safe:
 - *SAFE - Target appears patched*
    This happens when the target doesn't respond to the triggering
    request. This means it's a Windows system that's been patched,
    or a system that wasn't vulnerable to begin with, like Windows 10
    or Unix.
 - *SAFE - CredSSP/NLA required* 
    This means that the target first requires Network Level Authentication before
    the RDP connection can be established. The tool cannot pass this point, without
    leigitimate credentials, so cannot determine whether the target has been patched.
    However, hackers can't continue past this point to exploit vulnerable systems, either,
    so you are likely "safe". However, when exploits appear, insiders with valid
    usernames/passwords will be able to exploit the system if it's un-patched.
 - *SAFE - not RDP*
    This means the system is not RDP, but has some other service that happens to use
    this same port, and produces a response that's clearly not RDP. Common examples are
    HTTP and SSH. Note however that instead of an identifiable protocol, a server 
    may respond with a RST or FIN packet. These are identified as *UNKNOWN* instead
    of *SAFE*/

### VULNERABLE

This means we've confirmed the system is vulnerable  to the bug.
  - *VULNERABLE - got appid*
    There is only one response when the system is vulnerable, this one.

### UNKNOWN

There are a zillion variations for unknown

  - *UNKNOWN - no connection - timeout*
    This is by far the most common response, and happens when the target
    IP address makes no response whatsoever. In fact, it's so common that
    when scanning large ranges of addresses, it's usually ommited. You
    have to add the *-v* (verbose) flag in order to enable it.
  - *UNKNOWN - no connection - refused (RST)*
    This is by far the second most common response, and happens when
    the target exists and responds to network traffic, but isn't running
    RDP, so refuses the connection with a TCP RST packet.
  - *UNKNOWN - RDP protocol error - receive timeout*
    This is the third most common response, and happens when we've successfully
    established an RDP connection, but then the server stops responding
    to us. This is due to network errors and when the target system is
    overloaded for some reason. It could also be network errors on this
    end, such as when you are behind a NAT and overloading it with too
    many connections.
  - *UNKNOWN - no connection - connection closed*
    This means we've established a connection (TCP SYN-ACK), but then
    the connection is immediately closed (with a RST or FIN). There are
    many reasons this happen, which we cannot distinguish:
    - It's running RDP, but for some reason closes the connection,
          possibly because it's out-of-resources.
     - It's not RDP, and doesn't like the RDP request we send it,
          so instad of sending us a nice error message (which would
          trigger *SAFE - not RDP*), it abruptly closes the connection.
     - Some intervening device, like an IPS, firewall, or NAT closed
          the connection because it identified this as hostile, or
          ran out of resources.
     - Some other reason I haven't identified, there's a lot of 
          weird stuff happening when I scan the Internet.
  - *UNKNOWN - no connection - host unreachable (ICMP error)*
    The remote network reports the host cannot be reached or is not running.
    Try again later if you think that host should be alive.
  - *UNKNOWN - no connection - network unreachable (ICMP error)*
    There is a (transient) network error on the far end, try again
    later if you  believe that network should be running.
  - *UNKNOWN - RDP protocol error*
    This means some corruption happened in the RDP protocol, either because
    the remote side implents it wrong (not a Windows system), because it's
    handling a transient network error badly, or something else.
  - *UNKNOWN - SSL protocol error*
    Since Windows Vista, RDP uses the STARTTLS protocol to run over SSL.
    This layer has it's own problems like above, which includes handling
    underlying network errors badly, or trying to communicate with
    systems that have some sort of incompatibility. If you get a very
    long error message here (like SSL3_GET_RECORD:wrong version), it's
    because the other side has a bug in SSL, or your own SSL library that
    you are using has a bug.


## Using with masscan

This `rdpscan` tool is fairly slow, only scanning a few hundred targets per second.
You can instead use [`masscan`](https://github.com/robertdavidgraham/masscan) to speed things up.
The `masscan` tool is roughly 1000 times faster, but only gives limited information
on the target.

The steps are:
  * First scan the address ranges with masscan to quickly find hosts that
    respond on port 3389 (or whatever port you use).
  * Second feed the output of `masscan` into  `rdpscan`, so it only has
    to scan targets we know are active.

The simple way to run this is just to combine them on the command-line:

    masscan 10.0.0.0/8 -p3389 | rdpscan --file -

The way I do it is in two steps:

    masscan 10.0.0.0/8 -p3389 > ips.txt
    rdpscan --file ips.txt --workers 10000 >results.txt


## Building

The difficult part is getting the *OpenSSL* libraries installed, and not conflicting
with other versions on the system. On Debian Linux, I do:

    $ sudo apt install libssl-dev

Once you've solved that problem, you just compile all the `.c` files together
like this:

    $ gcc *.c -lssl -lcrypto -o rdpscan

I've put a Makefile in the directory that does this, so you can likely do
just:

    $ make
    
The code is written in C, so needs a C compiler installed, such as doing the following:

    $ sudo apt install build-essential
    
## Common build errors

This section describes the more obvious build errors.

    ssl.h:24:25: fatal error: openssl/rc4.h: No such file or directory

This means you either don't have the OpensSSL headers installed, or they aren't
in a path somewhere. Remember that even if you have OpenSSL binaries installed,
this doesn't mean you've got the development stuff installed. You need both
the headers and libraries installed.

To install these things on Debian, do:

    $ sudo apt install libssl-dev
    
To fix the path issue, add a compilation flag `-I/usr/local/include`, or something 
similar.

An example linker problem is the following:

    Undefined symbols for architecture x86_64:
    "_OPENSSL_init_ssl", referenced from:
        _tcp_tls_connect in tcp-fac73c.o
    "_RSA_get0_key", referenced from:
        _rdssl_rkey_get_exp_mod in ssl-d5fdf5.o
    "_SSL_CTX_set_options", referenced from:
        _tcp_tls_connect in tcp-fac73c.o
    "_X509_get_X509_PUBKEY", referenced from:
        _rdssl_cert_to_rkey in ssl-d5fdf5.o

I get this on macOS because there's multiple versions of OpenSSL. I fix this
by hard-coding the paths:

    $ gcc *.c -lssl -lcrypto -I/usr/local/include -L/usr/local/lib -o rdpscan

According to comments by others, the following command-line might work on macOS
if you've used Homebrew to install things. I still get the linking errors above, though,
because I've installed other OpenSSL components that are conflicting.

    gcc $(brew --prefix)/opt/openssl/lib/libssl.a $(brew --prefix)/opt/openssl/lib/libcrypto.a -o rdpscan *.c


## Running

The section above gives quickstart tips for running the program. This section gives
more in-depth help.

To scan a single target, just pass the address of the target:

    ./rdpscan 192.168.10.101
    
You can pass in IPv6 addresses and DNS names. You can pass in multiple targets.
An example of this would be:

    ./rdpscan 192.168.10.101 exchange.example.com 2001:0db8:85a3::1
    
You can also scan ranges of addresses, using either begin-end IPv4 addresses,
or IPv4 CIDR spec. IPv6 ranges aren't supported because they are so big.

    ./rdpscan 10.0.0.1-10.0.0.25 192.168.0.0/16

By default, it scans only 100 targets at a time. You can increase this number
with the `--workers` parameter. However, no matter how high you set this
parameter, in practice you'll get a max of around 500 to 1500 workers running
at once, depending upon your system.

    ./rdpscan --workers 1000 10.0.0.0/24

Instead of specifying targets on the command-line, you can load them
from a file instead, using the well-named `--file` parameter:

    ./rdpscan --file ips.txt

The format of the file is one address, name, or range per line. It can also
consume the text generated by `masscan`. Extra whitespace is trimmed,
blank lines ignored, any any comment lines are ignored. A *comment* is
a line starting with the `#` character, or `//` characters.

The output is sent to `stdout` giving the status of  VULNERABLE, SAFE, 
or UNKNOWN. There could be additional reasons for each. These reasons
are described above.

    211.101.37.250 - SAFE - CredSSP/NLA required
    185.11.124.79 - SAFE - not RDP - SSH response seen
    125.121.137.42 - UNKNOWN - no connection - refused (RST)
    40.117.191.215 - SAFE - CredSSP/NLA required
    121.204.186.182 - SAFE - CredSSP/NLA required
    99.8.11.148 - SAFE - CredSSP/NLA required
    121.204.186.114 - SAFE - CredSSP/NLA required
    49.50.145.236 - SAFE - CredSSP/NLA required
    106.12.74.155 - VULNERABLE - got appid
    222.84.253.26 - SAFE - CredSSP/NLA required
    144.35.133.109 - UNKNOWN - RDP protocol error - receive timeout
    199.212.226.196 - UNKNOWN - RDP protocol error - receive timeout
    183.134.58.152 - UNKNOWN - no connection - refused (RST)
    83.162.246.149 - VULNERABLE - got appid

You can process this with additional unix commands like `grep` and `cut`.
To get a list of just vulnerable machines:

    ./rdpscan 10.0.0.0/8 | grep 'VULN' | cut -f1 -d'-'

The parameter `-dddd` means *diagnostic* information, where the more `d`s you
add, the more details are printed. This is sent to `stderr` instead of `stdout`
so that you can separate the streams. Using `bash` this is done like this:

    ./rdpscan --file myips.txt -ddd 2> diag.txt 1> results.txt


## Diagnostic info

Adding the `-d` parameter dumps diagnostic info on the connections to `stderr`.

    ./rdpscan 62.15.34.157 -d
    
    [+] [62.15.34.157]:3389 - connecting...
    [+] [62.15.34.157]:3389 - connected from [10.1.10.133]:49211
    [+] [62.15.34.157]:3389 - SSL connection
    [+] [62.15.34.157]:3389 - version = v4.8
    [+] [62.15.34.157]:3389 - Sending MS_T120 check packet
    [-] [62.15.34.157]:3389 - Max sends reached, waiting...
    62.15.34.157    - SAFE - Target appears patched
    
On macOS/Linux, you can redirect `stdout` and `stderr` separately to different
files in the usual manner:

    ./rdpscan --file ips.txt 2> diag.txt 1> results.txt


## SOCKS5 and Tor lulz

So it includes SOCKS5 support:

    ./rdpscan --file ips.txt --socks5 localhost --socks5port 9050
    
It makes connection problems worse so you get a lot more "UNKNOWN" results.

## Statically link OpenSSL

For releasing the Windows and macOS binaries attached as *releases* to this project
I statically link OpenSSL, so that it doesn't need to be included separately, and the
programs *just work*. This section describes some notes on how to do this, especially
since the description on OpenSSL's own page seems to be out of date.

Both these steps start with downloading the OpenSSL source and putting
it next to the `rdpscan` directory:

    git clone https://github.com/openssl/openssl

### Windows

For Windows, you need to first install some version of Perl. I use the one
from [ActiveState](http://www.activestate.com/ActivePerl).

Next, you'll need a special "assembler". I use the recommended one called
[NASM]( http://nasm.sourceforge.net/))

Next, you'll need a compiler. I use VisualStudio 2010. You can download
the latest "Visual Studio Community Edition" (which is 2019) instead from
Microsoft.

Now you need to build the makefile. This is done by going into the OpenSSL
directory and running the `Configure` Perl program:

    perl Configure VC-WIN32

I chose 32-bit for Windows because there's a lot of old Windows out there,
and I want to make the program as compaitble as possible with old versions.

I want a completely static build, including the C runtime. To do that, I opened
the resulting makefile in an editor, and changed the C compilation flag from
`/MD` (meaning use DLLs) to `/MT`. While I was there, I added the following 
to the CPPFLAGS `-D_WIN32_WINNT=0x501`, which restrict OpenSSL to features that
work back on Windows XP and Server 2003. Otherwise, you get errors that `bcrypt.dll`
was not found if your run on those older systems.

Now you'll need to make sure everything is in your path. I copied `nasm.exe` 
to the a directory in the PATH. For Visual Studio 2010, I ran the program
`vcvars32.bat` to setup the path variables for the compiler.

At this point on the command-line, I typed:

    nmake

This makes the libraries. The static ones are `libssl_static.lib` and `libcrypto_static.lib`,
which I use to link to in `rdpscan`.

### macOS
    
First of all, you need to install a compiler. I use the Developer Tools from Apple, installing
XCode and the compiler. I think you can use Homebrew to install `gcc` instead.

Then go int othe source directory for OpenSSL and create a makefile:

    perl Configure darwin64-x86_64-cc

Now simply make it:

    make depend
    make
    
At this point, it's created both dynamic (`.dylib`) and static (`.lib`) libraries. I deleted
the dynamic libraries so that it'll catch the static ones by default.

Now in `rdpscan`, just build the macOS makefile:

    make -f Makefile.macos
    
This will compile all the `rdpscan` source files, then link to the OpenSSL libraries
in the directory `../openssl` that you just built.

This should produce a 3-megabyte exexeutable. If you instead only got a
200-kilobyte executable, then you made a mistake and linked to the dynamic libraries
instead.




