# rdpscan for CVE-2019-0708 bluekeep vuln

This is a quick-and-dirty scanner for the CVE-2019-0708 vulnerability.
This is based entirely on the `rdesktop` patch from https://github.com/zerosum0x0/CVE-2019-0708.
I've simply trimmed the code so that I can easily compile on macOS and Windows,
as well as added the ability to scan multiple targets.

## Status

This is highly flakey and experimental. You are likely to have lots of problems, but
you can try contacting me on Twitter (@erratarob) for help. Or maybe I'll be asleep
having stayed up late futzing with development.

 - 2019-05-24 - works on Linux and macOS, Windows has a few compilation bugs
 - 2019-05-23 - currently working on macOS within XCode
 
 ## Primary use
 
 The primary way of using this tool is first using `masscan` to scan for the port,
 then using tool to probe those ports that are listening. An example is:
 
    $ masscan 0.0.0.0/0 -p3389 >ips.txt
    $ rdpscan --file ips.txt > results.txt
    
In the `results.txt` file, search for those lines containing the string "VULNERABLE".

## Building

The difficult part is getting the OpenSSL libraries installed, and not conflicting
with other versions of OpenSSL on the system. On Debian Linux, I do:

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



## Running

Just run the program with an IP address:

    ./rdpscan 192.168.10.101
    
You can scan multiple targets at once. Instead of IPv4 addresses, they can be
DNS names or IPv6 addresses.

    ./rdpscan 192.168.10.101 exchange.example.com 2001:0db8:85a3::1
    
You can also scan ranges of addresses, using either begin-end IPv4 addresses,
or IPv4 CIDR spec. IPv6 ranges aren't supported because they are so big.

    ./rdpscan 10.0.0.1-10.0.0.25 192.168.0.0/16

You can scan zillions of targets at once by loading address from a `--file` instead.
The format is each address should be alone on a line. Whitespace is ignored.
Lines starting with punctuation (except '[', which can be part of IPv6 address) is 
a comment and ignored, though the prefered comment mark is `#` or `//`.

    ./rdpscan --file ips.txt

This just dumps results to `stdout`, whether they are VULNERABLE, SAFE, or UNKNOWN.
There could be additional reasons for each.

    149.129.120.24  - UNKNOWN - FIN received
    45.60.213.160   - SAFE - not RDP but HTTP
    208.43.229.89   - SAFE - CredSSP required
    170.104.127.137 - UNKNOWN - FIN received
    86.188.190.117  - UNKNOWN - connect timeout
    62.15.34.157    - SAFE - Target appears patched
    216.15.251.120  - VULNERABLE -- got appid
    69.62.158.174   - VULNERABLE -- got appid
    92.111.20.13    - SAFE - Target appears patched

Those marked "UNKNOWN" are probably worth scanning later, especially
for "FIN received", which usually means the other side terminated the connection
early because of delay on the Internet.

Whether "CredSSP required" (meaning NLA required) is "SAFE" is debatable.
It means it requires a password
login *before* we can test/trigger the vuln. It may be unpatched and vulnerable to
an authenticated user, it's just not exploitable by a worm or unauthenticated user.

You *should* always get one-and-only-one status on `stdout` for each IP address
you scan. Of course, if you specify an IP address multiple times, you'll get multiple
statuses for that address.

However, because this code is based on `rdestkop`, there are certain protocol
errors that won't lead to a status. If you've got a public IP address on the Internet
that produces one of these errors, then I'm eager to fix it.


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
