# rdpscan for CVE-2019-0708 bluekeep vuln

This is a quick-and-dirty scanner for the CVE-2019-0708 vulnerability.
This is based entirely on the `rdesktop` patch from https://github.com/zerosum0x0/CVE-2019-0708.
I've simply removed all the dependencies not necessary for the purposes
of scanning for the vulnerability.

## Status

 - 2019-05-23 - currently working on macOS within XCode

## Building

You should just be able to compile all the *.c* files together:

    $ gcc *.c -lssl -lcrypto -o rdpscan
    
However, this may fail because of OpenSSL issues. I'm struggling on macOS
to get this working correctly.



