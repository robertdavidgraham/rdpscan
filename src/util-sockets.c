
#ifdef WIN32
#define WIN32_LEAN_AND_MEAN 
#if defined(_MSC_VER)
#pragma comment(lib, "Ws2_32.lib")
#ifdef SSLSTATIC
# pragma comment(lib, "libssl_static.lib")
# pragma comment(lib, "libcrypto_static.lib")
#else
# pragma comment(lib, "libssl.lib")
# pragma comment(lib, "libcrypto.lib")
#endif

#endif
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <intrin.h>
#include <process.h>
#define snprintf _snprintf
#define close(fd) closesocket(fd)
typedef int ssize_t;
#undef errno
#define errno WSAGetLastError()

#define strerror my_strerror

const char *
$strerror(int err)
{
    static char* msg = NULL;
    switch (err) {
    default:
        if (msg == NULL)
            free(msg);
        FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | 
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            err,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPSTR)&msg,
            0, NULL );
        return msg;
        break;
    }
}

#else
#endif

