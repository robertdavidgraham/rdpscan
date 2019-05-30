/*
    Spawn zillions of child processes, each scanning a different
    target
*/
#define _CRT_SECURE_NO_WARNINGS 1
#include "workers.h"
#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
#include <malloc.h> /* alloca() */
#include <direct.h> /* getcwd() */
#define snprintf _snprintf
#define getcwd _getcwd

struct tracker
{
    HANDLE parent_stdout;
    HANDLE parent_stderr;
    HANDLE child_stdout;
    HANDLE child_stderr;
};

struct spawned
{
    HANDLE hProcess;
};

static char *my_strerror(DWORD err)
{
    char* msg = NULL;
    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        err,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&msg,
        0, NULL );
    //LocalFree( msg );
    return msg;
}

static void
tracker_init(struct tracker *t, unsigned *max_children)
{
    SECURITY_ATTRIBUTES saAttr = {0};
    BOOL is_success;

    /* 
     * Set the inherit flag so that children can inherit handles
     */
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES); 
    saAttr.bInheritHandle = TRUE; 
    saAttr.lpSecurityDescriptor = NULL; 

    /*
     * Create the pipes, but set the parent half the pipe to non-inheritable,
     * so the child only inherits their side of the pipe.
     */
    is_success = CreatePipe(&t->parent_stdout, &t->child_stdout, &saAttr, 0);
    if (!is_success) {
        fprintf(stderr, "[-] CreatePipe() %s\n", my_strerror(GetLastError()));
        exit(1);
    }
    is_success = SetHandleInformation(t->parent_stdout, HANDLE_FLAG_INHERIT, 0);
    if (!is_success) {
        fprintf(stderr, "[-] SetHandleInfo(!INHERIT) %s\n", my_strerror(GetLastError()));
        exit(1);
    }

    is_success = CreatePipe(&t->parent_stderr, &t->child_stderr, &saAttr, 0);
    if (!is_success) {
        fprintf(stderr, "[-] CreatePipe() %s\n", my_strerror(GetLastError()));
        exit(1);
    }
    is_success = SetHandleInformation(t->parent_stderr, HANDLE_FLAG_INHERIT, 0);
    if (!is_success) {
        fprintf(stderr, "[-] SetHandleInfo(!INHERIT) %s\n", my_strerror(GetLastError()));
        exit(1);
    }

}
static struct spawned
spawn_program(struct tracker *t, const char *progname, size_t arg_count, ...)
{
    PROCESS_INFORMATION proc_info = {0};
    STARTUPINFOA start_info = {0};
    BOOL is_success;
    char *command_line;
    
    /*
     * Create the command-line from the arguments
     */
    {
        size_t command_line_length;
        size_t i;
        size_t offset;
        va_list marker;
        
        /* Calculate the length of the command-line */
        command_line_length = strlen(progname) + 1;
        va_start(marker, arg_count);
        for (i=0; i<arg_count; i++)
            command_line_length += strlen(va_arg(marker, char*)) + 1;
        va_end(marker);

        /* Allocate a buffer for it */
        command_line = alloca(command_line_length + 1);

        /* Create the command-line */
        offset = strlen(progname);
        memcpy(command_line, progname, offset + 1);
        va_start(marker, arg_count);
        for (i=0; i<arg_count; i++) {
            char *arg = va_arg(marker, char*);
            size_t arglen = strlen(arg);
            command_line[offset++] = ' ';
            memcpy(command_line + offset, arg, arglen + 1);
            offset += arglen;
        }
        va_end(marker);
    }

    
    /*
     * Configure which pipes the child will use
     */
   start_info.cb = sizeof(STARTUPINFOA); 
   start_info.hStdError = t->child_stderr;
   start_info.hStdOutput = t->child_stdout;
   start_info.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
   start_info.dwFlags |= STARTF_USESTDHANDLES;

   is_success = CreateProcessA(
       NULL, 
        command_line,     // command line 
        NULL,          // process security attributes 
        NULL,          // primary thread security attributes 
        TRUE,          // handles are inherited 
        CREATE_NO_WINDOW,// creation flags 
        NULL,          // use parent's environment 
        NULL,          // use parent's current directory 
        &start_info,  // STARTUPINFO pointer 
        &proc_info);  // receives PROCESS_INFORMATION
   if (!is_success) {
       fprintf(stderr, "[-] CreateProcessA() failed %d\n", (int)GetLastError());
       exit(1);
   }

    /* This should automatically reap zombies, by indicating
     * we are not interested in any return results from the
     * process, only their pipes */
    //CloseHandle(proc_info.hProcess);
    CloseHandle(proc_info.hThread);

   {
       struct spawned child = {0};
       child.hProcess = proc_info.hProcess;
       return child;
   }
}


static HANDLE
my_echo(HANDLE h, FILE *fp, int *closed_count)
{
    BOOL is_success;
    char buf[1024];
    DWORD length;
    
    is_success = ReadFile(h, buf, sizeof(buf), &length, NULL);
    if (is_success) {
        fwrite(buf, 1, length, fp);
    } else {
        (*closed_count)++;
        CloseHandle(h);
        h = NULL;
    }
    return h;
}

/**
 * Reads input from child and parses the results
 */
static int
parse_results(struct tracker *t, struct spawned *children, size_t children_count, unsigned milliseconds)
{
    size_t total_bytes_read = 0;
    int closed_count = 0;
    size_t i = 0;

    /*
     * Reap exited processes. Note that it only reaps a few processes
     * in each pass, rather than all possible processes.
     */
    i = 0;
    while (i < children_count) {
        HANDLE handles[MAXIMUM_WAIT_OBJECTS];
        DWORD handle_count = 0;
        DWORD result;

        for (; i<children_count; ) {
            handles[handle_count++] = children[i++].hProcess;
            if  (handle_count >= MAXIMUM_WAIT_OBJECTS)
                break;
        }

        /* Test to see if any processes have exited */
        result = WaitForMultipleObjects(handle_count, handles, FALSE, 0);
            
        /* If none have exited, then test the next batch */
        if (result == WAIT_TIMEOUT)
            continue;

        /* If there is a catostrophic failure, then print a message and 
         * exit the program. This shouldn't be possible. */
        if (result == WAIT_FAILED) {
            fprintf(stderr, "[-] Wait() error: %s\n", my_strerror(GetLastError()));
            exit(1);
        }

        /* When the child process dies, it'll trigger this code below. We 
         * want to simply close the handle and mark it close, so that we
         * know that we can open up new processes in its place */
        if (WAIT_OBJECT_0 <= result && result <= MAXIMUM_WAIT_OBJECTS) {
            size_t index;
            
            index = i;
            if (index % MAXIMUM_WAIT_OBJECTS == 0)
                index -= MAXIMUM_WAIT_OBJECTS;
            else
                index -= index % MAXIMUM_WAIT_OBJECTS;
            index += (result - WAIT_OBJECT_0);
            
            if (children[index].hProcess != handles[result - WAIT_OBJECT_0]) {
                fprintf(stderr, "bug\n");
                abort();
            }
            
            CloseHandle(children[index].hProcess);
            
            children[index].hProcess = NULL;

            closed_count++;
        }
    }

    /* Now wait for pipe input. All of the processes are writing to the same two
     * pipes. */
    for (;;) {
        char buffer[16384];
        DWORD length;
        BOOL is_success;
        DWORD combined_length = 0;

        if (PeekNamedPipe(t->parent_stdout, 0, 0, 0, &length, 0) && length) {
            is_success = ReadFile(t->parent_stdout, buffer, sizeof(buffer), &length, 0);
            if (is_success) {
                fwrite(buffer, 1, length, stdout);

                /* Remember this so we know if we need to sleep at the end of this function */
                total_bytes_read += length;

                /* Remember this so we know if we need to break out of this loop */
                combined_length += length;
            }
        }
        if (PeekNamedPipe(t->parent_stderr, 0, 0, 0, &length, 0) && length) {
            is_success = ReadFile(t->parent_stderr, buffer, sizeof(buffer), &length, 0);
            if (is_success) {
                fwrite(buffer, 1, length, stderr);

                /* Remember this so we know if we need to sleep at the end of this function */
                total_bytes_read += length;

                /* Remember this so we know if we need to break out of this loop */
                combined_length += length;
            }
        }

        /* Keep looping until there's nothing left to read from either pipe */
        if (combined_length == 0)
            break;
    }

    /* If there was no activity, then do a simple sleep so that we don't
     * burn through tons of CPU time */
    if (closed_count == 0 && total_bytes_read == 0)
        Sleep(milliseconds);

    /* Return the number of children that were closed, so that
     * the parent process can cleanup its tracking records */
    return closed_count;
}

/**
 * Called to cleanup any children records after their processes have
 * died. We simply move the entry at the end of the list to fill
 * the void of dead child.
 */
static void
cleanup_children(struct spawned *children, size_t *children_count)
{
    size_t i;
    
    for (i = 0; i < *children_count; i++) {
        struct spawned *child = &children[i];
        
        if (child->hProcess == NULL) {
            memcpy(child, &children[*children_count - 1], sizeof(*child));
            (*children_count)--;
            i--;
        }
    }
}

#endif

#ifndef _WIN32
#include <unistd.h>
#include <sys/select.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>

/* On Windows, we use a single set of pipes that we store here. 
 * On POSIX, we are creating one pipe per process, though we
 * may change that model in the future */
struct tracker
{
    int parent_stdout;
    int parent_stderr;
    int child_stdout;
    int child_stderr;
    size_t count_closed;
};

/* On POSIX, we want to disover the limits for filehandles and process
 * creation. */
static void
tracker_init(struct tracker *t, unsigned *max_children)
{
    struct rlimit limit;
    int err;
    extern int g_log_level;
    
    /* Discover how many child processes we can have active at
     * a time. */
#ifdef RLIMIT_NPROC
    err = getrlimit(RLIMIT_NPROC, &limit);
    if (err) {
        fprintf(stderr, "[-] getrlimit() %s\n", strerror(errno));
        exit(1);
    }
    if (g_log_level > 1) {
        fprintf(stderr, "[ ] nproc = %ld (soft) %ld (hard)\n", (long)limit.rlim_cur, (long)limit.rlim_max);
    }
    if (*max_children > (unsigned)limit.rlim_max - 10 && limit.rlim_max > 10) {
        *max_children = (unsigned)limit.rlim_max - 10;
    }
    if (limit.rlim_cur + 10 < *max_children) {
        limit.rlim_cur = limit.rlim_max;
        setrlimit(RLIMIT_NPROC, &limit);
    }
#endif

    /* Discover how many file descriptors we can have open */
    err = getrlimit(RLIMIT_NOFILE, &limit);
    if (err) {
        fprintf(stderr, "[-] getrlimit() %s\n", strerror(errno));
        exit(1);
    }
    if (g_log_level > 1) {
        ;//fprintf(stderr, "[ ] nfile = %ld (soft) %ld (hard)\n", (long)limit.rlim_cur, (long)limit.rlim_max);
    }
    if (*max_children > (unsigned)limit.rlim_max/2 - 5 && limit.rlim_max > 10) {
        *max_children = (unsigned)limit.rlim_max/2 - 5;
    }
    if (limit.rlim_cur + 10 < *max_children * 2) {
        limit.rlim_cur = limit.rlim_max;
        setrlimit(RLIMIT_NOFILE, &limit);
    }

    /* Create a pipe to get output from children. All children
     * will write to the same pipe, which could in theory
     * cause some conflicts, but shouldn't in practice. */
    {
        int pipe_stdout[2];
        int pipe_stderr[2];
        
        err = pipe(pipe_stdout);
        if (err < 0) {
            fprintf(stderr, "[-] pipe(): %s\n", strerror(errno));
            exit(1);
        }
        err = pipe(pipe_stderr);
        if (err < 0) {
            fprintf(stderr, "[-] pipe(): %s\n", strerror(errno));
            exit(1);
        }
        
        /* Save the pipes that we'll use later */
        t->parent_stdout = pipe_stdout[0];
        t->parent_stderr = pipe_stderr[0];
        t->child_stdout = pipe_stdout[1];
        t->child_stderr = pipe_stderr[1];
        
        /* Configure the parent end of the pipes be be non-inheritable.
         * In other words, none of the children can read from these
         * pipes, nor will they exist in child process space */
        fcntl(t->parent_stdout, F_SETFD, FD_CLOEXEC);
        fcntl(t->parent_stderr, F_SETFD, FD_CLOEXEC);
    }
    

}

/**
 * A structure for tracking the spawned child program
 */
struct spawned
{
    const char *name;
    int pid;
};

/**
 * Do a fork()/exec() to spawn the program
 */
static struct spawned
spawn_program(struct tracker *t, const char *progname, size_t arg_count, ...)
{
    struct spawned child = {0};
    char **new_argv;
    
    /* Spawn child */
again:
    child.pid = fork();
    
    /* Test for fork errors */
    if (child.pid == -1 && errno == EAGAIN) {
        /* we've run out of max processes for this user, so wait and try again,
         * hopefull some of the processes will have exited in the meantime */
        static int is_printed = 0;
        if (is_printed++ == 0)
            fprintf(stderr, "[-] fork() hit process limit\n");
        sleep(1);
        goto again;
    } else if (child.pid == -1) {
        fprintf(stderr, "[-] fork() error: %s\n", strerror(errno));
        exit(1);
    }
    
    /* Setup child parameters */
    {
        size_t i = 0;
        
        /* We are the CHILD */
        new_argv = alloca((arg_count + 2) * sizeof(char*));
        va_list marker;
        
        new_argv[i++] = (char *)progname;
        va_start(marker, arg_count);
        while (arg_count--) {
            new_argv[i++] = va_arg(marker, char*);
        }
        va_end(marker);
        new_argv[i] = NULL;
        child.name = new_argv[1];
    }
    
    if (child.pid == 0) {
        int err;
        /* Set the 'write' end of the pipe 'stdout' */
        dup2(t->child_stdout, 1);
        dup2(t->child_stderr, 2);
        
        /* Now execute our child with new program */
        err = execve(progname, new_argv, 0);
        if (err) {
            fprintf(stderr, "[+] execve(%s) failed: %s\n", progname, strerror(errno));
            exit(1);
        }
    } else {
        /* we are the parent */
        ;
    }
    return child;
}

/**
 * Reads input from child and parses the results
 */
static int
parse_results(struct tracker *t, struct spawned *children, size_t children_count, unsigned milliseconds)
{
    fd_set fds;
    int nfds = 0;
    struct timeval tv;
    int err;
    int closed_count = 1;

    tv.tv_sec = milliseconds / 1000;
    tv.tv_usec = (milliseconds * 1000) % 1000000;

    
    /* Fill in all the file descriptors */
    FD_ZERO(&fds);
    FD_SET(t->parent_stdout, &fds);
    if (nfds < t->parent_stdout)
        nfds = t->parent_stdout;
    FD_SET(t->parent_stderr, &fds);
    if (nfds < t->parent_stderr)
        nfds = t->parent_stderr;
    
    /* Do the select */
again:
    err = select(nfds + 1, &fds, 0, 0, &tv);
    if (err < 0) {
        if (errno == EINTR)
            goto again; /* A signal from an exiting child interrupted this */
        fprintf(stderr, "[-] select(): %s\n", strerror(errno));
        exit(1);
    } else if (err == 0)
        return closed_count; /* okay, timeout */
    
    /* Check all the file descriptors */
    if (FD_ISSET(t->parent_stdout, &fds)) {
        char buf[16384];
        ssize_t count;
        
        count = read(t->parent_stdout, buf, sizeof(buf));
        if (count < 0) {
            fprintf(stderr, "[-] read(): %s\n", strerror(errno));
            exit(1);
        } else {
            fwrite(buf, 1, count, stdout);
        }
    }
    if (FD_ISSET(t->parent_stderr, &fds)) {
        char buf[16384];
        ssize_t count;
        
        count = read(t->parent_stderr, buf, sizeof(buf));
        if (count < 0) {
            fprintf(stderr, "[-] read(): %s\n", strerror(errno));
            exit(1);
        } else {
            fwrite(buf, 1, count, stderr);
        }
    }
    
    /* Return the number of children that were closed, so that
     * the parent process can cleanup its tracking records */
    return closed_count;
}

/**
 * Called to cleanup any children records after their processes have
 * died. We simply move the entry at the end of the list to fill
 * the void of dead child.
 */
static void
cleanup_children(struct spawned *children, size_t *children_count)
{
    for (;;) {
        int pid;
        
        /* Reap children.
         * The first parameter is set to -1 to indicate that we want
         * information about ANY of our children processes.
         * The second paremeter is set to NULL to indicate that we
         * aren't interested in knowing the status/result code from
         * the process.
         * The third parameter is WNOHHANG, meaning that we want to return
         * immediately
         */
        pid = waitpid(-1, 0, WNOHANG);
        
        if (pid > 0) {
            /* If we get back a valid PID, that means the child process
             * has terminated. We want to decrement our count by one
             * then loop around looking for more child processes. */
            (*children_count) --;
            //fprintf(stderr, "[ ] children left = %u\n", (unsigned)*children_count);
            continue;
        } else if (pid == 0) {
            /* if none of our children are currently exited, then this
             * value of zero is returned. */
            break;
        } else if (pid == -1 && errno == ECHILD) {
            /* In this condition, there are no child processes. In this
             * case, we just want to handle this the same as pid=0 */
            //fprintf(stderr, "[ ] no children left\n");
            break;
        } else if (pid < 0) {
            /* Some extraordinary error occured */
            //fprintf(stderr, "[-] waitpid() %s\n", strerror(errno));
            exit(1);
        }
    }
}

#endif


/**
 * A wrapper for spawning a worker, setting up the command-line parameters,
 * after which the operating-system spawn will happen (either POSIX or WIN32)
 */
static struct spawned
spawn_worker(struct tracker *t, const char *progname, const char *address, int debug_level, int port_number)
{
    char debug[16] = "-dddddddddddddd";
    char port[32];
    extern char *g_socks5_server;
    extern unsigned g_socks5_port;
    
    /* We always include the port number as a command-line parameter, even
     * if it's the default, which is almost always the case */
    snprintf(port, sizeof(port), "--port=%d", port_number);
    
    /* Create the debug-level/diag-level parameter */
    if (debug_level > 10) {
        debug_level = 10;
    }
    debug[debug_level + 1] = '\0';
    if (debug_level == 0) {
        extern int g_result_verbose;
        if (g_result_verbose)
            memcpy(debug, "-v", 3); /* make unresponsive IP addresses verbose */
        else
            memcpy(debug, "-q", 3); /* make unresponsive IP addresses quiet */

    }
    
    if (g_socks5_server) {
        char port2[32];
        snprintf(port2, sizeof(port2), "--socks5port=%u", g_socks5_port);
        return spawn_program(t, progname, 6, address, port, debug, "--socks5", g_socks5_server, port2);
    } else {
        return spawn_program(t, progname, 3, address, port, debug);
    }
}


int
spawn_workers(const char *progname,
              const char *filename,
              char **addresses,
              int debug_level,
              int rdp_port,
              unsigned max_children)
{
    FILE *fp;
    struct tracker tracker = {0};
    struct spawned *children;
    size_t children_count = 0;
    extern int g_log_level;

    tracker_init(&tracker, &max_children);

    /* Allocate space to track all our spawned workers */
    children = calloc(max_children + 1, sizeof(*children));
    if (children == NULL) {
        fprintf(stderr, "[-] out-of-memory\n");
        exit(1);
    }
    
    /* Open the file. If the name is "-", then that means use <stdin>
     * instead of a file */
    if (filename == NULL)
        fp = NULL; /* skip file, do only command-line */
    else if (strcmp(filename, "-") == 0)
        fp = stdin; /* instead of file, read stdin */
    else {
        fp = fopen(filename, "rt");
        if (fp == NULL) {
            char buf[512];
            fprintf(stderr, "[-] %s: %s\n", filename, strerror(errno));
            if (getcwd(buf, sizeof(buf)))
				fprintf(stderr, "[-] cwd = %s\n", buf);
            return 1;
        }
    }
    
    /*
     * Keep spawning workers as we parse the file
     */
    while (fp) {
        char line[512];
        struct spawned *child;
        
        /* Get the next line of text from the file */
        if (fgets(line, sizeof(line), fp) == NULL)
            break;
        
        /* Trim leading/trailing white space */
        while (*line && isspace(*line))
            memmove(line, line+1, strlen(line));
        while (*line && isspace(line[strlen(line)-1]))
            line[strlen(line)-1] = '\0';
        
        /* Ignore empty lines */
        if (*line == '\0')
            continue;
        
        /* If the line starts with punctuation, then assume it's some
         * sort of comment. The exception is the brackets '[' which
         * can be used in IPv6 addresses */
        if (ispunct(*line) && *line != '[')
            continue;
        
        /* If this is a line from masscan, then trim that beginning up
         * to the IP address */
        if (memcmp(line, "Discovered open port ", 21) == 0) {
            char *line2 = strstr(line, " on ");
            if (line2 == NULL)
                continue;
            memmove(line, line2+4, strlen(line2)+4);
        }
        
        /* Now spawn the child */
        child = &children[children_count++];
        *child = spawn_worker(&tracker, progname, line, debug_level, rdp_port);

        /* Do this at least once, which slows down how fast we spawn
         * new processes. If we've reached the maximum children count,
         * then we stay stuck here processing children until one
         * of them exits and creates room for a new child */
        do {
            int closed_count = parse_results(&tracker, children, children_count, 100);
            if (closed_count) {
                cleanup_children(children, &children_count);
            }
        } while (children_count == max_children);
    }
    if (fp && g_log_level)
        fprintf(stderr, "[+] done reading file\n");
    
    /* If addresses were specified on the command-line, then add
     * those to the list as well */
    while (addresses && *addresses) {
        struct spawned *child;

        /* Wait until there is space in our list to add the child
         * process */
        while (children_count == max_children) {
            int closed_count = parse_results(&tracker, children, children_count, 100);
            if (closed_count)
                cleanup_children(children, &children_count);
        }
        
        /* Now spawn the child */
        child = &children[children_count++];
        *child = spawn_worker(&tracker, progname, *addresses, debug_level, rdp_port);

        /* Now move to the next address in our list. This is NULL
         * terminated */
        addresses++;
    }
    
    
    /* We've run out of entries in the file, but we still may have
     * child processes in various states of execution, so we sit
     * here waiting for them all to exit */
    while (children_count) {
        int closed_count = parse_results(&tracker, children, children_count, 100);
        if (closed_count) {
            cleanup_children(children, &children_count);
        }
    }
    
    /* Clean up any remaining pipe stuff */
    parse_results(&tracker, children, children_count, 100);

    /* There are no more children left, so now it's time to exit */
    return 0;
}
