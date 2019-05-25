/*
    Spawn zillions of child processes, each scanning a different
    target
*/
#define _CRT_SECURE_NO_WARNINGS 1
#include "workers.h"
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>

struct spawned
{
    HANDLE parent_stdout;
    HANDLE parent_stderr;
    HANDLE hProcess;
    HANDLE hThread;
};

char *my_strerror(DWORD err)
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
static struct spawned
spawn_program(const char *progname, const char *argument)
{
    SECURITY_ATTRIBUTES saAttr = {0};
    DWORD err;
    HANDLE parent_stdout, child_stdout;
    HANDLE parent_stderr, child_stderr;
    PROCESS_INFORMATION proc_info = {0};
    STARTUPINFO start_info = {0};
    BOOL is_success;
    char *command_line;
    size_t command_line_length = strlen(progname) + strlen(argument) + 20;

    /*
     * Create the command-line from the arguments
     */
    sprintf_s(command_line, command_line_length, "%s %s", progname, argument);

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
    err = CreatePipe(&parent_stdout, &child_stdout, &saAttr, 0);
    if (err)
        exit(1);
    err = SetHandleInformation(parent_stdout, HANDLE_FLAG_INHERIT, 0);
    if (err)
        exit(1);

    err = CreatePipe(&parent_stderr, &child_stderr, &saAttr, 0);
    if (err != 0)
        exit(1);
    err = SetHandleInformation(parent_stderr, HANDLE_FLAG_INHERIT, 0);
    if (err)
        exit(1);

    /*
     * Configure which pipes the child will use
     */
   start_info.cb = sizeof(STARTUPINFO); 
   start_info.hStdError = child_stderr;
   start_info.hStdOutput = child_stdout;
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

   {
       struct spawned child = {0};
       child.parent_stderr = parent_stderr;
       child.parent_stdout = parent_stdout;
       child.hProcess = proc_info.hProcess;
       child.hThread = proc_info.hThread;

       return child;
   }
   //CloseHandle(proc_info.hProcess);
   //CloseHandle(proc_info.hThread);

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
parse_results(struct spawned *children, size_t children_count, unsigned milliseconds)
{
    int closed_count = 0;
    size_t i;
    size_t job;
    HANDLE errs[MAXIMUM_WAIT_OBJECTS];
    HANDLE outs[MAXIMUM_WAIT_OBJECTS];
    //HANDLE quits[MAXIMUM_WAIT_OBJECTS];
    
    /* Read all <stderr> */
    for (job=0; job<children_count; job+=MAXIMUM_WAIT_OBJECTS) {
        DWORD result;
        DWORD handle_count;
            
        for (i=0; i<MAXIMUM_WAIT_OBJECTS && job+i<job; i++) {
            errs[i] = children[i].parent_stderr;
            outs[i] = children[i].parent_stdout;
            //quits[i] = children[i].hProcess;
        }
        handle_count = (DWORD)i;
            

        for (;;) {
            result = WaitForMultipleObjects(handle_count, errs, FALSE, 0);
            
            if (result == WAIT_TIMEOUT)
                break;
            else if (result == WAIT_FAILED) {
                fprintf(stderr, "[-] Wait() error: %s\n", my_strerror(GetLastError()));
                exit(1);
            }
            if (WAIT_OBJECT_0 <= result && result <= MAXIMUM_WAIT_OBJECTS) {
                size_t index = result - WAIT_OBJECT_0;
                children[i].parent_stderr = my_echo(errs[index], stderr, &closed_count);
            }
        }

        for (;;) {
            result = WaitForMultipleObjects(handle_count, outs, FALSE, 0);
            if (result == WAIT_TIMEOUT)
                break;
            else if (result == WAIT_FAILED) {
                fprintf(stderr, "[-] Wait() error: %s\n", my_strerror(GetLastError()));
                exit(1);
            }
            if (WAIT_OBJECT_0 <= result && result <= MAXIMUM_WAIT_OBJECTS) {
                size_t index = result - WAIT_OBJECT_0;
                children[i].parent_stdout = my_echo(outs[index], stderr, &closed_count);
            }
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
    size_t i;
    
    for (i = 0; i < *children_count; i++) {
        struct spawned *child = &children[i];
        
        if (child->parent_stdout == 0 && child->parent_stderr == 0) {
            memcpy(child, &children[*children_count - 1], sizeof(*child));
            (*children_count)--;
        }
    }
}

#endif

#ifndef WIN32
#include <unistd.h>
#include <sys/select.h>
#include <fcntl.h>

/**
 * A structure for tracking the spawned child program
 */
struct spawned
{
    int pid;
    int fdout[2];
    int fderr[2];
    unsigned is_closed:1;
};

/**
 * Do a fork()/exec() to spawn the program
 */
static struct spawned
spawn_program(const char *progname, const char *argument)
{
    struct spawned child = {0};
    int err;
    
    /* Create a pipe to get output from child */
    err = pipe(child.fdout);
    if (err < 0) {
        fprintf(stderr, "[-] pipe(): %s\n", strerror(errno));
        exit(1);
    }
    err = pipe(child.fderr);
    if (err < 0) {
        fprintf(stderr, "[-] pipe(): %s\n", strerror(errno));
        exit(1);
    }
    
    /* Spawn child */
    child.is_closed = 0;
    child.pid = fork();
    
    if (child.pid == 0) {
        /* We are the CHILD */
        char * new_argv[3];
        new_argv[0] = (char *)progname;
        new_argv[1] = (char *)argument;
        new_argv[2] = 0;
        
        /* Close the 'read' end of the pipe, since child only writes to it */
        close(child.fdout[0]);
        close(child.fderr[0]);
        
        /* Set the 'write' end of the pipe 'stdout' */
        dup2(child.fdout[1], 1);
        dup2(child.fderr[1], 2);
        
        /* Now execute our child with new program */
        execve(progname, new_argv, 0);
    } else {
        /* We are the PARENT */
        
        /* Close the 'write' end of the pipe, since parent only reads
         * from it. Set the other end to be non-inheritable by children */
        close(child.fdout[1]);
        close(child.fderr[1]);
        fcntl(child.fdout[0], F_SETFD, FD_CLOEXEC);
        fcntl(child.fderr[0], F_SETFD, FD_CLOEXEC);
    }
    return child;
}

/**
 * Reads input from child and parses the results
 */
static int
parse_results(struct spawned *children, size_t children_count, unsigned milliseconds)
{
    fd_set fds;
    int nfds = 0;
    struct timeval tv;
    int err;
    size_t i;
    int closed_count = 0;

    tv.tv_sec = milliseconds / 1000;
    tv.tv_usec = (milliseconds * 1000) % 1000000;

    
    /* Fill in all the file descriptors */
    FD_ZERO(&fds);
    for (i=0; i<children_count; i++) {
        struct spawned *child = &children[i];
        
        if (child->fdout[0] != -1) {
            FD_SET(child->fdout[0], &fds);
            if (nfds < child->fdout[0])
                nfds = child->fdout[0];
        }
        
        if (child->fderr[0] != -1) {
            FD_SET(child->fderr[0], &fds);
            if (nfds < child->fderr[0])
                nfds = child->fderr[0];
        }
    }
    
    /* Do the select */
    err = select(nfds + 1, &fds, 0, 0, &tv);
    if (err < 0) {
        fprintf(stderr, "[-] select(): %s\n", strerror(errno));
        exit(1);
    } else if (err == 0)
        return 0; /* okay, timeout */
    
    /* Check all the file descriptors */
    for (i=0; i<children_count; i++) {
        struct spawned *child = &children[i];
        
        /* Check for <stdout> from the child worker */
        if (child->fdout[0] != -1 && FD_ISSET(child->fdout[0], &fds)) {
            char buf[512];
            ssize_t count;
            
            count = read(child->fdout[0], buf, sizeof(buf));
            if (count < 0) {
                fprintf(stderr, "[-] read(): %s\n", strerror(errno));
                exit(1);
            } else if (count == 0) {
                close(child->fdout[0]);
                child->fdout[0] = -1;
                closed_count++;
            } else {
                fwrite(buf, 1, count, stdout);
            }
        }
        
        /* Check for <stderr> from the child worker, this will
         * be debug messages, which if the debug_level is zero(0),
         * then there shouldn't be any of this. */
        if (child->fderr[0] != -1 && FD_ISSET(child->fderr[0], &fds)) {
            char buf[512];
            ssize_t count;
            
            count = read(child->fderr[0], buf, sizeof(buf));
            if (count < 0) {
                fprintf(stderr, "[-] read(): %s\n", strerror(errno));
                exit(1);
            } else if (count == 0) {
                close(child->fderr[0]);
                child->fderr[0] = -1;
                closed_count++;
            } else {
                fwrite(buf, 1, count, stderr);
            }
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
    size_t i;
    
    for (i = 0; i < *children_count; i++) {
        struct spawned *child = &children[i];
        
        if (child->fdout[0] == -1 && child->fderr[0] == -1) {
            memcpy(child, &children[*children_count - 1], sizeof(*child));
            (*children_count)--;
        }
    }
}

#endif


int
spawn_workers(const char *progname, const char *filename, int debug_level, unsigned max_children)
{
    FILE *fp;
    struct spawned *children;
    size_t children_count = 0;
    
    /* Automatically reap zombies. Child processes will otherwise stay around
     * in a zombie state after they exit, waiting for the parent to read their
     * return values. By doing this, we indicate we aren't interested in reading
     * the return values, and that the operating system should clean them
     * up quickly. */
#ifdef SIGCHLD
    if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
        perror("signal(SIGCHLD, SIG_IGN)");
        exit(1);
    }
#endif

    /* Make sure that the number of children cannot exceed the total
     * number of file descriptors that we can have in a select()
     * statement */
#ifdef FD_SETSIZE
    if (max_children > FD_SETSIZE/2 - 4) {
        max_children = FD_SETSIZE/2 - 4;
        fprintf(stderr, "[ ] max children = %u\n", max_children);
    }
#endif
    

    /* Allocate space to track all our spawned workers */
    children = calloc(max_children + 1, sizeof(*children));
    if (children == NULL) {
        fprintf(stderr, "[-] out-of-memory\n");
        exit(1);
    }
    
    /* Open the file. If the name is "-", then that means use <stdin>
     * instead of a file */
    if (strcmp(filename, "-") == 0)
        fp = stdin;
    else {
        fp = fopen(filename, "rt");
        if (fp == NULL) {
            char buf[512];
            fprintf(stderr, "[-] %s: %s\n", filename, strerror(errno));
            getcwd(buf, sizeof(buf));
            fprintf(stderr, "[-] cwd = %s\n", buf);
            return 1;
        }
    }
    
    /*
     * Keep spawning workers as we parse the file
     */
    for (;;) {
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
        
        /* Now spawn the child */
        child = &children[children_count++];
        *child = spawn_program(progname, line);

        /* Do this at least once, which slows down how fast we spawn
         * new processes. If we've reached the maximum children count,
         * then we stay stuck here processing children until one
         * of them exits and creates room for a new child */
        do {
            int closed_count = parse_results(children, children_count, 100);
            if (closed_count) {
                cleanup_children(children, &children_count);
            }
        } while (children_count == max_children);
    }
    fprintf(stderr, "[+] done reading file\n");
    
    /* We've run out of entries in the file, but we still may have
     * child processes in various states of execution, so we sit
     * here waiting for them all to exit */
    while (children_count) {
        int closed_count = parse_results(children, children_count, 100);
        if (closed_count) {
            cleanup_children(children, &children_count);
        }
    }
    fprintf(stderr, "[+] FIN\n");
    
    return 0;
}
