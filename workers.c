/*
    Spawn zillions of child processes, each scanning a different
    target
*/
#include "workers.h"
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>


#ifndef WIN32
#include <unistd.h>
#include <sys/select.h>
#include <fcntl.h>
#endif

/**
 * A structure for tracking the spawned child program
 */
struct spawned
{
    pid_t pid;
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
    if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
        perror("signal(SIGCHLD, SIG_IGN)");
        exit(1);
    }

    /* Make sure that the number of children cannot exceed the total
     * number of file descriptors that we can have in a select()
     * statement */
    if (max_children > FD_SETSIZE/2 - 4) {
        max_children = FD_SETSIZE/2 - 4;
        fprintf(stderr, "[ ] max children = %u\n", max_children);
    }
    

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
