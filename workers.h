#ifndef WORKERS_H
#define WORKERS_H

/**
 * In order to handle more than one target, we need to spawn
 * child processes.
 * @param progname
 *  The name of this program, namely argv[0].
 * @param filename
 *  A file containing many IP addresses, IPv6 addresses, or
 *  DNS names. One child process will be spawned per entry
 *  in the file. Child processes will be spawn in the same
 *  order as found in the file. May be NULL.
 * @param addresses
 *  Addresses specified on the command-line. May be NULL.
 * @param debug_level
 *  The debug level to pass to the processes for additional
 *  debugging information, default=0.
 * @param rdp_port
 *  Almost always 3389, but can be changed with the command-line
 *  parameter --port.
 * @param max_children
 *  The maximum number of child processes that can be active
 *  at once. Modern systems should be able to handle thousands
 *  without too much problem.
 * @return
 *  This function doesn't return until all children have been
 *  spawned and completed their scans. At that point, it's
 *  assumed the parent program will exit having completed
 *  its task.
 */
int spawn_workers(const char *progname,
                  const char *filename,
                  char **addresses,
                  int debug_level,
                  int rdp_port,
                  unsigned max_children);

#endif

