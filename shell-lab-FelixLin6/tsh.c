/**
 * @file tsh.c
 * @brief A tiny shell program with job control
 *
 * The shell has a main function that has a while loop that continuously calls
 * the eval function on parsed commandline commands. With each command, the
 * shell either executes one of the builtin commands -- quit, fg, bg, or jobs --
 * or starts a process for running an executable. The tsh is installed with
 * custom signal handlers for the signals SIGCHLD, SIGINT, and SIGSTP, which can
 * be sent to the shell with respective keyboard commnands. The shell
 * differentiates between foreground and background jobs, and supports
 * IO-redirection for both inputting and outputing onto a file instead of
 * standard in/output.
 *
 * @author Felix Lin <felixl@andrew.cmu.edu>
 */

#include "csapp.h"
#include "tsh_helper.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * If DEBUG is defined, enable contracts and printing on dbg_printf.
 */
#ifdef DEBUG
/* When debugging is enabled, these form aliases to useful functions */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_requires(...) assert(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_ensures(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated for these */
#define dbg_printf(...)
#define dbg_requires(...)
#define dbg_assert(...)
#define dbg_ensures(...)
#endif

extern char **environ;

/* Function prototypes */
void eval(const char *cmdline);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
void sigquit_handler(int sig);
void cleanup(void);

/**
 * @brief Sets up the tsh environment and repeatedly takes command and calls
 * eval
 *
 * Takes in number of arguments and an array of strings -- the arguments
 * themselves; Initiates jobs list, sets up the variable environment, installs
 * the signal handlers at the end of this file and starts a while loop that
 * continuously parses commandline arguments and executing them.
 *
 * "Each function should be prefaced with a comment describing the purpose
 *  of the function (in a sentence or two), the function's arguments and
 *  return value, any error cases that are relevant to the caller,
 *  any pertinent side effects, and any assumptions that the function makes."
 */
int main(int argc, char **argv) {
    int c;
    char cmdline[MAXLINE_TSH]; // Cmdline for fgets
    bool emit_prompt = true;   // Emit prompt (default)

    // Redirect stderr to stdout (so that driver will get all output
    // on the pipe connected to stdout)
    if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) {
        perror("dup2 error");
        exit(1);
    }

    // Parse the command line
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
        case 'h': // Prints help message
            usage();
            break;
        case 'v': // Emits additional diagnostic info
            verbose = true;
            break;
        case 'p': // Disables prompt printing
            emit_prompt = false;
            break;
        default:
            usage();
        }
    }

    // Create environment variable
    if (putenv(strdup("MY_ENV=42")) < 0) {
        perror("putenv error");
        exit(1);
    }

    // Set buffering mode of stdout to line buffering.
    // This prevents lines from being printed in the wrong order.
    if (setvbuf(stdout, NULL, _IOLBF, 0) < 0) {
        perror("setvbuf error");
        exit(1);
    }

    // Initialize the job list
    init_job_list();

    // Register a function to clean up the job list on program termination.
    // The function may not run in the case of abnormal termination (e.g. when
    // using exit or terminating due to a signal handler), so in those cases,
    // we trust that the OS will clean up any remaining resources.
    if (atexit(cleanup) < 0) {
        perror("atexit error");
        exit(1);
    }

    // Install the signal handlers
    Signal(SIGINT, sigint_handler);   // Handles Ctrl-C
    Signal(SIGTSTP, sigtstp_handler); // Handles Ctrl-Z
    Signal(SIGCHLD, sigchld_handler); // Handles terminated or stopped child

    Signal(SIGTTIN, SIG_IGN);
    Signal(SIGTTOU, SIG_IGN);

    Signal(SIGQUIT, sigquit_handler);

    // Execute the shell's read/eval loop
    while (true) {
        if (emit_prompt) {
            printf("%s", prompt);

            // We must flush stdout since we are not printing a full line.
            fflush(stdout);
        }

        if ((fgets(cmdline, MAXLINE_TSH, stdin) == NULL) && ferror(stdin)) {
            perror("fgets error");
            exit(1);
        }

        if (feof(stdin)) {
            // End of file (Ctrl-D)
            printf("\n");
            return 0;
        }

        // Remove any trailing newline
        char *newline = strchr(cmdline, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }

        // Evaluate the command line
        eval(cmdline);
    }

    return -1; // control never reaches here
}

// Given a JID, wait for the foreground job until it is done.
static void waitfg(jid_t jid) {
    sigset_t mask, prev;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTSTP);

    sigprocmask(SIG_BLOCK, &mask, &prev);
    while (job_exists(jid) && job_get_state(jid) == FG) {
        sigsuspend(&prev);
    }
    sigprocmask(SIG_SETMASK, &prev, NULL);
}

// Given a string, parses the JID or parses the PID and return the PID.
static jid_t get_jid(const char *s) {
    if (!s)
        return 0;

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTSTP);
    sigprocmask(SIG_BLOCK, &mask, NULL);

    jid_t jid = 0;
    if (s[0] == '%') {
        jid = atoi(s + 1);
        if (!job_exists(jid))
            jid = 0;
    }

    else {
        pid_t pid = atoi(s);
        jid = job_from_pid(pid);
    }

    sigprocmask(SIG_UNBLOCK, &mask, NULL);
    return jid;
}

// Given a string, determines whether it is a PID (return 1)or JID (return 2),
// or neither (return 0).
static int pidORjid(const char *s) {
    if (s == NULL || !*s)
        return 0;

    // Starts with %, so is a JID
    if (s[0] == '%') {
        if (!isdigit((unsigned char)s[1]))
            return 0;
        for (int i = 2; s[i]; i++) {
            if (!isdigit((unsigned char)s[i]))
                return 0;
        }
        return 2;
    }

    // PID
    else {
        for (int i = 0; s[i]; i++) {
            if (!isdigit((unsigned char)s[i]))
                return 0;
        }
        return 1;
    }
}

/**
 * @brief Executes a given commendline.
 *
 * Parses a command from the cmdline string, determines if it is a tsh builtin
 * command or command to run a process. Then executes correspondingly.
 *
 * NOTE: The shell is supposed to be a long-running process, so this function
 *       (and its helpers) should avoid exiting on error.  This is not to say
 *       they shouldn't detect and print (or otherwise handle) errors!
 */
void eval(const char *cmdline) {
    struct cmdline_tokens token;

    // Parse command line
    parseline_return parse_result = parseline(cmdline, &token);

    // Return if command empty
    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY)
        return;

    // Builtin: quit
    if (token.builtin == BUILTIN_QUIT)
        exit(0);

    sigset_t mask, prev;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTSTP);

    // Print the list of all jobs -- into a file if IO-redirected
    if (token.builtin == BUILTIN_JOBS) {
        int fd = STDOUT_FILENO;
        if (token.outfile)
            fd =
                open(token.outfile, O_WRONLY | O_CREAT | O_TRUNC,
                     S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
        if (fd < 0) {
            perror(token.outfile);
            return;
        }

        // Lock the job states before printing jobs
        sigprocmask(SIG_BLOCK, &mask, &prev);
        list_jobs(fd);
        sigprocmask(SIG_SETMASK, &prev, NULL);

        if (token.outfile)
            close(fd);
        return;
    }

    // Toggle betwen foreground/background for a job
    if (token.builtin == BUILTIN_FG || token.builtin == BUILTIN_BG) {
        const char *cmd;
        if (token.builtin == BUILTIN_FG)
            cmd = "fg";
        else
            cmd = "bg";

        if (token.argc < 2) {
            fprintf(stderr, "%s command requires PID or %%jobid argument\n",
                    cmd);
            return;
        }

        if (!pidORjid(token.argv[1])) {
            fprintf(stderr, "%s: argument must be a PID or %%jobid\n", cmd);
            return;
        }

        jid_t jid = get_jid(token.argv[1]);
        if (!jid) {
            fprintf(stderr, "%s: No such job\n", token.argv[1]);
            return;
        }

        sigprocmask(SIG_BLOCK, &mask, &prev);
        pid_t pid = job_get_pid(jid);
        kill(-pid, SIGCONT);

        if (token.builtin == BUILTIN_BG) {
            job_set_state(jid, BG);
            sio_printf("[%d] (%d) %s\n", jid, pid, job_get_cmdline(jid));
        } else
            job_set_state(jid, FG);

        sigprocmask(SIG_SETMASK, &prev, NULL);

        if (token.builtin == BUILTIN_FG)
            waitfg(jid);

        return;
    }

    // If command wasn't a builtin command and is for starting a new job
    bool bg = (parse_result == PARSELINE_BG);

    sigprocmask(SIG_BLOCK, &mask, &prev);
    pid_t pid = fork();
    if (pid == 0) {
        sigprocmask(SIG_SETMASK, &prev, NULL);
        setpgid(0, 0);

        // Input IO-redirection
        if (token.infile) {
            int fd = open(token.infile, O_RDONLY);
            if (fd < 0) {
                perror(token.infile);
                _exit(1);
            }
            dup2(fd, STDIN_FILENO);
            close(fd);
        }

        // Output IO-redirection
        if (token.outfile) {
            int fd =
                open(token.outfile, O_WRONLY | O_CREAT | O_TRUNC,
                     S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
            if (fd < 0) {
                perror(token.outfile);
                _exit(1);
            }
            dup2(fd, STDOUT_FILENO);
            close(fd);
        }

        execve(token.argv[0], token.argv, environ);
        perror(token.argv[0]);
        _exit(1);
    }

    // If this is the parent, use the child pid to update the jobs list
    jid_t jid = add_job(pid, bg ? BG : FG, cmdline);

    if (bg)
        sio_printf("[%d] (%d) %s\n", jid, pid, cmdline);

    sigprocmask(SIG_SETMASK, &prev, NULL);

    // Then, wait for child to finish if its a fg job
    if (!bg) {
        waitfg(jid);
    }
}

/*****************
 * Signal handlers
 *****************/

/**
 * @brief Handlers SIGCHLD signal by reaping all zombie children.
 *
 * Continuously reaps zombie children until there is none while also reflecting
 * the formal termination of those processes on the jobs list
 */
void sigchld_handler(int sig) {
    int old_errno = errno;
    sigset_t mask, prev;

    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTSTP);

    pid_t pid;
    int status;

    // Continue reaping children if there are still zombie children
    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED | WCONTINUED)) > 0) {

        // Lock job states so that job status stay the same
        sigprocmask(SIG_BLOCK, &mask, &prev);
        jid_t jid = job_from_pid(pid);

        // Normal exit
        if (WIFEXITED(status))
            delete_job(jid);

        // If it was terminated by a signal, print the signal then delete job
        else if (WIFSIGNALED(status)) {
            sio_printf("Job [%d] (%d) terminated by signal %d\n", jid, pid,
                       WTERMSIG(status));
            delete_job(jid);
        }

        // If stopped by a signal, print that
        else if (WIFSTOPPED(status)) {
            sio_printf("Job [%d] (%d) stopped by signal %d\n", jid, pid,
                       WSTOPSIG(status));
            job_set_state(jid, ST);
        }

        sigprocmask(SIG_SETMASK, &prev, NULL);
    }

    errno = old_errno;
}

/**
 * @brief Handles CTRL-C signal that terminates a job
 *
 * Relays the SIGINT signal to the fg process, if there is one
 */
void sigint_handler(int sig) {
    int old_errno = errno;
    sigset_t mask, prev;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTSTP);

    // Preserve the job states
    sigprocmask(SIG_BLOCK, &mask, &prev);
    jid_t jid = fg_job();
    // If there is a fg job, relay the signal to the job's process
    if (jid) {
        pid_t pid = job_get_pid(jid);
        kill(-pid, SIGINT);
    }

    sigprocmask(SIG_SETMASK, &prev, NULL);
    errno = old_errno;
}

/**
 * @brief Handles CTRL-Z signal that temporarily halts a job
 *
 * Relays the SIGSTP signal to the fg process, if there is one
 */
void sigtstp_handler(int sig) {
    int old_errno = errno;
    sigset_t mask, prev;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTSTP);

    // Preserve the job states
    sigprocmask(SIG_BLOCK, &mask, &prev);

    jid_t jid = fg_job();
    // If there is a fg job, relay the signal to the job's process
    if (jid) {
        pid_t pid = job_get_pid(jid);
        kill(-pid, SIGTSTP);
    }

    sigprocmask(SIG_SETMASK, &prev, NULL);
    errno = old_errno;
}

/**
 * @brief Attempt to clean up global resources when the program exits.
 *
 * In particular, the job list must be freed at this time, since it may
 * contain leftover buffers from existing or even deleted jobs.
 */
void cleanup(void) {
    // Signals handlers need to be removed before destroying the joblist
    Signal(SIGINT, SIG_DFL);  // Handles Ctrl-C
    Signal(SIGTSTP, SIG_DFL); // Handles Ctrl-Z
    Signal(SIGCHLD, SIG_DFL); // Handles terminated or stopped child

    destroy_job_list();
}
