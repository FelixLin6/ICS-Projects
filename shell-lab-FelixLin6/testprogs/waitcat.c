#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "testprogs/helper.h"

static void sigalrm_handler(int signum) {
    _exit(0);
}

int main(void) {

    int c;
    while ((c = getchar()) != EOF) {
        putchar(c);
    }

    int syncfd;
    int standalone;

    Signal(SIGALRM, sigalrm_handler);

    standalone = get_syncfd(&syncfd);

    if (standalone) {
        perror("standalone");
        exit(1);
    }

    alarm(JOB_TIMEOUT);

    sync_signal(syncfd);
    sync_wait(syncfd);

    exit(0);
}
