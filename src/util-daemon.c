/* Copyright (C) 2007-2010 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Gerardo Iglesias Galvan <iglesiasg@gmail.com>
 *
 * Daemonization process
 */

#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include "util-daemon.h"
//#include "util-debug.h"

#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>

static volatile sig_atomic_t sigflag = 0;

/**
 * \brief Signal handler used to take the parent process out of stand-by
 */
static void SignalHandlerSigusr1 (__attribute__((unused))int signo) {
    sigflag = 1;
}

/**
 * \brief Tell the parent process the child is ready
 *
 * \param pid pid of the parent process to signal
 */
static void TellWaitingParent (pid_t pid) {
    kill(pid, SIGUSR1);
}

/**
 * \brief Set the parent on stand-by until the child is ready
 *
 * \param pid pid of the child process to wait
 */
static void WaitForChild (pid_t pid) {
    int status;
//    SCLogDebug("Daemon: Parent waiting for child to be ready...");
    /* Wait until child signals is ready */
    while (sigflag == 0) {
        if (waitpid(pid, &status, WNOHANG)) {
            /* Check if the child is still there, otherwise the parent should exit */
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
//                SCLogError(SC_ERR_DAEMON, "Child died unexpectedly");
                exit(EXIT_FAILURE);
            }
        }
        /* sigsuspend(); */
        sleep(1);
    }
}
/**
 * \brief Close stdin, stdout, stderr.Redirect logging info to syslog
 *
 */
#if 0
static void SetupLogging (void) {
    /* Redirect stdin, stdout, stderr to /dev/null  */
    int fd = open("/dev/null", O_RDWR);
    if (fd < 0)
        return;
    if (dup2(fd, 0) < 0)
        return;
    if (dup2(fd, 1) < 0)
        return;
    if (dup2(fd, 2) < 0)
        return;
    close(fd);
}
#endif

/**
 * \brief Daemonize the process
 *
 */
void Daemonize (void) {
    pid_t pid, sid;

    /* Register the signal handler */
    signal(SIGUSR1, SignalHandlerSigusr1);

    /** \todo We should check if wie allow more than 1 instance
              to run simultaneously. Maybe change the behaviour
              through conf file */

    /* Creates a new process */
    pid = fork();

    if (pid < 0) {
        /* Fork error */
//        SCLogError(SC_ERR_DAEMON, "Error forking the process");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        /* Child continues here */
        umask(027);

        sid = setsid();
        if (sid < 0) {
 //           SCLogError(SC_ERR_DAEMON, "Error creating new session");
            exit(EXIT_FAILURE);
        }

        if (chdir("/") < 0) {
   //         SCLogError(SC_ERR_DAEMON, "Error changing to working directory '/'");
        }

//        SetupLogging();

        /* Child is ready, tell its parent */
        TellWaitingParent(getppid());

        /* Daemon is up and running */
//        SCLogDebug("Daemon is running");
        return;
    }
    /* Parent continues here, waiting for child to be ready */
//    SCLogDebug("Parent is waiting for child to be ready");
    WaitForChild(pid);

    /* Parent exits */
//    SCLogDebug("Child is ready, parent exiting");
    exit(EXIT_SUCCESS);

}


