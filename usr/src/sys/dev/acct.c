#include <sys/param.h>
#include <sys/systm.h>
#include <sys/disk.h>
#include <sys/event.h>
#include <sys/limits.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/malloc.h>
#include <sys/fcntl.h>
#include <sys/timeout.h>
#include <sys/mutex.h>
#include <sys/task.h>
#include <sys/msgbuf.h>
#include <sys/mount.h>
#include <sys/syscallargs.h>
#include <sys/tty.h>
#include <sys/proc.h>
#include <sys/rwlock.h>

#include <dev/acct.h>

union acct_types {
        struct acct_fork ac_fork;
        struct acct_exec ac_exec;
        struct acct_exit ac_exit;
};

// struct acct_entry
// {
// 	TAILQ_ENTRY(acct_entry) entry;
//         unsigned short ac_type;
//         union acct_types acct_t;
// };
// TAILQ_HEAD(acct_list, acct_entry);

// struct acct_list acct_entries = TAILQ_HEAD_INITIALIZER(acct_entries);

struct rwlock act_lock = RWLOCK_INITIALIZER("ac_lock");

struct acct_common common;

struct acct_exit exit;

void
acct_fork(struct process *p)
{
        // struct acct_fork ac_fork;
        // // struct acct_entry *ac_entry;

        // ac_fork.ac_common.ac_type = ACCT_MSG_FORK;
        // ac_fork.ac_common.ac_len = sizeof(struct acct_fork);
        // ac_fork.ac_common.ac_seq = 0;

        // // ac_entry->ac_type = ACCT_MSG_FORK;
        // // ac_entry->acct_t.ac_fork = ac_fork;

        // TAILQ_INSERT_TAIL(&acct_entries, ac_entry, entry);
        printf("fork\n");
}

void
acct_exec(struct process *p)
{
        // common.ac_etime = p->ps_start;
        // common.ac_btime = p->ps_start;
        common.ac_seq++;
        printf("exec\n");
}

void
acct_exit(struct process *p)
{
	struct acct_exit acct;
	struct process *pr = p;
	struct rusage *r;

	// rw_enter_write(&act_lock);

	/*
	 * Get process accounting information.
	 */

	/* (1) The name of the command that ran */
	memcpy(acct.ac_common.ac_comm, pr->ps_comm, sizeof(acct.ac_common.ac_comm));

	/* (3) The elapsed time the command ran (and its starting time) */
	acct.ac_common.ac_btime = pr->ps_start;
	acct.ac_common.ac_etime = pr->ps_start;

	/* (4) The average amount of memory used */
	// r = &(p->ps_mainproc)->p_ru;
	// timespecadd(&ut, &st, &tmp);
	// t = tmp.tv_sec * hz + tmp.tv_nsec / (1000 * tick);
	// if (t)
	// 	acct.ac_mem = (r->ru_ixrss + r->ru_idrss + r->ru_isrss) / t;
	// else
	acct.ac_mem = 0;

	/* (5) The number of disk I/O operations done */
	acct.ac_io = r->ru_inblock + r->ru_oublock;

	/* (6) The UID and GID of the process */
        acct.ac_common.ac_pid = pr->ps_pid;
        printf("pid: %i\n", pr->ps_pid);
	acct.ac_common.ac_uid = pr->ps_ucred->cr_ruid;
	acct.ac_common.ac_gid = pr->ps_ucred->cr_rgid;

	/* (7) The terminal from which the process was started */
	if ((pr->ps_flags & PS_CONTROLT) &&
	    pr->ps_pgrp->pg_session->s_ttyp)
		acct.ac_common.ac_tty = pr->ps_pgrp->pg_session->s_ttyp->t_dev;
	else
		acct.ac_common.ac_tty = NODEV;

	/* (8) The boolean flags that tell how the process terminated, etc. */
	acct.ac_common.ac_flag = pr->ps_acflag;


        acct.ac_common.ac_type = ACCT_MSG_EXIT;
        acct.ac_common.ac_len = sizeof(struct acct_exit);
        acct.ac_common.ac_seq = 0;

	/*
	 * Now, just write the accounting information to the file.
	 */
	exit = acct;

        printf(">> exit set: %hu %hu %u %s %i %i %i %llu %llu\n",
                exit.ac_common.ac_type,
                exit.ac_common.ac_len,
                exit.ac_common.ac_seq,
                exit.ac_common.ac_comm,
                exit.ac_common.ac_pid,
                exit.ac_common.ac_uid,
                exit.ac_common.ac_gid,
                exit.ac_mem,
                exit.ac_io
        );

        // rw_exit_write(&act_lock);
}

void
acctattach(int num)
{
        printf("attach\n");
}

int
acctopen(dev_t dev, int flag, int mode, struct proc *p)
{
        printf("open\n");
        struct process *pr = p->p_p;
        common.ac_btime = pr->ps_start;
        common.ac_etime = pr->ps_start;
        common.ac_seq = 0;
        return 0;
}

int
acctclose(dev_t dev, int flag, int mode, struct proc *p)
{
        printf("close\n");
        return 0;
}

int
acctioctl(dev_t dev, u_long cmd, caddr_t data, int fflag, struct proc *p)
{
        printf("ioctl\n");
        return 0;
}

int
acctread(dev_t dev, struct uio *uio, int flags)
{
        printf("*read*\n");
	int error;
        // switch (common.ac_type) {
        //         case ACCT_MSG_FORK:
        //                 common.ac_len = sizeof(struct acct_fork);
        //                 break;
        //         case ACCT_MSG_EXEC:
        //                 common.ac_len = sizeof(struct acct_exec);
        //                 break;
        //         case ACCT_MSG_EXIT:
        //                 common.ac_len = sizeof(struct acct_exit);
        //                 break;
        // }


        size_t len = sizeof(struct acct_exit);

        if (exit == NULL) {
                return 0;
        }

	if (uio->uio_offset < 0) {
		return EINVAL;
        }

        if (uio->uio_offset >= len) {
                return 0;
        }

        if (len > uio->uio_resid) {
                len = uio->uio_resid;
        }
        
        // rw_enter_read(&act_lock);

        printf(">> %hu %hu %u %s %i %i %i %llu %llu\n",
                exit.ac_common.ac_type,
                exit.ac_common.ac_len,
                exit.ac_common.ac_seq,
                exit.ac_common.ac_comm,
                exit.ac_common.ac_pid,
                exit.ac_common.ac_uid,
                exit.ac_common.ac_gid,
                exit.ac_mem,
                exit.ac_io
        );

        if ((error = uiomove((void *)&exit, sizeof(struct acct_exit), uio)) != 0) {
                // rw_exit_read(&act_lock);
                return error;
        }

        exit = NULL;
        // rw_exit_read(&act_lock);


        return 0;
}

int
acctwrite(dev_t dev, int flag, int mode, struct proc *p)
{
        return EOPNOTSUPP;
}

int
acctpoll(dev_t dev, int events, struct proc *p)
{
        printf("poll\n");
        return 0;
}

int
acctkqfilter(dev_t dev, struct knote *kn)
{
        printf("kqfilter\n");
        return 0;
}