#include <sys/param.h>
#include <sys/systm.h>
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
#include <sys/resourcevar.h>
#include <sys/tty.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/kernel.h>

#include <dev/acct.h>

union acct_types {
        struct acct_fork ac_fork;
        struct acct_exec ac_exec;
        struct acct_exit ac_exit;
};

struct acct_entry
{
	TAILQ_ENTRY(acct_entry) entry;
        unsigned short ac_type;
        union acct_types acct_t;
};
TAILQ_HEAD(acct_list, acct_entry);

struct acct_list acct_entries = TAILQ_HEAD_INITIALIZER(acct_entries);

struct rwlock ac_lock = RWLOCK_INITIALIZER("ac_lock");

int ac_seq_counter = 0;

int device_opened = 0;

void
acct_fork(struct process *p)
{
        struct process *parent;
        struct acct_fork ac_fork;
        struct acct_entry *ac_entry;
        struct timespec temp;

        rw_enter_read(&ac_lock);
        if (!device_opened) {
                rw_exit_read(&ac_lock);
                return;
        }
        rw_exit_read(&ac_lock);

        parent = p->ps_pptr;
        ac_entry = malloc(sizeof(struct acct_entry), M_DEVBUF, M_WAITOK);

        rw_enter_write(&ac_lock);
        ac_fork.ac_common.ac_seq = ac_seq_counter;
        ac_seq_counter++;
        rw_exit_write(&ac_lock);

        ac_fork.ac_common.ac_type = ACCT_MSG_FORK;
        ac_fork.ac_common.ac_len = sizeof(struct acct_fork);

        /* Process name */
        memcpy(ac_fork.ac_common.ac_comm, parent->ps_comm,
                sizeof(ac_fork.ac_common.ac_comm));

        /* Starting and elapsed time */
	ac_fork.ac_common.ac_btime = parent->ps_start;
        nanotime(&temp);
        timespecsub(&temp, &parent->ps_start, &ac_fork.ac_common.ac_etime);

        /* Ids */
        ac_fork.ac_cpid = p->ps_pid;
        ac_fork.ac_common.ac_pid = parent->ps_pid;
	ac_fork.ac_common.ac_uid = parent->ps_ucred->cr_ruid;
	ac_fork.ac_common.ac_gid = parent->ps_ucred->cr_rgid;

	/* Starting terminal */
	if ((parent->ps_flags & PS_CONTROLT)
                && parent->ps_pgrp->pg_session->s_ttyp)
        {
		ac_fork.ac_common.ac_tty =
                        parent->ps_pgrp->pg_session->s_ttyp->t_dev;
        }
	else
        {
                ac_fork.ac_common.ac_tty = NODEV;
        }

        /* Termination flags */
	ac_fork.ac_common.ac_flag = parent->ps_acflag;

        /* Enqueue */
        ac_entry->ac_type = ACCT_MSG_FORK;
        ac_entry->acct_t.ac_fork = ac_fork;

        rw_enter_write(&ac_lock);
        TAILQ_INSERT_TAIL(&acct_entries, ac_entry, entry);
        rw_exit_write(&ac_lock);
}

void
acct_exec(struct process *p)
{
        struct acct_exec ac_exec;
        struct acct_entry *ac_entry;
        struct timespec temp;

        rw_enter_read(&ac_lock);
        if (!device_opened) {
                rw_exit_read(&ac_lock);
                return;
        }
        rw_exit_read(&ac_lock);

        ac_entry = malloc(sizeof(struct acct_entry), M_DEVBUF, M_WAITOK);

        rw_enter_write(&ac_lock);
        ac_exec.ac_common.ac_seq = ac_seq_counter;
        ac_seq_counter++;
        rw_exit_write(&ac_lock);

        ac_exec.ac_common.ac_type = ACCT_MSG_EXEC;
        ac_exec.ac_common.ac_len = sizeof(struct acct_exec);

        /* Process name */
	memcpy(ac_exec.ac_common.ac_comm, p->ps_comm,
                sizeof(ac_exec.ac_common.ac_comm));

        /* Starting and elapsed time */
	ac_exec.ac_common.ac_btime = p->ps_start;
        nanotime(&temp);
        timespecsub(&temp, &p->ps_start, &ac_exec.ac_common.ac_etime);

        /* Ids */
        ac_exec.ac_common.ac_pid = p->ps_pid;
	ac_exec.ac_common.ac_uid = p->ps_ucred->cr_ruid;
	ac_exec.ac_common.ac_gid = p->ps_ucred->cr_rgid;

	/* Starting terminal */
	if ((p->ps_flags & PS_CONTROLT)
                && p->ps_pgrp->pg_session->s_ttyp)
        {
		ac_exec.ac_common.ac_tty =
                        p->ps_pgrp->pg_session->s_ttyp->t_dev;
        }
	else
        {
                ac_exec.ac_common.ac_tty = NODEV;
        }

        /* Termination flags */
	ac_exec.ac_common.ac_flag = p->ps_acflag;

        /* Enqueue */
        ac_entry->ac_type = ACCT_MSG_EXEC;
        ac_entry->acct_t.ac_exec = ac_exec;

        rw_enter_write(&ac_lock);
        TAILQ_INSERT_TAIL(&acct_entries, ac_entry, entry);
        rw_exit_write(&ac_lock);
}

void
acct_exit(struct process *p)
{
        struct acct_exit ac_exit;
        struct acct_entry *ac_entry;
	struct rusage *r;
        struct timespec temp, ut, st;
        int t;

        rw_enter_read(&ac_lock);
        if (!device_opened)
        {
                rw_exit_read(&ac_lock);
                return;
        }
        rw_exit_read(&ac_lock);

        ac_entry = malloc(sizeof(struct acct_entry), M_DEVBUF, M_WAITOK);

        rw_enter_write(&ac_lock);
        ac_exit.ac_common.ac_seq = ac_seq_counter;
        ac_seq_counter++;
        rw_exit_write(&ac_lock);

        ac_exit.ac_common.ac_type = ACCT_MSG_EXIT;
        ac_exit.ac_common.ac_len = sizeof(struct acct_exit);

        /* Process name */
	memcpy(ac_exit.ac_common.ac_comm, p->ps_comm,
                sizeof(ac_exit.ac_common.ac_comm));

        /* Starting and elapsed time */
	ac_exit.ac_common.ac_btime = p->ps_start;
        nanotime(&temp);
        timespecsub(&temp, &p->ps_start, &ac_exit.ac_common.ac_etime);

	/* Memory */
	calctsru(&p->ps_tu, &ut, &st, NULL);
        r = p->ps_ru;
	timespecadd(&ut, &st, &temp);
	t = temp.tv_sec * hz + temp.tv_nsec / (1000 * tick);
	if (t)
        {
		ac_exit.ac_mem = (r->ru_ixrss + r->ru_idrss + r->ru_isrss) / t;
        }
	else
        {
		ac_exit.ac_mem = 0;
        }

	/* I/O */
	ac_exit.ac_io = r->ru_inblock + r->ru_oublock;

        /* Ids */
        ac_exit.ac_common.ac_pid = p->ps_pid;
	ac_exit.ac_common.ac_uid = p->ps_ucred->cr_ruid;
	ac_exit.ac_common.ac_gid = p->ps_ucred->cr_rgid;

	/* Starting terminal */
	if ((p->ps_flags & PS_CONTROLT)
                && p->ps_pgrp->pg_session->s_ttyp)
        {
		ac_exit.ac_common.ac_tty =
                        p->ps_pgrp->pg_session->s_ttyp->t_dev;
        }
	else
        {
                ac_exit.ac_common.ac_tty = NODEV;
        }

        /* Termination flags */
	ac_exit.ac_common.ac_flag = p->ps_acflag;

        /* Enqueue */
        ac_entry->ac_type = ACCT_MSG_EXIT;
        ac_entry->acct_t.ac_exit = ac_exit;

        rw_enter_write(&ac_lock);
        TAILQ_INSERT_TAIL(&acct_entries, ac_entry, entry);
        rw_exit_write(&ac_lock);
}

void
acctattach(int num)
{
        return;
}

int
acctopen(dev_t dev, int flag, int mode, struct proc *p)
{
	if (minor(dev) != 0)
        {       
		return (ENXIO);
        }

	if ((flag & FWRITE))
        {
		return (EPERM);
        }

        if (device_opened)
        {
                return (EBUSY);
        }

        rw_enter_write(&ac_lock);
        ac_seq_counter = 0;
        device_opened = 1;
        rw_exit_write(&ac_lock);
        return (0);
}

int
acctclose(dev_t dev, int flag, int mode, struct proc *p)
{
        return 0;
}

int
acctioctl(dev_t dev, u_long cmd, caddr_t data, int fflag, struct proc *p)
{
        printf("ioctl\n");
        return 0;
}

int
handle_acct_fork(struct uio *uio, struct acct_fork fork)
{
        // printf(">> %hu %hu %u %s %i %i %i\n",
        //         fork.ac_common.ac_type,
        //         fork.ac_common.ac_len,
        //         fork.ac_common.ac_seq,
        //         fork.ac_common.ac_comm,
        //         fork.ac_common.ac_pid,
        //         fork.ac_common.ac_uid,
        //         fork.ac_common.ac_gid
        // );

	int error = 0;
        if ((error = uiomove((void *)&fork,
                sizeof(struct acct_fork), uio)) != 0) {
                return error;
        }

        return 0;
}

int
handle_acct_exec(struct uio *uio, struct acct_exec exec)
{
	int error = 0;
        if ((error = uiomove((void *)&exec,
                sizeof(struct acct_exec), uio)) != 0) {
                return error;
        }

        return 0;
}

int
handle_acct_exit(struct uio *uio, struct acct_exit exit)
{
        // printf(">> %hu %hu %u %s %i %i %i\n",
        //         exit.ac_common.ac_type,
        //         exit.ac_common.ac_len,
        //         exit.ac_common.ac_seq,
        //         exit.ac_common.ac_comm,
        //         exit.ac_common.ac_pid,
        //         exit.ac_common.ac_uid,
        //         exit.ac_common.ac_gid
        // );

	int error = 0;
        if ((error = uiomove((void *)&exit,
                sizeof(struct acct_exit), uio)) != 0) {
                return error;
        }

        return 0;
}

int
acctread(dev_t dev, struct uio *uio, int flags)
{
        if (TAILQ_EMPTY(&acct_entries)) {
                printf("queue empty\n");
                return 0;
        }
        
        struct acct_entry *ac_entry = TAILQ_FIRST(&acct_entries);

        TAILQ_REMOVE(&acct_entries, ac_entry, entry);

        int error = 0;

        rw_enter_read(&ac_lock);
        switch (ac_entry->ac_type)
        {       
                case ACCT_MSG_FORK:
                        error = handle_acct_fork(uio, ac_entry->acct_t.ac_fork);
                        break;
                case ACCT_MSG_EXEC:
                        error = handle_acct_exec(uio, ac_entry->acct_t.ac_exec);
                        break;
                case ACCT_MSG_EXIT:
                        error = handle_acct_exit(uio, ac_entry->acct_t.ac_exit);
                        break;
        }
        rw_exit_read(&ac_lock);

        free(ac_entry, M_DEVBUF, sizeof(struct acct_entry));

        return error;
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
