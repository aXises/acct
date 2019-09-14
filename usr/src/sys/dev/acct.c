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
#include <sys/poll.h>

#include <dev/acct.h>

void filt_acct_detach(struct knote *);
int  filt_acct_read(struct knote *, long);

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

struct filterops acct_read_filtops =
	{ 1, NULL, filt_acct_detach, filt_acct_read};

struct selinfo acct_sel;

int ac_seq_counter = 0;

int device_opened = 0;

struct acct_common
generate_acct_common(struct process *p, unsigned short ac_type)
{
        struct acct_common ac_common;
        struct timespec temp;

        rw_enter_write(&ac_lock);
        ac_common.ac_seq = ac_seq_counter;
        ac_seq_counter++;
        rw_exit_write(&ac_lock);

        ac_common.ac_type = ac_type;
        switch (ac_type)
        {
                case ACCT_MSG_FORK:
                        ac_common.ac_len = sizeof(struct acct_fork);
                        break;
                case ACCT_MSG_EXEC:
                        ac_common.ac_len = sizeof(struct acct_exec);
                        break;
                case ACCT_MSG_EXIT:
                        ac_common.ac_len = sizeof(struct acct_exit);
                        break;
        }

        /* Process name */
        memcpy(ac_common.ac_comm, p->ps_comm,
                sizeof(ac_common.ac_comm));

        /* Starting and elapsed time */
	ac_common.ac_btime = p->ps_start;
        nanotime(&temp);
        timespecsub(&temp, &p->ps_start, &ac_common.ac_etime);

        /* Ids */
        ac_common.ac_pid = p->ps_pid;
	ac_common.ac_uid = p->ps_ucred->cr_ruid;
	ac_common.ac_gid = p->ps_ucred->cr_rgid;

	/* Starting terminal */
	if ((p->ps_flags & PS_CONTROLT)
                && p->ps_pgrp->pg_session->s_ttyp)
        {
		ac_common.ac_tty = p->ps_pgrp->pg_session->s_ttyp->t_dev;
        }
	else
        {
                ac_common.ac_tty = NODEV;
        }

        /* Termination flags */
	ac_common.ac_flag = p->ps_acflag;

        return ac_common;
}

void
acct_fork(struct process *p)
{
        struct process *parent;
        struct acct_fork ac_fork;
        struct acct_entry *ac_entry;

        rw_enter_read(&ac_lock);
        if (!device_opened)
        {
                rw_exit_read(&ac_lock);
                return;
        }
        rw_exit_read(&ac_lock);

        parent = p->ps_pptr;
        ac_entry = malloc(sizeof(struct acct_entry), M_DEVBUF, M_WAITOK);

        ac_fork.ac_common = generate_acct_common(parent, ACCT_MSG_FORK);
        ac_fork.ac_cpid = p->ps_pid;

        /* Enqueue */
        ac_entry->ac_type = ACCT_MSG_FORK;
        ac_entry->acct_t.ac_fork = ac_fork;

        rw_enter_write(&ac_lock);
        TAILQ_INSERT_TAIL(&acct_entries, ac_entry, entry);
        rw_exit_write(&ac_lock);

        rw_enter_read(&ac_lock);
        if (!TAILQ_EMPTY(&acct_entries))
        {
                wakeup(&acct_entries);
                selwakeup(&acct_sel);
        }
        rw_exit_read(&ac_lock);
}

void
acct_exec(struct process *p)
{
        struct acct_exec ac_exec;
        struct acct_entry *ac_entry;

        rw_enter_read(&ac_lock);
        if (!device_opened)
        {
                rw_exit_read(&ac_lock);
                return;
        }
        rw_exit_read(&ac_lock);

        ac_entry = malloc(sizeof(struct acct_entry), M_DEVBUF, M_WAITOK);

        ac_exec.ac_common = generate_acct_common(p, ACCT_MSG_EXEC);

        /* Enqueue */
        ac_entry->ac_type = ACCT_MSG_EXEC;
        ac_entry->acct_t.ac_exec = ac_exec;

        rw_enter_write(&ac_lock);
        TAILQ_INSERT_TAIL(&acct_entries, ac_entry, entry);
        rw_exit_write(&ac_lock);

        rw_enter_read(&ac_lock);
        if (!TAILQ_EMPTY(&acct_entries))
        {
                wakeup(&acct_entries);
                selwakeup(&acct_sel);
        }
        rw_exit_read(&ac_lock);
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

        ac_exit.ac_common = generate_acct_common(p, ACCT_MSG_EXIT);

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

        /* Enqueue */
        ac_entry->ac_type = ACCT_MSG_EXIT;
        ac_entry->acct_t.ac_exit = ac_exit;

        rw_enter_write(&ac_lock);
        TAILQ_INSERT_TAIL(&acct_entries, ac_entry, entry);
        rw_exit_write(&ac_lock);

        rw_enter_read(&ac_lock);
        if (!TAILQ_EMPTY(&acct_entries))
        {
                wakeup(&acct_entries);
                selwakeup(&acct_sel);
        }
        rw_exit_read(&ac_lock);
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
        rw_enter_write(&ac_lock);
        ac_seq_counter = 0;
        device_opened = 0;
        rw_exit_write(&ac_lock);

        wakeup(&acct_entries);

        switch (rw_status(&ac_lock))
        {
                case RW_WRITE | RW_WRITE_OTHER:
                        rw_exit_write(&ac_lock);
                        break;
                case RW_READ:
                        rw_exit_read(&ac_lock);
                        break;
        }

        return (0);
}

size_t
get_next_struct_len()
{
        size_t size;
        struct acct_entry *ac_entry;

        size = 0;
        rw_enter_read(&ac_lock);
        
        if (!TAILQ_EMPTY(&acct_entries))
        {
                ac_entry = TAILQ_FIRST(&acct_entries);
                switch (ac_entry->ac_type)
                {
                        case(ACCT_MSG_EXIT):
                                size = sizeof(struct acct_exit);
                                break;
                        case(ACCT_MSG_FORK):
                                size = sizeof(struct acct_fork);
                                break;
                        case(ACCT_MSG_EXEC):
                                size = sizeof(struct acct_exec);
                                break;
                }
        }
        rw_exit_read(&ac_lock);
        return size;
}

int
acctioctl(dev_t dev, u_long cmd, caddr_t data, int fflag, struct proc *p)
{
	int error;
	error = 0;

	switch(cmd)
        {
                case FIONREAD:
                        *(int *)data = get_next_struct_len();
                        break;
	        case FIONBIO:
		/* All handled in the upper FS layer */
		        break;
	        default:
		        error = ENOTTY;
	}
	return (error);
}

int
handle_acct_fork(struct uio *uio, struct acct_fork fork)
{
	int error = 0;
        if ((error = uiomove((void *)&fork,
                sizeof(struct acct_fork), uio)) != 0)
        {
                return error;
        }

        return (0);
}

int
handle_acct_exec(struct uio *uio, struct acct_exec exec)
{
	int error = 0;
        if ((error = uiomove((void *)&exec,
                sizeof(struct acct_exec), uio)) != 0)
        {
                return error;
        }

        return (0);
}

int
handle_acct_exit(struct uio *uio, struct acct_exit exit)
{
	int error = 0;
        if ((error = uiomove((void *)&exit,
                sizeof(struct acct_exit), uio)) != 0)
        {
                return error;
        }

        return (0);
}

int
acctread(dev_t dev, struct uio *uio, int flags)
{
        struct acct_entry *ac_entry;
        int error;

        rw_enter_read(&ac_lock);
        if (!device_opened)
        {
                rw_exit_read(&ac_lock);
                return (0);
        }

        if (TAILQ_EMPTY(&acct_entries))
        {
                rw_exit_read(&ac_lock);
                tsleep(&acct_entries, PWAIT | PCATCH, "acct_q_empty", 0);
                rw_enter_read(&ac_lock);
        }

        if (TAILQ_EMPTY(&acct_entries))
        {
                rw_exit_read(&ac_lock);
                return (0);
        }
        
        ac_entry = TAILQ_FIRST(&acct_entries);

        TAILQ_REMOVE(&acct_entries, ac_entry, entry);

        error = 0;

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

        return (error);
}

int
acctwrite(dev_t dev, int flag, int mode, struct proc *p)
{
        return (EOPNOTSUPP);
}

int
acctpoll(dev_t dev, int events, struct proc *p)
{
        int revents;
        revents = 0;

        if (events & (POLLIN | POLLRDNORM))
        {
                rw_enter_read(&ac_lock);
                if (!TAILQ_EMPTY(&acct_entries))
                {
                        revents |= events & (POLLIN | POLLRDNORM);
                }
                else
                {
                        selrecord(p, &acct_sel);
                }
                rw_exit_read(&ac_lock);
        }

        return (revents);
}

int
acctkqfilter(dev_t dev, struct knote *kn)
{
        struct klist *klist;
	int s;

	switch (kn->kn_filter)
        {
                case EVFILT_READ:
                        klist = &acct_sel.si_note;
                        kn->kn_fop = &acct_read_filtops;
                        break;
                default:
                        return (EINVAL);
	}

	s = splbio();
	SLIST_INSERT_HEAD(klist, kn, kn_selnext);
	splx(s);
	return (0);
}

void
filt_acct_detach(struct knote *kn)
{
	int s;
        rw_enter_write(&ac_lock);
        ac_seq_counter = 0;
        rw_exit_write(&ac_lock);
	s = splbio();
	SLIST_REMOVE(&acct_sel.si_note, kn, knote, kn_selnext);
	splx(s);
}

int
filt_acct_read(struct knote *kn, long hint)
{
	kn->kn_data = TAILQ_EMPTY(&acct_entries);
	return !TAILQ_EMPTY(&acct_entries);
}

