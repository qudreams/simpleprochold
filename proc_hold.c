/*
 * selfhold_proc.c: 2019-02-18 created by qudreams
 * self-hold for process
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/vermagic.h>


#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,23)
    #define PID(ts) task_tgid_vnr(ts)
#else
    #define PID(ts) ((ts)->tgid)
#endif

static int client_pid = -1;


//SIGNAL_UNKILLABLE is added from 2.6.26
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
static int do_hold_one_proc(struct pid* spid)
{
	int rc = -ESRCH;
    unsigned int* pflags = NULL;
    struct task_struct* task = NULL;
    struct signal_struct* sig = NULL;
    struct sighand_struct *sighand = NULL;

    task = pid_task(spid,PIDTYPE_PID);
    if(!task) { goto out; }

    sig = task->signal;
    if(!sig) { goto out; }

    sighand = task->sighand;
    spin_lock_irq(&sighand->siglock);
    pflags = &(sig->flags);
    if(pflags) {
    	*pflags |= SIGNAL_UNKILLABLE;
    	rc = 0;
    }
    spin_unlock_irq(&sighand->siglock);

out:
	return rc;
}

int hold_one_proc(pid_t pid)
{
    int rc = -ESRCH;
	struct pid* spid = NULL;

    if(pid <= 0) { goto out; }

	spid = find_get_pid(pid);
	if(!spid) { goto out; }

	rcu_read_lock();
	rc = do_hold_one_proc(spid);
	rcu_read_unlock();

out:
	if(spid) { put_pid(spid); }
    return rc;
}

static int do_unhold_one_proc(struct pid* spid)
{
	int rc = -ESRCH;
	unsigned int* pflags = NULL;
	struct task_struct* task = NULL;
	struct signal_struct* sig = NULL;
	struct sighand_struct *sighand = NULL;

	task = pid_task(spid,PIDTYPE_PID);
	if(!task) { goto out; }

	sig = task->signal;
	if(!sig) { goto out; }

	sighand = task->sighand;
	spin_lock_irq(&sighand->siglock);
	pflags = &(sig->flags);
	if(pflags) {
		*pflags &= ~SIGNAL_UNKILLABLE;
		rc = 0;
	}
	spin_unlock_irq(&sighand->siglock);

out:
	return rc;
}

int unhold_one_proc(pid_t pid)
{
	int rc = -ESRCH;
	struct pid* spid = NULL;

	if(pid <= 0) { goto out; }

	spid = find_get_pid(pid);
	if(!spid) { goto out; }

	rcu_read_lock();
	rc = do_unhold_one_proc(spid);
	rcu_read_unlock();

out:
	if(spid) { put_pid(spid); }
	return rc;
}

int start_proc_hold(void)
{
    return 0;
}

void finish_proc_hold(void)
{
    (void)xchg(&client_pid,0);
}

#else
extern struct security_operations *security_ops;
typedef int (*task_kill_handler_t)(struct task_struct*,struct siginfo*,int,u32);
task_kill_handler_t org_handler = NULL;

static int is_care_signal(int sig)
{
	int is_care = 0;

    is_care = (sig == SIGINT ||
               sig == SIGTERM ||
               sig == SIGQUIT ||
               sig == SIGABRT);
    return is_care;
}

static int is_self_hold_client(pid_t pid)
{
	return unlikely(pid == client_pid);
}

//send by sigqueue
#define SI_FROMQUEUE(siptr) ((siptr)->si_code == SI_QUEUE)

static int need_intercept(pid_t pid,int sig,struct siginfo* info)
{
    pid_t spid = 0; //the pid of sender
    int intercept = 0;

    //target pid is not valid
    if(pid <= 0) { goto out; }
    //the sig may be 0,it suppose that
    //just check process,don't kill process really
    if(sig <= 0) { goto out; }

    //is special signal info?
    if(is_si_special(info)) {
        goto out;
    }

    //is the signal from kernel?
    if(SI_FROMKERNEL(info)) {
        goto out;
    }

    //is the target us?
    if(!is_self_hold_client(pid)) {
        goto out;
    }

    //is the signal from myself
    spid = info->si_pid;
    if(is_self_hold_client(spid)) {
        goto out;
    }

    //we just recive signal sent by sigqueue
    intercept = !SI_FROMQUEUE(info);
    if(intercept) { goto out; }

    intercept = !is_care_signal(sig);
    if(intercept) { goto out; }

out:
	return intercept;
}

static int hold_task_kill(struct task_struct* p,struct siginfo* info,int sig,u32 secid)
{
    int rc = -EFAULT;
    int intercept = 0;
    pid_t pid = PID(p); //the pid of target

    int gotmod = try_module_get(THIS_MODULE);
    if(!gotmod) { return rc; }

    rc = -EPERM;
    intercept = need_intercept(pid,sig,info);
    if(!intercept) { goto out; }

    printk("hold task kill:pid:%d,signal: %d\n",pid,sig);

out:
    if(!intercept) { rc = org_handler(p,info,sig,secid); }
    module_put(THIS_MODULE);

    return rc;
}

static void disable_kernel_preempt(void)
{
    preempt_disable();
    barrier();
}

static void enable_kernel_preempt(void)
{
    barrier();
    preempt_enable();
}

int start_proc_hold(void)
{
    int rc = -EFAULT;
    task_kill_handler_t old_handler = NULL;

    rc = -EFAULT;

    disable_kernel_preempt();

    if(!security_ops) { goto out; }
    (void)xchg(&old_handler,security_ops->task_kill);
    if(!old_handler) { goto out; }

    //save original task_kill handler
    org_handler = cmpxchg(&security_ops->task_kill,
                        old_handler,hold_task_kill);
    if(org_handler != old_handler) { goto out; }
    rc = 0;

out:
    enable_kernel_preempt();

    return rc;
}

int hold_one_proc(pid_t pid)
{
    return 0;
}

int unhold_one_proc(pid_t pid)
{
    return 0;
}

void finish_proc_hold(void)
{

    disable_kernel_preempt();
    //restore it
    (void)cmpxchg(&security_ops->task_kill,
                hold_task_kill,org_handler);
    (void)xchg(&client_pid,0);
    enable_kernel_preempt();
}

#endif

#define DEVICE_NAME     "prochold"

static int __init prochold_init(void)
{
    int rc = 0;
    printk("-----Start prochold,"
        "kernel-version: %s\n",UTS_RELEASE);

    rc = start_proc_hold();
    if(rc) { return rc; }

    rc = hold_one_proc(client_pid);
    if(rc) { finish_proc_hold(); }

    return rc;
}

static void __exit prochold_exit(void)
{
    printk("-----exit proc_hold-----\n");
    unhold_one_proc(client_pid);
    finish_proc_hold();
}

module_init(prochold_init);
module_exit(prochold_exit);

module_param(client_pid,int,0);
MODULE_PARM_DESC(client_pid, "hold process pid");

MODULE_LICENSE("GPL");
MODULE_AUTHOR("qudreams");
MODULE_DESCRIPTION(DEVICE_NAME);
MODULE_VERSION(DEVICE_VERSION);
