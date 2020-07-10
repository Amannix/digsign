
#define pr_fmt(fmt) "ftrace_hook: " fmt

#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include <linux/string.h>
#include "../../include/ksig/sigver.h"


MODULE_DESCRIPTION("module hooking execve() via ftrace");
MODULE_AUTHOR("xmb");
MODULE_LICENSE("GPL");

 /*
  * 挂接时有两种防止恶性递归循环的方法：
  * 使用函数返回地址（USE_FENTRY_OFFSET = 0）检测响应
  * 通过跳过ftrace调用来避免回避（USE_FENTRY_OFFSET = 1）
  */
#define USE_FENTRY_OFFSET 0

 /**
  * struct ftrace_hook-描述要安装的单个钩子
  *
  * name：要挂接的函数的名称
  * @function：指向要执行的函数的指针
  * @original：指向保存指针的位置的指针
  * 
  * 恢复原始功能
  * @address：函数条目的内核地址
  * @ops：此函数挂钩的ftrace_ops状态
  *
  * 用户只能填写＆name，＆hook，＆orig字段。
  * 其他字段视为实施细节。
  */
struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = kallsyms_lookup_name(hook->name);

	if (!hook->address) {
		pr_debug("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long*) hook->original) = hook->address;
#endif

	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct pt_regs *regs)
{
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
	regs->ip = (unsigned long) hook->function;
#else
	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long) hook->function;
#endif
}

 /**
  * fh_install_hooks（）-注册并启用一个钩子
  * @hook：要安装的钩子
  *
  * 返回：成功则返回零，否则返回负错误代码。
  */
int fh_install_hook(struct ftrace_hook *hook)
{
	int err;
	//备份原地址
	err = fh_resolve_hook_address(hook);
	if (err)
		return err;

    /*
     * 修改％rip寄存器，因此需要IPMODIFY标志
     * 并以SAVE_REGS为前提。 ftrace的抗递归防护
     * 如果更改％rip无效，使用RECURSION_SAFE将其禁用。
     * 将执行自己的跟踪功能重新输入检查。
     */
	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION_SAFE
	                | FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	return 0;
}

/**
 * fh_remove_hooks() - 禁用和注销一个钩子
 * hook: 被注销的hook结构
 */
void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
	}
}

 /**
  * fh_install_hooks（）-注册并启用多个挂钩
  * hooks：要安装的钩子结构体数组
  * count：要安装的挂钩数量
  *
  * 整个挂钩过程必须一次完成，如果某些钩子函数无法安装，则所有挂钩将被删除。
  *
  * 返回：成功则返回零，否则返回负错误代码。
  */
int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err;
	size_t i;

	for (i = 0; i < count; i++) {
		err = fh_install_hook(&hooks[i]);
		if (err)
			goto error;
	}

	return 0;

error:
	while (i != 0) {
		fh_remove_hook(&hooks[--i]);
	}

	return err;
}

 /**
  * fh_remove_hooks（）-禁用和注销多个钩子
  * hooks：要删除的钩子数组
  * count：要删除的挂钩数
  */
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		fh_remove_hook(&hooks[i]);
}

#ifndef CONFIG_X86_64
#error Currently only x86_64 architecture is supported
#endif

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

 /*
  *尾部调用优化可能会干扰基于堆栈上返回地址的递归检测。禁用它以避免机器挂断。
  */
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

static char *duplicate_filename(const char __user *filename)
{
	char *kernel_filename;

	kernel_filename = kmalloc(4096, GFP_KERNEL);
	if (!kernel_filename)
		return NULL;

	if (strncpy_from_user(kernel_filename, filename, 4096) < 0) {
		kfree(kernel_filename);
		return NULL;
	}

	return kernel_filename;
}

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_execve)(struct pt_regs *regs);

static asmlinkage long fh_sys_execve(struct pt_regs *regs)
{
	long ret;
	char *kernel_filename;

	kernel_filename = duplicate_filename((void*) regs->di);

	pr_info("execve() before: %s\n", kernel_filename);

	kfree(kernel_filename);

	ret = real_sys_execve(regs);

	pr_info("execve() after: %ld\n", ret);

	return ret;
}
#else
static asmlinkage long (*real_sys_execve)(
        const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp);

static asmlinkage long fh_sys_execve(
        const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp)
{
	char *kernel_filename;
    long ret;
	kernel_filename = duplicate_filename(filename);
    //printk("%s start", kernel_filename);
    ret = digver(kernel_filename);
    if (ret == FAULTERR){
        kfree(kernel_filename);
        pr_info("%s 验证失败!", kernel_filename);
        return -1;
    } else if (ret == OTHERERR) {
        pr_info("%s 没有加密信息!", kernel_filename);
    } else if (ret == SUCCESS) {
        pr_info("%s 验证成功！", kernel_filename);
    } else {
        pr_info("%s 未知错误", kernel_filename);
    }
    
    ret = real_sys_execve(filename, argv, envp);
    //printk("%s end", kernel_filename);
    kfree(kernel_filename);
	return ret;
}
#endif

/*
 * x86_64 kernels have a special naming convention for syscall entry points in newer kernels.
 * That's what you end up with if an architecture has 3 (three) ABIs for system calls.
 */
#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif

#define HOOK(_name, _function, _original)	\
	{					\
		.name = SYSCALL_NAME(_name),	\
		.function = (_function),	\
		.original = (_original),	\
	}

static struct ftrace_hook demo_hooks[] = {
	HOOK("sys_execve", fh_sys_execve, &real_sys_execve),
};

static int fh_init(void)
{
	int err;
	//struct task_struct *pos;
    //struct list_head *current_head;
    //int count=0;
    printk("Traversal module is working..\n");
    /*
    current_head=&(current->tasks);
    list_for_each_entry(pos,current_head,tasks)
    {
            count++;
            printk("[process %d]: -- %s -- \'s pid is %d\n",count,pos->comm,pos->pid);
    }
    printk(KERN_ALERT"The number of process is:%d\n",count);
    */

	err = fh_install_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
	if (err)
		return err;
	pr_info("module loaded\n");
	return 0;
}
module_init(fh_init);

static void fh_exit(void)
{
	fh_remove_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));

	pr_info("module unloaded\n");
}
module_exit(fh_exit);
