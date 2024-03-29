/*
* 
* This is free software; you can redistribute it and/or modify it under the
* terms of the GNU General Public License as published by the Free Software
* Foundation; either version 3 of the License, or (at your option) any later
* version.
* 
* This module is distributed in the hope that it will be useful, but WITHOUT ANY
* WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
* A PARTICULAR PURPOSE. See the GNU General Public License for more details.
*  
* @brief This is the main source for a kernel level reference monitor for file protection.
*
* @author Simone Bauco
*
* @date March 13, 2024
*/

#define EXPORT_SYMTAB
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/cred.h>
#include <linux/crypto.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/apic.h>
#include <asm/io.h>
#include <linux/syscalls.h>
#include "lib/include/scth.h"
#include <linux/err.h>
#include <linux/unistd.h>
#include <linux/uaccess.h>
#include <crypto/hash.h>
#include <linux/spinlock.h>
#include <linux/kprobes.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/file.h>
#include <linux/limits.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/dcache.h>
#include <linux/fs_struct.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Simone Bauco");
MODULE_DESCRIPTION("Kernel Level Reference Monitor for File Protection");

#define MODNAME "REFERENCE MONITOR"
#define PASSW_LEN 32
#define AUDIT if(1)
#define NUM_KRETPROBES 6

/* the first 6 arguments in rdi, rsi, rdx, rcx, r8, r9 */

/* FUNCTIONS TO BE PROBED 
*       int do_unlinkat(int dfd, struct filename *name)
*       int do_renameat2(int olddfd, struct filename *from, int newdfd, struct filename *to, unsigned int flags)
*       int do_linkat(int olddfd, struct filename *old, int newdfd, struct filename *new, int flags)
*       int do_symlinkat(struct filename *from, int newdfd, struct filename *to)
*       int do_mkdirat(int dfd, struct filename *name, umode_t mode)
*/

char *encrypt_password(const char *password);


struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};

/* kretprobes structs */
static struct kretprobe do_filp_open_retprobe;
static struct kretprobe do_unlinkat_retprobe;
static struct kretprobe do_renameat2_retprobe;
static struct kretprobe do_symlinkat_retprobe;
static struct kretprobe do_linkat_retprobe;
static struct kretprobe do_mkdirat_retprobe;

struct kretprobe **rps; /* kretprobes array */

struct blacklist_entry {
        struct list_head list;
        char *path;
        char *filename;
};

struct blacklist_dir_entry {
        struct list_head list;
        char *path;
};

/** @struct reference_monitor
 *  @brief Reference Monitor Basic Structure
 */
struct reference_monitor {
        int state;                              /**< The state can be one of the following: OFF (0), ON (1), REC-OFF (2), REC-ON (3)*/
        char *password;                         /**< Password for Reference Monitor reconfiguration */
        struct list_head blacklist;             /**< Files to be protected */
        struct list_head blacklist_dir;         /**< Directories to be protected */
        spinlock_t lock;                        /**< Lock for synchronization */
} reference_monitor;


/* reference monitor password, to be checked when switching to states REC-ON and REC-OFF */
char password[PASSW_LEN];
module_param_string(password, password, PASSW_LEN, 0);

/* syscall table base address */
unsigned long the_syscall_table = 0x0;
module_param(the_syscall_table, ulong, 0660);

unsigned long the_ni_syscall;

unsigned long new_sys_call_array[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};                 /* new syscalls addresses array */
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array)/sizeof(unsigned long))  /* number of entries to be hacked */
int restore[HACKED_ENTRIES] = {[0 ... (HACKED_ENTRIES-1)] -1};                  /* array of free entries on the syscall table */


/* UTILS */

char *get_full_path(char *rel_path) {

        pr_info("%s: finding full path for %s\n", MODNAME, rel_path);

        char *k_full_path = NULL;
        struct path path;
        int ret;

        k_full_path = kmalloc(PATH_MAX, GFP_KERNEL);
        if (!k_full_path) {
                pr_err("%s: error in kmalloc (get_full_path)\n", MODNAME);
                return NULL; 
        }

        ret = kern_path(rel_path, LOOKUP_FOLLOW, &path);
        if (ret == -ENOENT) {
                ret = kern_path(strcat(rel_path, "~"), LOOKUP_FOLLOW, &path);
        }
        if (ret) {
                pr_err("%s: full path not found (error %d)\n", MODNAME, ret);
                return NULL;
        }

        ret = snprintf(k_full_path, PATH_MAX, "%s", d_path(&path, k_full_path, PATH_MAX));
        if (ret < 0 || ret >= PATH_MAX) {
                kfree(k_full_path);
                pr_err("%s: full path is too long\n", MODNAME);
        }

        char *tilde_pos = strrchr(k_full_path, '~');
        if (tilde_pos != NULL) {
                *tilde_pos = '\0'; 
        }

        pr_info("%s: full path is %s\n", MODNAME, k_full_path);

        return k_full_path;
}


/* SYSCALL UTILS */

int is_directory(char *path) {
        struct path p;
        int error;
        struct inode *inode;

        error = kern_path(path, LOOKUP_FOLLOW, &p);
        if(error) {
                pr_err("%s: error in kern_path (is_directory)\n", MODNAME);
        }
        inode = p.dentry->d_inode;

        return S_ISDIR(inode->i_mode);
}

int add_dir_to_rm(char *path) {
        struct blacklist_dir_entry *new_entry;

        new_entry = kmalloc(sizeof(struct blacklist_dir_entry), GFP_KERNEL);
        if (!new_entry) {
                pr_err("%s: error in kmalloc allocation (add_dir_to_rm)\n", MODNAME);
                return -ENOMEM;
        }

        new_entry->path = kstrdup(path, GFP_KERNEL);
        if (!new_entry->path) {
                kfree(new_entry);
                pr_err("%s: error in kstrdup (add_dir_to_rm)\n", MODNAME);
                return -ENOMEM;
        }

        spin_lock(&reference_monitor.lock);
        list_add_tail(&new_entry->list, &reference_monitor.blacklist_dir);
        spin_unlock(&reference_monitor.lock);

        return 0;
}

int add_file_to_rf(char *path, char *rel_path) {

        struct blacklist_entry *new_entry;

        new_entry = kmalloc(sizeof(struct blacklist_entry), GFP_KERNEL);
        if (!new_entry) {
                pr_err("%s: error in kmalloc allocation (add_file_to_rf)\n", MODNAME);
                return -ENOMEM;
        }

        new_entry->path = kstrdup(path, GFP_KERNEL);
        if (!new_entry->path) {
                kfree(new_entry);
                pr_err("%s: error in kstrdup (add_file_to_rf)\n", MODNAME);
                return -ENOMEM;
        }

        new_entry->filename = kstrdup(kbasename(rel_path), GFP_KERNEL);
        if (!new_entry->filename) {
                kfree(new_entry);
                pr_err("%s: error in kstrdup (add_file_to_rf)\n", MODNAME);
                return -ENOMEM;
        }


        spin_lock(&reference_monitor.lock);
        list_add_tail(&new_entry->list, &reference_monitor.blacklist);
        spin_unlock(&reference_monitor.lock);

        return 0;
}

struct custom_dir_context {
    struct dir_context dir_ctx; 
    char *dir_path; 
};

int add_directory_to_rf(struct file *dir, char *dir_name);

static bool process_dir_entry(struct dir_context *dir, const char *name, int name_len,
                        loff_t offset, u64 ino, unsigned int d_type) {

        /* retrieve base dir path from struct custom_dir_context */
        struct custom_dir_context *custom_ctx = container_of(dir, struct custom_dir_context, dir_ctx);
        char *full_path = kmalloc(sizeof(char)*PATH_MAX, GFP_KERNEL);
        if (!full_path) {
                pr_err("%s: kmalloc allocation error (process_dir_entry)\n", MODNAME);
                return false;
        }
        strcpy(full_path, custom_ctx->dir_path);

        /* get file/subdirectory name */
        char *file_name = kmalloc(name_len + 1, GFP_KERNEL);
        if (!file_name) {
                pr_err("%s: kmalloc allocation error (process_dir_entry)\n", MODNAME);
                kfree(full_path);
                return false;
        }
        strncpy(file_name, name, name_len);
        file_name[name_len] = '\0'; 

        /* exclude current and parent directories */
        if (strcmp(file_name, ".") && strcmp(file_name, "..")) {

                /* reconstruct file/subdirectory path */
                strcat(full_path, "/");
                strcat(full_path, file_name);


                if (d_type == DT_DIR) {         /* subdirectory */
                        
                        struct file *subdir = filp_open(full_path, O_RDONLY, 0);
                        
                        if (IS_ERR(subdir)) {
                                pr_err("%s: error in opening file %s\n", MODNAME, file_name);
                                return PTR_ERR(subdir);
                        }

                        add_directory_to_rf(subdir, full_path);
                        
                } else {        /* file */

                        add_file_to_rf(full_path, file_name);

                }

        }

        kfree(full_path);
        kfree(file_name);

        return true;

}


int add_directory_to_rf(struct file *dir, char *dir_path) {

        /* add directory path to blacklist */
        add_dir_to_rm(dir_path);

        struct custom_dir_context ctx = {
                .dir_ctx = {.actor = &process_dir_entry},
                .dir_path = dir_path
        };
        iterate_dir(dir, &ctx.dir_ctx);

        return 0;
}


/* NEW SYSCALLS DEFINITION */

/* add path to reference monitor syscall */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(1, _add_path_to_rf, char *, rel_path) {
#else 
asmlinkage long sys_add_path_to_rf(char *rel_path) {
#endif
        if (reference_monitor.state < 2) {
                printk(KERN_ERR "%s: the reference monitor is not in a reconfiguration state\n", MODNAME);
                return -EACCES;  // todo is EACCES correct?
        }

        char *path = get_full_path(rel_path);
        if (path == NULL) {
                pr_err("%s: error in getting full path\n", MODNAME);
                return -ENOENT;
        }

        pr_info("%s: adding path %s\n", MODNAME, path);

        //#ifdef FILES_ONLY
        if (is_directory(path)) {
                struct file *dir = filp_open(path, O_RDONLY, 0);
                if (IS_ERR(dir)) {
                        pr_err("%s: error in opening file %s\n", MODNAME, path);
                        return PTR_ERR(dir);
                }

                add_directory_to_rf(dir, path);

                filp_close(dir, NULL);

        } else {
                add_file_to_rf(path, rel_path);
        }
        //#else
        //add_file_to_rf(path, rel_path);
        //#endif

        return 0;
}


/* remove path from reference monitor syscall */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(1, _remove_path_from_rf, char *, path) {
#else 
asmlinkage long sys_remove_path_from_rf(char *path) {
#endif

        struct blacklist_entry *entry, *temp;

        spin_lock(&reference_monitor.lock);
        list_for_each_entry_safe(entry, temp, &reference_monitor.blacklist, list) {
                if (strcmp(entry->path, path) == 0) {
                list_del(&entry->list);
                kfree(entry->path);
                kfree(entry);
                }
        }
        spin_unlock(&reference_monitor.lock);

        return 0;
}


/* print black_list (only for debug) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(1, _print_black_list, int, none) {
#else
asmlinkage long sys_print_black_list(void) {
#endif

        struct blacklist_entry *entry;
        printk(KERN_INFO "Blacklist contents (files):\n");
        list_for_each_entry(entry, &reference_monitor.blacklist, list) {
                printk(KERN_INFO "path = %s, filename = %s\n", entry->path, entry->filename);
        }

        struct blacklist_dir_entry *dir_entry;
        printk(KERN_INFO "Blacklist contents (directories):\n");
        list_for_each_entry(dir_entry, &reference_monitor.blacklist_dir, list) {
                printk(KERN_INFO "path = %s\n", dir_entry->path);
        }

        return 0;
}


/* read state syscall */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(1, _read_rf_state, int, none) {
#else
asmlinkage long sys_read_rf_state(void) {
#endif
        printk("%s: The state is %d\n", MODNAME, reference_monitor.state);

	return reference_monitor.state;
	
}


/* update state syscall */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) 
__SYSCALL_DEFINEx(2, _write_rf_state, int, state, char*, password) {
#else
asmlinkage long sys_write_rf_state(int state) {
#endif 

        /* check state number */
        if (state < 0 || state > 3) {
                printk(KERN_ERR "%s: Unexpected state", MODNAME);
                return -EINVAL;
        }


        /* check state number */
        if (state < 0 || state > 3) {
                printk(KERN_ERR "%s: Unexpected state", MODNAME);
                return -EINVAL;
        }

        kuid_t euid = current_euid();

        /* check EUID */
        if (!uid_eq(euid, GLOBAL_ROOT_UID)) {
                printk(KERN_ERR "%s: Access denied: only root (EUID 0) can change the state\n", MODNAME);
                printk(KERN_ERR "%s: Access denied: only root (EUID 0) can change the state\n", MODNAME);
                return -EPERM;
        }   

        /* if requested state is REC-ON or REC-OFF, check password */
        if (state > 1) {
                if (strcmp(reference_monitor.password, encrypt_password(password)) != 0) {
                        printk(KERN_ERR "%s: Access denied: invalid password\n", MODNAME);
                        return -EACCES;
                }
        }

        spin_lock(&reference_monitor.lock);

        /* state update */
        printk("%s: password check successful, changing the state to %d\n", MODNAME, state);
        reference_monitor.state = state;

        spin_unlock(&reference_monitor.lock);

        /*
        if (state == 1 || state == 3) {
                enable_kprobe(&kp);     // the reference monitor has been turned on 
                printk(KERN_INFO "%s: kprobe enabled\n", MODNAME);
        } else {
                disable_kprobe(&kp);    // the reference monitor has been turned off
                printk(KERN_INFO "%s: kprobe disabled\n", MODNAME); 
        }*/
        
        return reference_monitor.state;
        
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
long sys_read_state = (unsigned long) __x64_sys_read_rf_state;   
long sys_write_state = (unsigned long) __x64_sys_write_rf_state;    
long sys_add_to_blacklist = (unsigned long) __x64_sys_add_path_to_rf;
long sys_remove_from_blacklist = (unsigned long) __x64_sys_remove_path_from_rf;
long sys_print_blacklist = (unsigned long) __x64_sys_print_black_list;
#else
#endif

/* UTILS */

static char *get_dir_path_from_fd(int fd) {

        struct file *file;
        char *buffer, *path_name;
        int ret;

        file = fget(fd);
        if (!file) {
                printk(KERN_ERR "Failed to get file from file descriptor\n");
                return NULL;
        }

        struct path p = file->f_path;
        struct dentry *d = p.dentry;

        buffer = (char *)__get_free_page(GFP_KERNEL);
        if (!buffer)
                return NULL;
        path_name = dentry_path_raw(d, buffer, PAGE_SIZE);

        if (IS_ERR(path_name))
                printk(KERN_ERR "ERR");

        if ((ret=kern_path(path_name, LOOKUP_FOLLOW, &p))) {
                printk("kern_path returned %d for path_name \"%s\", inode %ld\n", ret, path_name, d->d_inode->i_ino);
                return NULL;
        }

        free_page((unsigned long)buffer);

        return strcat(path_name, "/");
}

static char *get_full_path_from_fd(int fd, char *filename) {

        pr_info("%s: requested full path computation for file %s\n", MODNAME, filename);

        /* get parent directory full path */
        char *dir = get_dir_path_from_fd(fd);
        if (!dir) {
                pr_err("%s: failed to get dir path\n", MODNAME);
                return NULL;
        }

        /* concatenate parent directory and filename */
        char *full_path = strcat(dir, filename);

        pr_info("%s: full path is %s\n", MODNAME, full_path);
        return full_path;
}


/**
 * Check if this file is blacklisted, retrieve full path from filename
*/
int is_blacklisted(char *filename) {
        struct blacklist_entry *entry;
        list_for_each_entry(entry, &reference_monitor.blacklist, list) {

                if (!strcmp(kbasename(filename), entry->filename)) {
                        char *full_path = get_full_path(filename);
                        if (full_path == NULL) {
                                pr_err("%s: full path not found for filename %s\n", MODNAME, filename);
                                return 0;
                        }

                        /* check if file is blacklisted */
                        if (!strcmp(full_path, entry->path)) {
                                return 1;
                        }

                        /* check if file belongs to a blacklisted directory */
                        //else if (strstr(full_path, entry->path) != NULL) {
                        //        return 1;
                        //}
                }
                
        }

        return 0;
}


/**
 * Check if this file is blacklisted, retrieve full path from file descriptor
*/
int is_blacklisted_fd(char *path, int fd) {
        struct blacklist_entry *entry;
        list_for_each_entry(entry, &reference_monitor.blacklist, list) {

                if (!strcmp(kbasename(path), entry->filename)) {

                        char *full_path = get_full_path_from_fd(fd, path);
                        if (full_path == NULL) {
                                pr_err("%s: full path not found for filename %s\n", MODNAME, path);
                                return 0;
                        }
                                
                        /* check if file is blacklisted */    
                        if (!strcmp(full_path, entry->path)) {
                                return 1;
                        }

                        /* check if file belongs to a blacklisted directory */
                        //else if (strstr(full_path, entry->path) != NULL) {
                        //        return 1;
                        //}
                }
        }

        return 0;
}

int is_blacklisted_dir(char *path) {

        struct blacklist_dir_entry *entry;
        list_for_each_entry(entry, &reference_monitor.blacklist_dir, list) {
                if (strstr(path, entry->path) != NULL) {
                        return 1;
                }
        }

        return 0;
}


/* REFERENCE MONITOR
 * The following functions implement the core functionalities of the reference monitor. 
*/

static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
        
        pr_info("%s: Access denied\n", MODNAME);
        regs->ax = -EACCES;

        return 0;
}


static int do_unlinkat_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {

        /* get path and open flags from the registers snapshot */
        struct filename *fn = (struct filename *)regs->si;
        char *filename = fn->name;

        int dfd = (int)regs->di;

        /* check if this path belongs to the blacklist */
        if (dfd == AT_FDCWD) {
                if (is_blacklisted(filename)) {
                        regs->di = -1;
                        return 0;
                }
        } else {
                if (is_blacklisted_fd(filename, dfd)) {
                        regs->di = -1;
                        return 0;
                }
        }

        return 1;
}

char *get_current_working_directory(char *path) {
        struct path abs_path;
        char *buffer, *full_path;

        buffer = (char *)__get_free_page(GFP_KERNEL);
        if (!buffer)
                return NULL;

        get_fs_pwd(current->fs, &abs_path);

        full_path = dentry_path_raw(abs_path.dentry, buffer, PATH_MAX);
        if (IS_ERR(full_path)) {
                pr_err("dentry_path_raw failed: %li", PTR_ERR(full_path));
        } 

        free_page((unsigned long)buffer);
        path_put(&abs_path);

        strcat(full_path, "/");
        strcat(full_path, path);

        return full_path;
}


static int do_filp_open_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {

        /* get path and open flags from the registers snapshot */
        struct filename *fn = (struct filename *)regs->si;
        char *path = fn->name;

        struct open_flags *flags = (struct open_flags *)regs->dx;
        int flag = flags->open_flag; 

        if (flag & O_CREAT) {
                
                char *full_path;

                if (path[0] != '/') {
                        full_path = get_current_working_directory(path);
                        pr_info("%s, path = %s\n", full_path, path);
                } else {
                        full_path = path;
                }

                
                if (is_blacklisted_dir(full_path)) {
                        pr_info("%s: tried to create a file in protected directory %s\n", MODNAME, full_path);
                        const struct open_flags of = {
                                .open_flag = 0,
                                .mode = (umode_t)0,
                                .acc_mode = 0,
                                .intent = 0,
                                .lookup_flags = 0
                        };
                        
                        regs->dx = (unsigned long)&of;
                        return 0;
                }
        
        }

        if (flag & O_RDWR || flag & O_WRONLY) {

                /* if the path belongs to the blacklist, schedule the return handler */
                if (is_blacklisted(path)) {
                        return 0;       /* schedule return handler execution */
                }
        }

        return 1;       /* the path is not blacklisted or it is opened in read mode, so the return handler will not be executed */
   
}

static int do_mkdirat_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {

        /* get path and open flags from the registers snapshot */
        struct filename *fn = (struct filename *)regs->si;
        char *path = fn->name;

        char *full_path;

        if (path[0] != '/') {
                full_path = get_current_working_directory(path);
                pr_info("%s, path = %s\n", full_path, path);
        } else {
                full_path = path;
        }

        
        if (is_blacklisted_dir(full_path)) {
                pr_info("%s: tried to create a directory in protected directory %s\n", MODNAME, full_path);
                regs->si = 0777;
                return 0;
        }

        return 1;
        
}

static int do_renameat2_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {

        struct filename *from = (struct filename *)regs->si;
        char *path = from->name;

        if (is_blacklisted(path)) {
                regs->di = -1;
                pr_info("%s: Detected try to move the blacklisted file %s\n", MODNAME, path);
                return 0;
        }

        return 1;
}

static int do_linkat_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
        struct filename *old = (struct filename *)regs->si;
        char *path = old->name;

        int dfd = (int)regs->di;

        if (dfd == AT_FDCWD) {
                if (is_blacklisted(path)) {
                        regs->di = -1;
                        pr_info("%s: Detected try to create a hard link for a blacklisted file %s\n", MODNAME, path);
                        return 0;
                } 
        } else {
                if (is_blacklisted_fd(path, dfd)) {
                        regs->di = -1;
                        pr_info("%s: Detected try to create a hard link for a blacklisted file %s\n", MODNAME, path);
                        return 0;
                } 
        }

        return 1;
}

static int do_symlinkat_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
        struct filename *from = (struct filename *)regs->di;
        char *path = from->name;

        if (is_blacklisted(path)) {
                regs->si = -1;
                pr_info("%s: Detected try to create a symbolic link for a blacklisted file %s\n", MODNAME, path);
                return 0;
        }

        return 1;
}


/* UTILS */
static void set_kretprobe(struct kretprobe *krp, char *symbol_name, kretprobe_handler_t entry_handler) {
        krp->kp.symbol_name = symbol_name;
        krp->handler = (kretprobe_handler_t)ret_handler;
        krp->entry_handler = entry_handler;
        krp->maxactive = -1;
}


static int kretprobe_init(void)
{
        int ret;

        set_kretprobe(&do_filp_open_retprobe, "do_filp_open", (kretprobe_handler_t)do_filp_open_handler);
        set_kretprobe(&do_unlinkat_retprobe, "do_unlinkat", (kretprobe_handler_t)do_unlinkat_handler);
        set_kretprobe(&do_renameat2_retprobe, "do_renameat2", (kretprobe_handler_t)do_renameat2_handler);
        set_kretprobe(&do_linkat_retprobe, "do_linkat", (kretprobe_handler_t)do_linkat_handler);
        set_kretprobe(&do_symlinkat_retprobe, "do_symlinkat", (kretprobe_handler_t)do_symlinkat_handler);
        set_kretprobe(&do_mkdirat_retprobe, "do_mkdirat", (kretprobe_handler_t)do_mkdirat_handler);

        rps = kmalloc(NUM_KRETPROBES*sizeof(struct kretprobe *), GFP_KERNEL);
        if (rps == NULL) {
                pr_err("%s: kmalloc allocation of rps failed\n", MODNAME);
                return -ENOMEM;
        }
        

        rps[0] = &do_filp_open_retprobe;
        rps[1] = &do_unlinkat_retprobe;
        rps[2] = &do_renameat2_retprobe;
        rps[3] = &do_linkat_retprobe;
        rps[4] = &do_symlinkat_retprobe;
        rps[5] = &do_mkdirat_retprobe;

	ret = register_kretprobes(rps, NUM_KRETPROBES);
	if (ret < 0) {
		printk("%s: kretprobes registration failed, returned %d\n", MODNAME, ret);
		return ret;
	}
	printk("%s: kretprobes correctly installed\n", MODNAME);

	return 0;
}


/* INITIALIZATION FUNCTIONS 
 * the following functions are used in the module's initialization phase,
 * in order to initialize the syscalls and encrypt the reference monitor password.
*/


/**
 * @brief This function adds the new syscalls to the syscall table's free entries
*/
int initialize_syscalls(void) {
        int i;
        int ret;

        if (the_syscall_table == 0x0){
           printk("%s: cannot manage sys_call_table address set to 0x0\n",MODNAME);
           return -1;
        }

	AUDIT{
	   printk("%s: the syscall table base address is %px\n",MODNAME,(void*)the_syscall_table);
     	   printk("%s: initializing - hacked entries %d\n",MODNAME,HACKED_ENTRIES);
	}

	new_sys_call_array[0] = (unsigned long)sys_read_state; 
        new_sys_call_array[1] = (unsigned long)sys_write_state;
        new_sys_call_array[2] = (unsigned long)sys_add_to_blacklist;
        new_sys_call_array[3] = (unsigned long)sys_remove_from_blacklist;
        new_sys_call_array[4] = (unsigned long)sys_print_blacklist;

        /* get free entries on the syscall table */
        ret = get_entries(restore,HACKED_ENTRIES,(unsigned long*)the_syscall_table,&the_ni_syscall);

        if (ret != HACKED_ENTRIES){
                printk("%s: could not hack %d entries (just %d)\n",MODNAME,HACKED_ENTRIES,ret); 
                return -1;      
        }

	unprotect_memory();

        /* the free entries will point to the new syscalls */
        for(i=0;i<HACKED_ENTRIES;i++){
                ((unsigned long *)the_syscall_table)[restore[i]] = (unsigned long)new_sys_call_array[i];
        }

	protect_memory();

        printk("%s: all new system-calls correctly installed on sys-call table\n",MODNAME);

        return 0;
}

/**
 * @brief Password encryption (SHA256)
 * @param password Password to be encrypted
 * @returns Encrypted password
 */
char *encrypt_password(const char *password) {  
        struct crypto_shash *hash_tfm;
        struct shash_desc *desc;
        unsigned char *digest;
        char *result = NULL;
        int ret = -ENOMEM;

        /* hash transform allocation */
        hash_tfm = crypto_alloc_shash("sha256", 0, 0);
        if (IS_ERR(hash_tfm)) {
                printk(KERN_ERR "Failed to allocate hash transform\n");
                return NULL;
        }

        /* hash descriptor allocation */
        desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(hash_tfm), GFP_KERNEL);
        if (!desc) {
                printk(KERN_ERR "Failed to allocate hash descriptor\n");
                goto out;
        }
        desc->tfm = hash_tfm;

        /* digest allocation */
        digest = kmalloc(32, GFP_KERNEL);
        if (!digest) {
                printk(KERN_ERR "Failed to allocate hash buffer\n");
                goto out;
        }

        /* hash computation */
        ret = crypto_shash_digest(desc, password, strlen(password), digest);
        if (ret) {
                printk(KERN_ERR "Failed to calculate hash\n");
                goto out;
        }

        /* result allocation */
        result = kmalloc(2 * 32 + 1, GFP_KERNEL);
        if (!result) {
                printk(KERN_ERR "Failed to allocate memory for result\n");
                goto out;
        }

        /* printing result */
        for (int i = 0; i < 32; i++)
                sprintf(&result[i * 2], "%02x", digest[i]);
        
out:
        if (digest)
                kfree(digest);
        if (desc)
                kfree(desc);
        if (hash_tfm)
                crypto_free_shash(hash_tfm);


        return result;
}


int init_module(void) {

        int ret;

        /* SYSCALL TABLE UPDATE (NEW SYSCALL INSERTION) */
        ret = initialize_syscalls();
        if (ret != 0) {
                return ret;
        }

        /* REFERENCE MONITOR INITIALIZATION */
        printk("%s: setting initial state to OFF (0)\n", MODNAME);
        reference_monitor.state = 0;

        INIT_LIST_HEAD(&reference_monitor.blacklist);
        INIT_LIST_HEAD(&reference_monitor.blacklist_dir);
        
        DEFINE_SPINLOCK(lock);
        reference_monitor.lock = lock;

        /* PASSWORD SETUP */
        char *enc_password = encrypt_password(password); 
        reference_monitor.password = enc_password;

        /* KPROBES INITIALIZATION */
        kretprobe_init();

        return 0;

}


void cleanup_module(void) {

        int i;
                
        printk("%s: shutting down\n",MODNAME);

        /* syscall table restoration */
	unprotect_memory();
        for(i=0;i<HACKED_ENTRIES;i++){
                ((unsigned long *)the_syscall_table)[restore[i]] = the_ni_syscall;
        }
	protect_memory();
        printk("%s: sys-call table restored to its original content\n",MODNAME);

        /* kretprobes unregistration*/
        for (int i = 0; i < NUM_KRETPROBES; i++) {
                printk(KERN_INFO "Missed probing %d instances of %s\n", rps[i]->nmissed, rps[i]->kp.symbol_name);
        }
        unregister_kretprobes(rps, NUM_KRETPROBES);
        
}
