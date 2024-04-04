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
#include <linux/vmalloc.h>
#include <linux/cred.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/apic.h>
#include <asm/io.h>
#include <linux/syscalls.h>
#include <linux/err.h>
#include <linux/unistd.h>
#include <linux/spinlock.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/file.h>
#include <linux/limits.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/dcache.h>
#include <linux/fs_struct.h>
#include <linux/path.h>

#include "lib/include/scth.h"
#include "reference-monitor.h"
#include "utils.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Simone Bauco");
MODULE_DESCRIPTION("Kernel Level Reference Monitor for File Protection");

/* kretprobes structs */
static struct kretprobe vfs_open_retprobe;
static struct kretprobe do_unlinkat_retprobe;
static struct kretprobe do_renameat2_retprobe;
static struct kretprobe do_symlinkat_retprobe;
static struct kretprobe do_linkat_retprobe;
static struct kretprobe security_inode_mkdir_retprobe;
static struct kretprobe security_inode_create_retprobe;

/* kretprobes array */
struct kretprobe **rps;     

/* reference monitor struct */
struct reference_monitor reference_monitor;    

// TODO sistema gestione password
/* reference monitor password, to be checked when switching to states REC-ON and REC-OFF */
char password[PASSW_LEN];
module_param_string(password, password, PASSW_LEN, 0);

/* syscall table base address */
unsigned long the_syscall_table = 0x0;
module_param(the_syscall_table, ulong, 0660);

unsigned long the_ni_syscall;
unsigned long new_sys_call_array[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};                 /* new syscalls addresses array */
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array)/sizeof(unsigned long))       /* number of entries to be hacked */
int restore[HACKED_ENTRIES] = {[0 ... (HACKED_ENTRIES-1)] -1};                       /* array of free entries on the syscall table */


/**
 * Add directory path to the reference monitor's blacklist
 * @param path path to add
*/
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


/**
 * Add file path and filename to the reference monitor's blacklist
 * @param path full path
 * @param rel_path relative path or filename
*/
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

        unsigned long inode_number = retrieve_inode_number(path);
        new_entry->inode_number = inode_number;

        spin_lock(&reference_monitor.lock);
        list_add_tail(&new_entry->list, &reference_monitor.blacklist);
        spin_unlock(&reference_monitor.lock);

        return 0;
}

/**
 * Function executed for each element (file/subdirectory) in the directory: if the sub-element is a subdirectory, 
 * the same function is recursively called; otherwise (i.e., the sub-element is a file), the file is added to the 
 * blacklist 
*/
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

/**
 * Iterate on each element in the directory, and add it to the blacklist
*/
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
                return -EACCES;
        }

        char *path = get_full_path(rel_path);
        if (path == NULL) {
                pr_err("%s: error in getting full path\n", MODNAME);
                return -ENOENT;
        }

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

        return 0;
}


/* remove path from reference monitor syscall */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(1, _remove_path_from_rf, char *, path) {
#else 
asmlinkage long sys_remove_path_from_rf(char *path) {
#endif

        struct blacklist_entry *entry, *temp;
        struct blacklist_dir_entry *dir_entry, *dir_temp;

        char *full_path = get_full_path(path);
        if (!full_path) {
                return -EINVAL;
        }

        if (is_directory(full_path)) {
                spin_lock(&reference_monitor.lock);
                list_for_each_entry_safe(dir_entry, dir_temp, &reference_monitor.blacklist_dir, list) {
                        if (!strcmp(entry->path, full_path)) {
                                list_del(&entry->list);
                                kfree(entry->path);
                                kfree(entry);
                        }
                }
                spin_unlock(&reference_monitor.lock);
        }


        spin_lock(&reference_monitor.lock);
        list_for_each_entry_safe(entry, temp, &reference_monitor.blacklist, list) {
                if (!strstr(full_path, entry->path)) {
                        list_del(&entry->list);
                        kfree(entry->path);
                        kfree(entry);
                }
        }
        spin_unlock(&reference_monitor.lock);
        
        return 0;
}


/* print blacklist */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(1, _print_black_list, int, none) {
#else
asmlinkage long sys_print_black_list(void) {
#endif

        struct blacklist_entry *entry;
        printk(KERN_INFO "Blacklist contents (files):\n");
        list_for_each_entry(entry, &reference_monitor.blacklist, list) {
                printk(KERN_INFO "path = %s, filename = %s, inode number = %lu\n", entry->path, entry->filename, entry->inode_number);
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
        AUDIT {
        printk("%s: The state is %d\n", MODNAME, reference_monitor.state);
        }
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

        kuid_t euid = current_euid();

        /* check EUID */
        if (!uid_eq(euid, GLOBAL_ROOT_UID)) {
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
        AUDIT {
        printk("%s: password check successful, changing the state to %d\n", MODNAME, state);
        }
        reference_monitor.state = state;

        spin_unlock(&reference_monitor.lock);

        /* enable/disable monitor */
        if (state == 1 || state == 3) {
                for (int i = 0; i < NUM_KRETPROBES; i++) {
                        enable_kretprobe(rps[i]);
                }
                AUDIT {
                pr_info("%s: kretprobes enabled\n", MODNAME);
                }
        } else {
                for (int i = 0; i < NUM_KRETPROBES; i++) {
                        disable_kretprobe(rps[i]);
                }
                AUDIT {
                pr_info("%s: kretprobes disabled\n", MODNAME);
                }
        }
        
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


/**
 *  Check if this file is blacklisted
 *  @param filename filename, from which the file's full path is retrieved 
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
                }
                
        }

        return 0;
}


/**
 * Check if this file is blacklisted
 * @param path filename/relative path
 * @param fd file descriptor, from which the full path is retrieved
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

                }
        }

        return 0;
}

/**
 * Check if a directory is blacklisted (a directory is considered to be blacklisted if its path includes 
 * a blacklisted directory's path, i.e. it is a subdirectory of a blacklisted directory)
 * @param path directory path
*/
int is_blacklisted_dir(char *path) {

        struct blacklist_dir_entry *entry;
        list_for_each_entry(entry, &reference_monitor.blacklist_dir, list) {
                if (strstr(path, entry->path) != NULL) {
                        return 1;
                }
        }

        return 0;
}

/**
 * This function implements protection against hard links: if a file is an hard link to another file, these two
 * files share the inode number, so this function checks if the inode number of a write-accessed file is blacklisted 
 * @param path full path of the file
 * @param inode_number inode number of the file 
*/
int is_blacklisted_hl(char *path, unsigned long inode_number) {

        struct blacklist_entry *entry;
        list_for_each_entry(entry, &reference_monitor.blacklist, list) {
                if (!strcmp(path, entry->path) || (inode_number == entry->inode_number)) {
                        return 1;
                }
        }

        return 0;
}


/* REFERENCE MONITOR
 * The following functions implement the core functionalities of the reference monitor. 
*/

/**
 * Deferred work to be carried out at each invalid access (i.e., offending program file's hash computation and writing to the log)
 * @param data address of a packed_work element
*/
static void deferred_work(unsigned long data) {

        packed_work *the_work = container_of((void*)data,packed_work,the_work);
        struct log_data *log_data = the_work->log_data;

        /* fingerprint (hash) computation */
        char *hash = calc_fingerprint(log_data->exe_path);
        
        /* string to be written to the log */
        char row[256];
        snprintf(row, 256, "%d, %d, %u, %u, %s, %s\n", log_data->tid, log_data->tgid, 
                        log_data->uid, log_data->euid, log_data->exe_path, hash);


        struct file *file = filp_open(LOG_FILE, O_WRONLY, 0644);
        if (IS_ERR(file)) {
                pr_err("Error in opening log file: %ld\n", PTR_ERR(file));
                return;
        }

        ssize_t ret = kernel_write(file, row, strlen(row), &file->f_pos);

        AUDIT {
        pr_info("%s: written %ld bytes on log\n", MODNAME, ret);
        }

        filp_close(file, NULL);
        kfree((void*)container_of((void*)data,packed_work,the_work));
}

/**
 * Collect TID, TGID, UID, EUID and the offending program's full path, and schedule the deferred work (fingerprint
 * computation and writing to log) 
*/
static void log_info(void) {

        /* allocate a struct log_data, to gather all data to be logged */
        struct log_data *log_data = kmalloc(sizeof(struct log_data), GFP_KERNEL);
        if (!log_data) {
                pr_err("%s: error in kmalloc allocation (log_info)\n", MODNAME);
                return;
        }

        /* get path of the offending program */
        struct mm_struct *mm = current->mm;
        struct dentry *exe_dentry = mm->exe_file->f_path.dentry;
        char *exe_path = get_path_from_dentry(exe_dentry);

        log_data->exe_path = kstrdup(exe_path, GFP_KERNEL);
        log_data->tid = current->pid;
        log_data->tgid = task_tgid_vnr(current);
        log_data->uid = current_uid().val;
        log_data->euid = current_euid().val;

        /* Schedule hash computation and writing on file in deferred work */
        packed_work *def_work;

        def_work = kmalloc(sizeof(packed_work), GFP_KERNEL);
        if (def_work == NULL) {
                pr_err("%s: tasklet buffer allocation failure\n",MODNAME);
                return;
        }

        def_work->buffer = def_work;
        def_work->log_data = log_data;

        __INIT_WORK(&(def_work->the_work),(void*)deferred_work,(unsigned long)(&(def_work->the_work)));

        schedule_work(&def_work->the_work);
        
}

/**
 * Return handler shared among all kretprobes: it prints a specific error message, updates the return
 * code to -EACCES, and triggers log management
*/
static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {

        /* get message */
        struct invalid_operation_data *iop = (struct invalid_operation_data *)ri->data;
        
        pr_info("%s", iop->message);

        /* return "Permission denied" error */
        regs->ax = -EACCES;

        log_info();

        kfree(iop->message);

        return 0;
}

/**
 * Entry handler for the function do_unlinkat (file/directory deletion)
*/
static int do_unlinkat_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {

        struct invalid_operation_data *iop;
        char message[200];

        /* get path and open flags from the registers snapshot */
        struct filename *fn = (struct filename *)regs->si;
        char *filename = fn->name;

        int dfd = (int)regs->di;

        /* check if this path belongs to the blacklist */
        if (dfd == AT_FDCWD) {
                if (is_blacklisted(filename)) {
                        goto block_unlink;
                }
        } else {
                if (is_blacklisted_fd(filename, dfd)) {
                        goto block_unlink;
                }
        }

        return 1;

block_unlink:

        /* set message */
        iop = (struct invalid_operation_data *)ri->data;
        sprintf(message, "%s [BLOCKED]: Deletion attempt on file %s\n", MODNAME, filename);
        iop->message = kstrdup(message, GFP_KERNEL);

        /* update target file descriptor to an invalid one (-1) */
        regs->di = -1;
        return 0;

        
}


/**
 * Entry handler for the function vfs_open (write-openings)
*/
static int vfs_open_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {

        struct invalid_operation_data *iop;
        char message[200];

        /* retrieve parameters */
        const struct path *path = (const struct path *)regs->di;
        struct file *file = (struct file *)regs->si;

        struct dentry *dentry = path->dentry;
        fmode_t mode = file->f_mode;

        if ((mode & FMODE_WRITE) || (mode & FMODE_PWRITE)) {

                /* retrieve path */
                char *full_path = get_path_from_dentry(dentry);
                
                /* retrieve inode number (hard link protection) */
                struct inode *inode = dentry->d_inode;
                unsigned long inode_number = inode->i_ino;
                
                if (is_blacklisted_hl(full_path, inode_number)) {
                        /* set message */
                        iop = (struct invalid_operation_data *)ri->data;
                        sprintf(message, "%s [BLOCKED]: Writing attempt on blacklisted file %s\n", MODNAME, full_path);
                        iop->message = kstrdup(message, GFP_KERNEL);

                        /* schedule return handler execution, that will update the return value (fd) to -1  */
                        return 0;
                }
                
        }

        return 1;
   
}

/**
 * Entry handler for the functions security_inode_mkdir and security_inode_create (directory/file creation)
*/
static int blacklisted_directory_update_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {

        struct invalid_operation_data *iop;
        char message[200];

        struct dentry *dentry = (struct dentry *)regs->si;

        char *full_path = get_path_from_dentry(dentry);

        if (is_blacklisted_dir(full_path)) {
                /* set message */
                iop = (struct invalid_operation_data *)ri->data;
                sprintf(message, "%s [BLOCKED]: File/subdirectory creation in blacklisted directory %s\n", MODNAME, kbasename(full_path));
                iop->message = kstrdup(message, GFP_KERNEL);

                return 0;
        }
        
        return 1;
}

/**
 * Entry handler for the function do_renameat2 (move/copy operations)
*/
static int do_renameat2_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {

        struct invalid_operation_data *iop;
        char message[200];

        struct filename *from = (struct filename *)regs->si;
        char *path = from->name;

        if (is_blacklisted(path)) {

                /* set message */
                iop = (struct invalid_operation_data *)ri->data;
                sprintf(message, "%s [BLOCKED]: Renaming attempt on file %s\n", MODNAME, path);
                iop->message = kstrdup(message, GFP_KERNEL);

                /* update target file descriptor to an invalid one (-1) */
                regs->di = -1;
                return 0;
        }

        return 1;
}


/**
 * Entry handler for the function do_linkat (hard link creation)
*/
static int do_linkat_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {

        struct invalid_operation_data *iop;
        char message[200];

        struct filename *old = (struct filename *)regs->si;
        char *path = old->name;

        int dfd = (int)regs->di;

        if (dfd == AT_FDCWD) {  /* the path is relative to the PWD */
                if (is_blacklisted(path)) {
                        goto hlink_block;
                } 
        } else {
                if (is_blacklisted_fd(path, dfd)) {
                        goto hlink_block;
                } 
        }

        return 1;

hlink_block:

        /* set message */
        iop = (struct invalid_operation_data *)ri->data;
        sprintf(message, "%s [BLOCKED]: Hard link creation on file %s\n", MODNAME, path);
        iop->message = kstrdup(message, GFP_KERNEL);

        /* update target file descriptor to an invalid one (-1) */
        regs->di = -1;
        return 0;


}


/**
 * Entry handler for the function do_symlinkat (symlink creation)
*/
static int do_symlinkat_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {

        struct invalid_operation_data *iop;
        char message[200];

        /* get do_symlinkat parameters from registers */
        struct filename *from = (struct filename *)regs->di;
        char *path = from->name;

        if (is_blacklisted(path)) {

                /* set message */
                iop = (struct invalid_operation_data *)ri->data;
                sprintf(message, "%s [BLOCKED]: Symlink creation on file %s\n", MODNAME, path);
                iop->message = kstrdup(message, GFP_KERNEL);

                /* update new file's descriptor to an invalid one (-1) */
                regs->si = -1;
                return 0;
        }

        return 1;
}

/**
 * Set the struct kretprobe
 * @param krp struct kretprobe
 * @param symbol_name name of the function to be probed
 * @param entry_handler kretprobe'e entry handler
*/
static void set_kretprobe(struct kretprobe *krp, char *symbol_name, kretprobe_handler_t entry_handler) {
        krp->kp.symbol_name = symbol_name;
        krp->handler = (kretprobe_handler_t)ret_handler;
        krp->entry_handler = entry_handler;
        krp->maxactive = -1;
        krp->data_size = sizeof(struct invalid_operation_data);
}


static int kretprobe_init(void)
{
        int ret;

        /* initialize all kretprobes */
        set_kretprobe(&vfs_open_retprobe, "vfs_open", (kretprobe_handler_t)vfs_open_handler);
        set_kretprobe(&do_unlinkat_retprobe, "do_unlinkat", (kretprobe_handler_t)do_unlinkat_handler);
        set_kretprobe(&do_renameat2_retprobe, "do_renameat2", (kretprobe_handler_t)do_renameat2_handler);
        set_kretprobe(&do_linkat_retprobe, "do_linkat", (kretprobe_handler_t)do_linkat_handler);
        set_kretprobe(&do_symlinkat_retprobe, "do_symlinkat", (kretprobe_handler_t)do_symlinkat_handler);
        set_kretprobe(&security_inode_mkdir_retprobe, "security_inode_mkdir", (kretprobe_handler_t)blacklisted_directory_update_handler);
        set_kretprobe(&security_inode_create_retprobe, "security_inode_create", (kretprobe_handler_t)blacklisted_directory_update_handler);
        
        /* kretprobes array allocation */
        rps = kmalloc(NUM_KRETPROBES*sizeof(struct kretprobe *), GFP_KERNEL);
        if (rps == NULL) {
                pr_err("%s: kmalloc allocation of rps failed\n", MODNAME);
                return -ENOMEM;
        }
        
        rps[0] = &vfs_open_retprobe;
        rps[1] = &do_unlinkat_retprobe;
        rps[2] = &do_renameat2_retprobe;
        rps[3] = &do_linkat_retprobe;
        rps[4] = &do_symlinkat_retprobe;
        rps[5] = &security_inode_mkdir_retprobe;
        rps[6] = &security_inode_create_retprobe;

	ret = register_kretprobes(rps, NUM_KRETPROBES);
	if (ret < 0) {
		printk("%s: kretprobes registration failed, returned %d\n", MODNAME, ret);
		return ret;
	}
        AUDIT {
	pr_info("%s: kretprobes correctly installed\n", MODNAME);
        }

	return 0;
}


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

        AUDIT {
        printk("%s: all new system-calls correctly installed on sys-call table\n",MODNAME);
        }

        return 0;
}


int init_module(void) {

        int ret;

        /* syscall table update (add new syscalls) */
        ret = initialize_syscalls();
        if (ret != 0) {
                return ret;
        }

        /* reference monitor initialization */
        AUDIT {
        printk("%s: setting initial state to OFF (0)\n", MODNAME);
        }
        reference_monitor.state = 0;

        /* blacklists initialization */
        INIT_LIST_HEAD(&reference_monitor.blacklist);
        INIT_LIST_HEAD(&reference_monitor.blacklist_dir);
        
        /* spinlock setup */
        DEFINE_SPINLOCK(lock);
        reference_monitor.lock = lock;

        /* password setup */
        char *enc_password = encrypt_password(password); 
        reference_monitor.password = enc_password;

        /* kretprobes setup */
        kretprobe_init();

        return 0;

}


void cleanup_module(void) {

        int i;
                
        AUDIT{
        printk("%s: shutting down\n",MODNAME);
        }

        /* syscall table restoration */
	unprotect_memory();
        for(i=0;i<HACKED_ENTRIES;i++){
                ((unsigned long *)the_syscall_table)[restore[i]] = the_ni_syscall;
        }
	protect_memory();
        printk("%s: sys-call table restored to its original content\n",MODNAME);

        /* kretprobes unregistration*/
        AUDIT{
        for (int i = 0; i < NUM_KRETPROBES; i++) {
                printk(KERN_INFO "Missed probing %d instances of %s\n", rps[i]->nmissed, rps[i]->kp.symbol_name);
        }
        }
        unregister_kretprobes(rps, NUM_KRETPROBES);
        
}
