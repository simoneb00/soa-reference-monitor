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
#include <linux/proc_fs.h>

#include "lib/include/scth.h"
#include "reference-monitor.h"
#include "utils.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Simone Bauco");
MODULE_DESCRIPTION("Kernel Level Reference Monitor for File Protection");

/* kretprobes structs */
static struct kretprobe vfs_open_retprobe;
static struct kretprobe may_delete_retprobe;
static struct kretprobe security_inode_symlink_retprobe;
static struct kretprobe security_inode_link_retprobe;
static struct kretprobe security_inode_mkdir_retprobe;
static struct kretprobe security_inode_create_retprobe;

/* kretprobes array */
struct kretprobe **rps;     

/* reference monitor struct */
struct reference_monitor reference_monitor;    

/* reference monitor password, to be checked when switching to states REC-ON and REC-OFF */
char password[PASSW_LEN];
module_param_string(password, password, PASSW_LEN, 0);

/* syscall table base address */
unsigned long the_syscall_table = 0x0;
module_param(the_syscall_table, ulong, 0660);

unsigned long the_ni_syscall;
unsigned long new_sys_call_array[] = {0x0, 0x0, 0x0, 0x0, 0x0};                      /* new syscalls addresses array */
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array)/sizeof(unsigned long))       /* number of entries to be hacked */
int restore[HACKED_ENTRIES] = {[0 ... (HACKED_ENTRIES-1)] -1};                       /* array of free entries on the syscall table */

/* syscall codes */
int switch_state;
int add_to_blacklist;
int rm_from_blacklist;
int print_blacklist;
int get_blacklist_size;

/* read operation for pseudofile containing syscall codes (in /proc) */
static ssize_t read_proc(struct file *filp, char __user *buffer, size_t length, loff_t *offset) {
    char proc_buffer[512];
    int proc_buffer_len;

    proc_buffer_len = snprintf(proc_buffer, sizeof(proc_buffer),
                                "switch_state: %d\n"
                                "add_to_blacklist: %d\n"
                                "remove_from_blacklist: %d\n"
                                "print_blacklist: %d\n"
                                "get_blacklist_size: %d\n",
                                switch_state, add_to_blacklist,
                                rm_from_blacklist, print_blacklist, get_blacklist_size);

    if (*offset > 0 || length < proc_buffer_len)
        return 0;

    if (copy_to_user(buffer, proc_buffer, proc_buffer_len))
        return -EFAULT;

    *offset += proc_buffer_len;
    return proc_buffer_len;
}

/* proc operations */
static const struct proc_ops proc_fops = {
    .proc_read = read_proc,
};


/**
 * Add directory path to the reference monitor's blacklist
 * @param path path to add
*/
int add_dir_to_rm(char *path) {
        struct blacklist_dir_entry *new_entry;
        char *new_path;
        
        int path_len = strlen(path);

        new_path = kmalloc(path_len + 2, GFP_KERNEL); // Add '/' at the end
        if (!new_path) {
                pr_err("%s: error in kmalloc allocation (add_dir_to_rm)\n", MODNAME);
                return -ENOMEM;
        }

        strcpy(new_path, path);

        if (new_path[path_len - 1] != '/') {
                strcat(new_path, "/");
        }

        new_entry = kmalloc(sizeof(struct blacklist_dir_entry), GFP_KERNEL);
        if (!new_entry) {
                pr_err("%s: error in kmalloc allocation (add_dir_to_rm)\n", MODNAME);
                kfree(new_path);
                return -ENOMEM;
        }

        new_entry->path = kstrdup(new_path, GFP_KERNEL);
        if (!new_entry->path) {
                pr_err("%s: error in kstrdup (add_dir_to_rm)\n", MODNAME);
                kfree(new_entry);
                kfree(new_path);
                return -ENOMEM;
        }

        spin_lock(&reference_monitor.lock);
        list_add_tail(&new_entry->list, &reference_monitor.blacklist_dir);
        spin_unlock(&reference_monitor.lock);

        kfree(new_path);

        return 0;
}


/**
 * Add file path and filename to the reference monitor's blacklist
 * @param path full path
 * @param rel_path relative path or filename
*/
int add_file_to_rf(char *path, char *rel_path) {

        struct blacklist_entry *new_entry;
        unsigned long inode_number;

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

        inode_number = retrieve_inode_number(path);
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0)
static bool process_dir_entry(struct dir_context *dir, const char *name, int name_len,
                        loff_t offset, u64 ino, unsigned int d_type) {
#else 
static int process_dir_entry(struct dir_context *dir, const char *name, int name_len,
                        loff_t offset, u64 ino, unsigned int d_type) {
#endif
        struct custom_dir_context *custom_ctx;
        char *full_path, *file_name;
        struct file *subdir;

        /* retrieve base dir path from struct custom_dir_context */
        custom_ctx = container_of(dir, struct custom_dir_context, dir_ctx);
        full_path = kmalloc(sizeof(char)*PATH_MAX, GFP_KERNEL);
        if (!full_path) {
                pr_err("%s: kmalloc allocation error (process_dir_entry)\n", MODNAME);
                return false;
        }
        strcpy(full_path, custom_ctx->dir_path);


        /* get file/subdirectory name */
        file_name = kmalloc(name_len + 1, GFP_KERNEL);
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
                        
                        subdir = filp_open(full_path, O_RDONLY, 0);
                        
                        if (IS_ERR(subdir)) {
                                pr_err("%s: error in opening file %s\n", MODNAME, file_name);
                                kfree(full_path);
                                kfree(file_name);
                                return PTR_ERR(subdir);
                        }

                        add_directory_to_rf(subdir, full_path);
                        
                } else {        /* file */

                        add_file_to_rf(full_path, file_name);

                }

        }

        kfree(full_path);
        kfree(file_name);

	#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0)
        return true;
	#else
	return 0;
	#endif

}

/**
 * Iterate on each element in the directory, and add it to the blacklist
*/
int add_directory_to_rf(struct file *dir, char *dir_path) {

	struct custom_dir_context ctx;

        /* add directory path to blacklist */
        add_dir_to_rm(dir_path);

        ctx = (struct custom_dir_context) {
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
        char *path, *kernel_rel_path;
        struct file *dir;

        if (reference_monitor.state < 2) {
                printk(KERN_ERR "%s: the reference monitor is not in a reconfiguration state\n", MODNAME);
                return -EPERM;
        }

        kernel_rel_path = kmalloc(PATH_MAX, GFP_KERNEL);
        if (!kernel_rel_path) {
                pr_err("%s: Error in kmalloc allocation\n", MODNAME);
                return -ENOMEM;
        }

        if (copy_from_user(kernel_rel_path, rel_path, PATH_MAX)) {
                pr_err("%s: error in copy_from_user\n", MODNAME);
                kfree(kernel_rel_path);
                return -EAGAIN;
        }

        path = get_full_path(kernel_rel_path);
        if (path == NULL) {
                pr_err("%s: error in getting full path\n", MODNAME);
                kfree(kernel_rel_path);
                return -ENOENT;
        }

        if (is_directory(path)) {

                dir = filp_open(path, O_RDONLY, 0);
                if (IS_ERR(dir)) {
                        pr_err("%s: error in opening file %s\n", MODNAME, path);
                        kfree(path);
                        kfree(kernel_rel_path);
                        return PTR_ERR(dir);
                }

                add_directory_to_rf(dir, path);

                filp_close(dir, NULL);

        } else {
                add_file_to_rf(path, kernel_rel_path);
        }

        kfree(kernel_rel_path);
        return 0;
}


/* remove path from reference monitor syscall */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _remove_path_from_rf, char *, path, int, mode) {
#else 
asmlinkage long sys_remove_path_from_rf(char *path, int mode) {
#endif

        struct blacklist_entry *entry, *temp;
        struct blacklist_dir_entry *dir_entry, *dir_temp;
        char *full_path, *dir_path, *kernel_path;
	int is_dir;

        if (mode != 0 && mode != 1) {
                pr_err("%s: invalid mode in sys_remove_path_from_rf\n", MODNAME);
                return -EINVAL;
        }

        kernel_path = kmalloc(PATH_MAX, GFP_KERNEL);
        if (!kernel_path) {
                pr_err("%s: Error in kmalloc allocation\n", MODNAME);
                return -ENOMEM;
        }

        if (copy_from_user(kernel_path, path, PATH_MAX)) {
                pr_err("%s: error in copy_from_user\n", MODNAME);
                kfree(kernel_path);
                return -EAGAIN;
        }

        full_path = get_full_path(kernel_path);
        if (!full_path) {
                return -ENOENT;
        }

        is_dir = is_directory(full_path);

        spin_lock(&reference_monitor.lock);

        if (is_dir) {

                dir_path = add_trailing_slash(full_path);

                /* delete directory from directories blacklist */
                list_for_each_entry_safe(dir_entry, dir_temp, &reference_monitor.blacklist_dir, list) {
                        if (!strcmp(dir_entry->path, full_path) || !strncmp(dir_entry->path, dir_path, strlen(dir_path))) {
                                AUDIT{
                                pr_info("%s: removing %s from blacklist\n", MODNAME, dir_entry->path);
                                }
                                list_del(&dir_entry->list);
                                kfree(dir_entry->path);
                                kfree(dir_entry);
                      	 }
                }
        
                if (mode == DELETE_ALL) {
                        list_for_each_entry_safe(entry, temp, &reference_monitor.blacklist, list) {
                                if (!strncmp(dir_path, entry->path, strlen(dir_path))) {
                                        AUDIT{
                                        pr_info("%s: removing %s from blacklist\n", MODNAME, entry->path);
                                        }
                                        list_del(&entry->list);
                                        kfree(entry->path);
                                        kfree(entry);
                                }
                        }
                }

                kfree(dir_path);
        } else {
                /* if the target is a file, mode is ignored */
                list_for_each_entry_safe(entry, temp, &reference_monitor.blacklist, list) {
                        if (!strcmp(full_path, entry->path)) {
                                AUDIT{
                                pr_info("%s: removing %s from blacklist\n", MODNAME, entry->path);
                                }
                                list_del(&entry->list);
                                kfree(entry->path);
                                kfree(entry);
                        }
                }
        }

        spin_unlock(&reference_monitor.lock);
        kfree(kernel_path);
        return 0;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _get_blacklist_size, size_t * __user, files_size, size_t * __user, dirs_size) {
#else
asmlinkage long sys_get_blacklist_size(void) {
#endif

        size_t total_files_size = 0;
        size_t total_dirs_size = 0;
        struct blacklist_entry *entry;
        struct blacklist_dir_entry *dir_entry;

        spin_lock(&reference_monitor.lock);
        list_for_each_entry(entry, &reference_monitor.blacklist, list) {
                total_files_size += strlen("path = ") + strlen(entry->path) +
                        strlen(", filename = ") + strlen(entry->filename) +
                        strlen(", inode number = ") + 20 + // Max length of inode numbers (20 chars)
                        3; // +3 for ", " and NULL terminator
        }

        list_for_each_entry(dir_entry, &reference_monitor.blacklist_dir, list) {
                total_dirs_size += strlen("path = ") + strlen(dir_entry->path) + 2; // +2 for ", " and NULL terminator
        }
        spin_unlock(&reference_monitor.lock);

        if (copy_to_user(files_size, &total_files_size, sizeof(total_files_size)) ||
            copy_to_user(dirs_size, &total_dirs_size, sizeof(total_dirs_size))) {
                return -EFAULT;
        }

        return 0;
}

/* print blacklist */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(4, _print_blacklist, char * __user, files, char * __user, dirs, size_t, files_size, size_t, dirs_size) {
#else
asmlinkage long sys_print_blacklist(void) {
#endif

        char *files_buf, *dirs_buf, *files_ptr, *dirs_ptr;
        struct blacklist_entry *entry;
        struct blacklist_dir_entry *dir_entry;

        if (!files || !dirs) {
                return -EINVAL;
        }

        files_buf = kmalloc(files_size, GFP_KERNEL);
        dirs_buf = kmalloc(dirs_size, GFP_KERNEL);

        if (!files_buf || !dirs_buf) {
                return -ENOMEM;
        }

        files_ptr = files_buf;
        dirs_ptr = dirs_buf;

        spin_lock(&reference_monitor.lock);
        list_for_each_entry(entry, &reference_monitor.blacklist, list) {
                files_ptr += snprintf(files_ptr, files_size - (files_ptr - files_buf),
                                "path = %s, filename = %s, inode number = %lu\n",
                                entry->path, entry->filename, entry->inode_number);
        }

        if (copy_to_user(files, files_buf, files_size)) {
                pr_err("%s: Fault in copying blacklisted files to user\n", MODNAME);
                spin_unlock(&reference_monitor.lock);
                return -EFAULT;
        }

        list_for_each_entry(dir_entry, &reference_monitor.blacklist_dir, list) {
                dirs_ptr += snprintf(dirs_ptr, dirs_size - (dirs_ptr - dirs_buf),
                                "path = %s\n", dir_entry->path);
        }
        spin_unlock(&reference_monitor.lock);


        if (copy_to_user(dirs, dirs_buf, dirs_size)) {
                pr_err("%s: Fault in copying blacklisted directories to user\n", MODNAME);
                return -EFAULT;
        }
        

        kfree(files_buf);
        kfree(dirs_buf);

        return 0;
}

/* update state syscall */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) 
__SYSCALL_DEFINEx(2, _write_rf_state, int, state, char*, password) {
#else
asmlinkage long sys_write_rf_state(int state, char *password) {
#endif 

        kuid_t euid;
	int i, ret;
        char *kernel_password;

        /* check state number */
        if (state < 0 || state > 3) {
                pr_err("%s: Unexpected state", MODNAME);
                return -EINVAL;
        }

        kernel_password = kmalloc(PASSW_LEN, GFP_KERNEL);
        if (!kernel_password) {
                pr_err("%s: Error in kmalloc allocation\n", MODNAME);
                return -ENOMEM;
        }

        if (copy_from_user(kernel_password, password, PASSW_LEN)) {
                pr_err("%s: error in copy_from_user\n", MODNAME);
                kfree(kernel_password);
                return -EAGAIN;
        }

        euid = current_euid();

        /* check EUID */
        if (!uid_eq(euid, GLOBAL_ROOT_UID)) {
                pr_err("%s: Access denied: only root (EUID 0) can change the state\n", MODNAME);
                kfree(kernel_password);
                return -EPERM;
        }   

        /* if requested state is REC-ON or REC-OFF, check password */
        if (state > 1) {
                if (strcmp(reference_monitor.password, encrypt_password(kernel_password)) != 0) {
                        pr_err("%s: Access denied: invalid password\n", MODNAME);
                        kfree(kernel_password);
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
                for (i = 0; i < NUM_KRETPROBES; i++) {
                        ret = enable_kretprobe(rps[i]);
                        if (ret) {
                                pr_err("%s: kretprobe enabling failed\n", MODNAME);
                        }
                }
                AUDIT {
                pr_info("%s: kretprobes enabled\n", MODNAME);
                }
        } else {
                for (i = 0; i < NUM_KRETPROBES; i++) {
                        ret = disable_kretprobe(rps[i]);
                        if (ret) {
                                pr_err("%s: kretprobe disabling failed\n", MODNAME);
                        }
                }
                AUDIT {
                pr_info("%s: kretprobes disabled\n", MODNAME);
                }
        }
        
        kfree(kernel_password);
        return reference_monitor.state;
        
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
long sys_write_state = (unsigned long) __x64_sys_write_rf_state;    
long sys_add_to_blacklist = (unsigned long) __x64_sys_add_path_to_rf;
long sys_remove_from_blacklist = (unsigned long) __x64_sys_remove_path_from_rf;
long sys_print_blacklist = (unsigned long) __x64_sys_print_blacklist;
long sys_get_blacklist_size = (unsigned long) __x64_sys_get_blacklist_size;
#else
#endif


/**
 *  Check if this file is blacklisted
 *  @param filename filename, from which the file's full path is retrieved 
*/
int is_blacklisted(const char *path) {
        struct blacklist_entry *entry;

        spin_lock(&reference_monitor.lock);
        list_for_each_entry(entry, &reference_monitor.blacklist, list) {
                if (!strcmp(path, entry->path)) {
                        spin_unlock(&reference_monitor.lock);
                        return 1;
                }
        }
        
        spin_unlock(&reference_monitor.lock);
        return 0;
}

/**
 * Check if a directory is blacklisted (a directory is considered to be blacklisted if its path includes 
 * a blacklisted directory's path, i.e. it is a subdirectory of a blacklisted directory)
 * @param path directory path
*/
int is_blacklisted_dir(const char *full_path) {

        char *new_path;
        int path_len;
        struct blacklist_dir_entry *entry;

        path_len = strlen(full_path);
        
        /* add / at the end of the path */
        if (full_path[path_len - 1] != '/') {
                new_path = kmalloc(strlen(full_path) + 2, GFP_KERNEL);
                if (!new_path) {
                        pr_err("%s: error in kmalloc allocation (is_blacklisted_dir)\n", MODNAME);
                        return 0;
                }

                strcpy(new_path, full_path);
                strcat(new_path, "/");

        } else {
                new_path = (char *)full_path;
        }

        spin_lock(&reference_monitor.lock);
        list_for_each_entry(entry, &reference_monitor.blacklist_dir, list) {
                if (!strncmp(new_path, entry->path, strlen(entry->path))) {
                        kfree(new_path);
                        spin_unlock(&reference_monitor.lock);
                        return 1;
                }
        }
        spin_unlock(&reference_monitor.lock);

        if (new_path)
                kfree(new_path);
        return 0;
}

/**
 * This function implements protection against hard links: if a file is an hard link to another file, these two
 * files share the inode number, so this function checks if the inode number of a write-accessed file is blacklisted 
 * @param path full path of the file
 * @param inode_number inode number of the file 
*/
int is_blacklisted_hl(const char *path, unsigned long inode_number) {

        struct blacklist_entry *entry;

        spin_lock(&reference_monitor.lock);
        list_for_each_entry(entry, &reference_monitor.blacklist, list) {
                if (!strcmp(path, entry->path) || (inode_number == entry->inode_number)) {
                        spin_unlock(&reference_monitor.lock);
                        return 1;
                }
        }
        spin_unlock(&reference_monitor.lock);

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

        packed_work *the_work;
        struct log_data *log_data;
        char *hash;
        char row[256];
        struct file *file;
        ssize_t ret;

        the_work = container_of((void*)data,packed_work,the_work);
        log_data = the_work->log_data;

        /* fingerprint (hash) computation */
        hash = calc_fingerprint(log_data->exe_path);
        
        /* string to be written to the log */
        snprintf(row, 256, "%d, %d, %u, %u, %s, %s\n", log_data->tid, log_data->tgid, 
                        log_data->uid, log_data->euid, log_data->exe_path, hash);


        file = filp_open(LOG_FILE, O_WRONLY, 0644);
        if (IS_ERR(file)) {
                pr_err("Error in opening log file (maybe the VFS is not mounted): %ld\n", PTR_ERR(file));
                return;
        }

        ret = kernel_write(file, row, strlen(row), &file->f_pos);

        AUDIT {
        pr_info("%s: written %ld bytes on log\n", MODNAME, ret);
        }

        filp_close(file, NULL);
        kfree(hash);
        kfree((void*)container_of((void*)data,packed_work,the_work));
}

/**
 * Collect TID, TGID, UID, EUID and the offending program's full path, and schedule the deferred work (fingerprint
 * computation and writing to log) 
*/
static void log_info(void) {

        struct log_data *log_data;
        struct mm_struct *mm;
        struct dentry *exe_dentry;
        char *exe_path;
        packed_work *def_work;

        /* allocate a struct log_data, to gather all data to be logged */
        log_data = kmalloc(sizeof(struct log_data), GFP_KERNEL);
        if (!log_data) {
                pr_err("%s: error in kmalloc allocation (log_info)\n", MODNAME);
                return;
        }

        /* get path of the offending program */
        mm = current->mm;
        exe_dentry = mm->exe_file->f_path.dentry;
        exe_path = get_path_from_dentry(exe_dentry);

        log_data->exe_path = kstrdup(exe_path, GFP_KERNEL);
        log_data->tid = current->pid;
        log_data->tgid = task_tgid_vnr(current);
        log_data->uid = current_uid().val;
        log_data->euid = current_euid().val;

        /* Schedule hash computation and writing on file in deferred work */
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

        struct invalid_operation_data *iop;

        /* get and print message */
        iop = (struct invalid_operation_data *)ri->data;
        pr_info("%s", iop->message);

        /* return "Permission denied" error */
        regs->ax = -EACCES;

        /* log offending thread info */
        log_info();

        kfree(iop->message);
        return 0;
}

/**
 * Entry handler for the function may_delete (file/directory deletion and renaming)
*/
static int may_delete_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {

        struct invalid_operation_data *iop;
        char message[200];
        struct dentry *dentry;
        char *full_path;

        /* get victim's dentry from parameters */

        #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0)
        dentry = (struct dentry *)regs->dx;
        #else
        dentry = (struct dentry *)regs->si;
        #endif

        /* get full path from dentry */
        full_path = get_path_from_dentry(dentry);

        /* check if file is blacklisted */
        if (is_blacklisted(full_path) || is_blacklisted_dir(full_path)) {
                goto block_delete;
        }

        return 1;

block_delete:

        /* set message */
        iop = (struct invalid_operation_data *)ri->data;
        sprintf(message, "%s [BLOCKED]: Deletion attempt on file %s\n", MODNAME, full_path);
        iop->message = kstrdup(message, GFP_KERNEL);

        /* schedule return handler's execution */
        return 0;

        
}


/**
 * Entry handler for the function vfs_open (write-openings)
*/
static int vfs_open_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {

        struct invalid_operation_data *iop;
        char message[200];
        const struct path *path;
        struct file* file;
        struct dentry *dentry;
        fmode_t mode;
        char *full_path;
        struct inode *inode;
        unsigned long inode_number;

        /* retrieve parameters */
        path = (const struct path *)regs->di;
        file = (struct file *)regs->si;

        dentry = path->dentry;
        mode = file->f_mode;

        if ((mode & FMODE_WRITE) || (mode & FMODE_PWRITE)) {

                /* retrieve path */
                full_path = get_path_from_dentry(dentry);
                
                /* retrieve inode number (hard link protection) */
                inode = dentry->d_inode;
                inode_number = inode->i_ino;
                
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
        struct dentry *dentry;
        char *full_path;

        dentry = (struct dentry *)regs->si;

        full_path = get_path_from_dentry(dentry);

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
 * Entry handler for the function security_inode_link (hard link creation)
*/
static int security_inode_link_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {

        struct invalid_operation_data *iop;
        char message[200];
        struct dentry *dentry;
        char *full_path;

        dentry = (struct dentry *)regs->di;

        full_path = get_path_from_dentry(dentry);

        if (is_blacklisted(full_path)) {
                goto hlink_block;
        }

        return 1;

hlink_block:

        /* set message */
        iop = (struct invalid_operation_data *)ri->data;
        sprintf(message, "%s [BLOCKED]: Hard link creation on file %s\n", MODNAME, full_path);
        iop->message = kstrdup(message, GFP_KERNEL);

        /* schedule return handler's execution */
        return 0;


}


/**
 * Entry handler for the function security_inode_symlink (symlink creation)
*/
static int security_inode_symlink_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {

        struct invalid_operation_data *iop;
        char message[200];
        const char *old_name;
        char *full_path;

        old_name = (const char *)regs->dx;
        full_path = get_full_path(old_name);
        if (!full_path) {
                return 1;
        }

        if (is_blacklisted(full_path) || is_blacklisted_dir(full_path)) {
                goto symlink_block;
        }

        kfree(full_path);
        return 1;

symlink_block:
        /* set message */
        iop = (struct invalid_operation_data *)ri->data;
        sprintf(message, "%s [BLOCKED]: Symlink creation on file %s\n", MODNAME, full_path);
        iop->message = kstrdup(message, GFP_KERNEL);

        /* schedule return handler's execution */
        kfree(full_path);
        return 0;
}

/**
 * Set the struct kretprobe
 * @param krp struct kretprobe
 * @param symbol_name name of the function to be probed
 * @param entry_handler kretprobe'e entry handler
*/
static void set_kretprobe(struct kretprobe *krp, char *symbol_name, kretprobe_handler_t entry_handler) {
        krp->kp.symbol_name = symbol_name;
        krp->kp.flags = KPROBE_FLAG_DISABLED;   // set kretprobe as disable (initial state is OFF)
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
        set_kretprobe(&may_delete_retprobe, "may_delete", (kretprobe_handler_t)may_delete_handler);
        set_kretprobe(&security_inode_link_retprobe, "security_inode_link", (kretprobe_handler_t)security_inode_link_handler);
        set_kretprobe(&security_inode_symlink_retprobe, "security_inode_symlink", (kretprobe_handler_t)security_inode_symlink_handler);
        set_kretprobe(&security_inode_mkdir_retprobe, "security_inode_mkdir", (kretprobe_handler_t)blacklisted_directory_update_handler);
        set_kretprobe(&security_inode_create_retprobe, "security_inode_create", (kretprobe_handler_t)blacklisted_directory_update_handler);
        
        /* kretprobes array allocation */
        rps = kmalloc(NUM_KRETPROBES*sizeof(struct kretprobe *), GFP_KERNEL);
        if (rps == NULL) {
                pr_err("%s: kmalloc allocation of rps failed\n", MODNAME);
                return -ENOMEM;
        }
        
        rps[0] = &vfs_open_retprobe;
        rps[1] = &may_delete_retprobe;
        rps[2] = &security_inode_link_retprobe;
        rps[3] = &security_inode_symlink_retprobe;
        rps[4] = &security_inode_mkdir_retprobe;
        rps[5] = &security_inode_create_retprobe;

	ret = register_kretprobes(rps, NUM_KRETPROBES);
	if (ret) {
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

        new_sys_call_array[0] = (unsigned long)sys_write_state;
        new_sys_call_array[1] = (unsigned long)sys_add_to_blacklist;
        new_sys_call_array[2] = (unsigned long)sys_remove_from_blacklist;
        new_sys_call_array[3] = (unsigned long)sys_print_blacklist;
        new_sys_call_array[4] = (unsigned long)sys_get_blacklist_size;

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

        /* set syscall codes */
        switch_state = restore[0];
        add_to_blacklist = restore[1];
        rm_from_blacklist = restore[2];
        print_blacklist = restore[3];
        get_blacklist_size = restore[4];

        return 0;
}


int init_module(void) {

        int ret;
        char *enc_password;

        /* syscall table update (add new syscalls) */
        ret = initialize_syscalls();
        if (ret != 0) {
                return ret;
        }

        /* /proc file setup (syscall codes) */
        proc_create(PROC_FILENAME, 0, NULL, &proc_fops);

        /* reference monitor initialization */
        AUDIT {
        printk("%s: setting initial state to OFF (0)\n", MODNAME);
        }
        reference_monitor.state = 0;

        /* blacklists initialization */
        INIT_LIST_HEAD(&reference_monitor.blacklist);
        INIT_LIST_HEAD(&reference_monitor.blacklist_dir);
        
        /* spinlock setup */
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
        DEFINE_SPINLOCK(lock);
	reference_monitor.lock = lock;
	#else
	spin_lock_init(&reference_monitor.lock);
	#endif

        /* password setup */
        enc_password = encrypt_password(password); 
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

        /* remove /proc file */
        remove_proc_entry(PROC_FILENAME, NULL);

        /* kretprobes unregistration */
        AUDIT{
        for (i = 0; i < NUM_KRETPROBES; i++) {
                printk(KERN_INFO "Missed probing %d instances of %s\n", rps[i]->nmissed, rps[i]->kp.symbol_name);
        }
        }
        unregister_kretprobes(rps, NUM_KRETPROBES);
        kfree(rps);
        
}
