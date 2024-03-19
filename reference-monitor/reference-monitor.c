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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Simone Bauco");
MODULE_DESCRIPTION("Kernel Level Reference Monitor for File Protection");

#define MODNAME "REFERENCE MONITOR"
#define PASSW_LEN 32
#define AUDIT if(1)

char *encrypt_password(const char *password);


struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};


struct kprobe kp = {
        .symbol_name = "do_filp_open",
};


struct blacklist_entry {
        struct list_head list;
        char *path;
};

/** @struct reference_monitor
 *  @brief Reference Monitor Basic Structure
 */
struct reference_monitor {
        int state;                              /**< The state can be one of the following: OFF (0), ON (1), REC-OFF (2), REC-ON (3)*/
        char *password;                         /**< Password for Reference Monitor reconfiguration */
        struct list_head blacklist;      /**< Paths to be protected */
        spinlock_t lock;                        /**< Lock for synchronization */
} reference_monitor;


/* reference monitor password, to be checked when switching to states REC-ON and REC-OFF */
char password[PASSW_LEN];
module_param_string(password, password, PASSW_LEN, 0);

/* syscall table base address */
unsigned long the_syscall_table = 0x0;
module_param(the_syscall_table, ulong, 0660);

unsigned long the_ni_syscall;

unsigned long new_sys_call_array[] = {0x0, 0x0, 0x0, 0x0, 0x0};                 /* new syscalls addresses array */
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array)/sizeof(unsigned long))  /* number of entries to be hacked */
int restore[HACKED_ENTRIES] = {[0 ... (HACKED_ENTRIES-1)] -1};                  /* array of free entries on the syscall table */


/* NEW SYSCALLS DEFINITION */

/* add path to reference monitor syscall */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(1, _add_path_to_rf, char *, path) {
#else 
asmlinkage long sys_add_path_to_rf(char *path) {
#endif
        if (reference_monitor.state < 2) {
                printk(KERN_ERR "%s: the reference monitor is not in a reconfiguration state\n", MODNAME);
                return -EACCES;  // todo is EACCES correct?
        }

        struct blacklist_entry *new_entry;

        new_entry = kmalloc(sizeof(struct blacklist_entry), GFP_KERNEL);
        if (!new_entry) {
                return -ENOMEM;
        }

        new_entry->path = kstrdup(path, GFP_KERNEL);
        if (!new_entry->path) {
                kfree(new_entry);
                return -ENOMEM;
        }

        spin_lock(&reference_monitor.lock);
        list_add_tail(&new_entry->list, &reference_monitor.blacklist);
        spin_unlock(&reference_monitor.lock);

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
        printk(KERN_INFO "Blacklist contents:\n");
        list_for_each_entry(entry, &reference_monitor.blacklist, list) {
                printk(KERN_INFO "%s\n", entry->path);
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
        } else {
                disable_kprobe(&kp);    // the reference monitor has been turned off 
        }
        */
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


/* REFERENCE MONITOR
 * The following functions implement the core functionalities of the reference monitor. 
*/

int handler(struct kprobe *p, struct pt_regs *regs) {
        

        // we need the second and third arguments, which are stored in registers rsi and rdx
        struct filename *fn = (struct filename *)regs->si;
        struct open_flags *flags = (struct open_flags *)regs->dx;

        int flag = flags->open_flag; 
        const char *path = fn->name;

        int blacklisted = 0;
        struct blacklist_entry *entry;
        list_for_each_entry(entry, &reference_monitor.blacklist, list) {
                if (!strcmp(path, entry->path)) {
                        blacklisted = 1;
                        break;
                }
        }

        if (blacklisted && (flag & O_RDWR || flag & O_WRONLY)) {
                printk("%s: pre-handler execution, path is %s, access denied\n", MODNAME, path);
        }

        return 0;
}

int init_kprobes(void) {
        int ret;
	kp.pre_handler = handler;

	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("%s: register_kprobe failed, returned %d\n", MODNAME, ret);
		return ret;
	}
	pr_info("%s: Planted kprobe at %p\n", MODNAME, kp.addr);

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
        
        DEFINE_SPINLOCK(lock);
        reference_monitor.lock = lock;

        /* PASSWORD SETUP */
        char *enc_password = encrypt_password(password); 
        reference_monitor.password = enc_password;

        /* KPROBES INITIALIZATION */
        init_kprobes();

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

        /* kprobes unregistration */
        unregister_kprobe(&kp);
	pr_info("kprobe at %p unregistered\n", kp.addr);
        
}
