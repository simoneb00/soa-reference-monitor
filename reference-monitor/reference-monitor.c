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
* @file virtual-to-physical-memory-mapper.c 
* @brief This is the main source for the Linux Kernel Module which implements
*       a system call that can be used to query the kernel for current mappings of virtual pages to 
*	physical frames - this service is x86_64 specific in the curent implementation
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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Simone Bauco");
MODULE_DESCRIPTION("Kernel Level Reference Monitor for File Protection");

#define MODNAME "REFERENCE MONITOR"

char *encrypt_password(const char *password);

/** @struct reference_monitor
 *  @brief Reference Monitor Basic Structure
 */
struct reference_monitor {
        int state;          /**< The state can be one of the following: OFF (0), ON (1), REC-OFF (2), REC-ON (3)*/
        char *password;     /**< Password for Reference Monitor reconfiguration */
        char *black_list[];  /**< Paths to be protected */
} reference_monitor;

const char *password = "ref_monitor_password";

unsigned long the_syscall_table = 0x0;
module_param(the_syscall_table, ulong, 0660);

unsigned long the_ni_syscall;

unsigned long new_sys_call_array[] = {0x0, 0x0};
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array)/sizeof(unsigned long))
int restore[HACKED_ENTRIES] = {[0 ... (HACKED_ENTRIES-1)] -1};

#define AUDIT if(1)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(1, _read_rf_state, int, none) {
#else
asmlinkage long sys_print(void) {
#endif
        printk("%s: The state is %d\n", MODNAME, reference_monitor.state);

	return reference_monitor.state;
	
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) 
__SYSCALL_DEFINEx(2, _write_rf_state, int, state, char*, password) {
#else
asmlinkage long sys_write_rf_state(int state) {
#endif 
        kuid_t euid = current_euid();

        if (!uid_eq(euid, GLOBAL_ROOT_UID)) {
                printk(KERN_ERR "%s: Access denied: only root (EUID 0) can change the state.\n", MODNAME);
                return -EPERM; // Ritorna un errore di permesso nel caso in cui l'utente non sia root
        }   

        printk("%s: checking password...\n", MODNAME);

        if (strcmp(reference_monitor.password, encrypt_password(password)) != 0) {
                printk(KERN_ERR "%s: Access denied: invalid password\n", MODNAME);
                return -EPERM;
        }
        
        // todo check password encryption

        printk("%s: check successful, changing the state to %d\n", MODNAME, state);
        reference_monitor.state = state;

        return reference_monitor.state;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
long sys_read_state = (unsigned long) __x64_sys_read_rf_state;   
long sys_write_state = (unsigned long) __x64_sys_write_rf_state;    
#else
#endif


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

        /* todo set syscalls */
	new_sys_call_array[0] = (unsigned long)sys_read_state; 
        new_sys_call_array[1] = (unsigned long)sys_write_state;

        ret = get_entries(restore,HACKED_ENTRIES,(unsigned long*)the_syscall_table,&the_ni_syscall);

        if (ret != HACKED_ENTRIES){
                printk("%s: could not hack %d entries (just %d)\n",MODNAME,HACKED_ENTRIES,ret); 
                return -1;      
        }

        AUDIT{
                printk("%s: got the following %d entries:\n", MODNAME, ret);
                for (i=0;i<HACKED_ENTRIES;i++) {
                        printk("%s: got entry %d\n", MODNAME, restore[i]);
                }
        }

	unprotect_memory();

        for(i=0;i<HACKED_ENTRIES;i++){
                ((unsigned long *)the_syscall_table)[restore[i]] = (unsigned long)new_sys_call_array[i];
        }

	protect_memory();

        printk("%s: all new system-calls correctly installed on sys-call table\n",MODNAME);

        return 0;
}


char *encrypt_password(const char *password) {  
        struct crypto_shash *hash_tfm;
        struct shash_desc *desc;
        unsigned char *digest;
        char *result = NULL;
        int ret = -ENOMEM;

        printk("%s: allocating hash_tfm\n", MODNAME);

        hash_tfm = crypto_alloc_shash("sha256", 0, 0);
        if (IS_ERR(hash_tfm)) {
                printk(KERN_ERR "Failed to allocate hash transform\n");
                return NULL;
        }

        printk("%s: allocating descriptor\n", MODNAME);

        desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(hash_tfm), GFP_KERNEL);
        if (!desc) {
                printk(KERN_ERR "Failed to allocate hash descriptor\n");
                goto out;
        }
        desc->tfm = hash_tfm;

        printk("%s: allocating digest\n", MODNAME);

        digest = kmalloc(32, GFP_KERNEL);
        if (!digest) {
                printk(KERN_ERR "Failed to allocate hash buffer\n");
                goto out;
        }

        printk("%s: calculating hash\n", MODNAME);

        ret = crypto_shash_digest(desc, password, strlen(password), digest);
        if (ret) {
                printk(KERN_ERR "Failed to calculate hash\n");
                goto out;
        }

        printk("%s: allocating result\n", MODNAME);

        result = kmalloc(2 * 32 + 1, GFP_KERNEL);
        if (!result) {
                printk(KERN_ERR "Failed to allocate memory for result\n");
                goto out;
        }

        printk("%s: printing result\n", MODNAME);

        for (int i = 0; i < 32; i++)
                sprintf(&result[i * 2], "%02x", digest[i]);
        
out:
        if (digest)
                kfree(digest);
        if (desc)
                kfree(desc);
        if (hash_tfm)
                crypto_free_shash(hash_tfm);

        printk("%s: done\n", MODNAME);

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

        /* PASSWORD SETUP */
        char *enc_password = encrypt_password(password); 

        printk("%s: printing encryption\n", MODNAME);

        reference_monitor.password = enc_password;
        printk("%s: encrypted password is: %s\n", MODNAME, enc_password);

        return 0;

}

void cleanup_module(void) {

        int i;
                
        printk("%s: shutting down\n",MODNAME);

	unprotect_memory();
        for(i=0;i<HACKED_ENTRIES;i++){
                ((unsigned long *)the_syscall_table)[restore[i]] = the_ni_syscall;
        }
	protect_memory();
        printk("%s: sys-call table restored to its original content\n",MODNAME);
        
}
