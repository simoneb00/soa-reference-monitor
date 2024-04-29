#include <linux/fs.h>    
#include <linux/slab.h>    
#include <linux/kernel.h>  
#include <linux/string.h>  
#include <linux/namei.h>
#include <linux/crypto.h>     
#include <linux/fdtable.h>     
#include <linux/uaccess.h>   
#include <linux/file.h>  
#include <crypto/hash.h>

#include "utils.h"
#include "reference-monitor.h"

char *get_path_from_dentry(struct dentry *dentry) {

	char *buffer, *full_path, *ret;
        int len;

        buffer = (char *)__get_free_page(GFP_ATOMIC);
        if (!buffer)
                return NULL;

        ret = dentry_path_raw(dentry, buffer, PATH_MAX);
        if (IS_ERR(ret)) {
                pr_err("dentry_path_raw failed: %li", PTR_ERR(ret));
                free_page((unsigned long)buffer);
                return NULL;
        } 

        len = strlen(ret);

        full_path = kmalloc(len + 2, GFP_ATOMIC);
        if (!full_path) {
                pr_err("%s: error in kmalloc allocation (get_path_from_dentry)\n", MODNAME);
                return NULL;
        }

        strncpy(full_path, ret, len);
        full_path[len + 1] = '\0';

        free_page((unsigned long)buffer);
        return full_path;
}

char *get_full_path(const char *rel_path) {

	char *k_full_path, *rel_path_tilde, *tilde_pos;
	struct path path;
	int ret;

        if (rel_path[0] == '/') {
                return (char *)rel_path;
        }


        k_full_path = kmalloc(PATH_MAX, GFP_ATOMIC);
        if (!k_full_path) {
                pr_err("%s: error in kmalloc (get_full_path)\n", MODNAME);
                return NULL; 
        }

        ret = kern_path(rel_path, LOOKUP_FOLLOW, &path);
        if (ret == -ENOENT) {
                rel_path_tilde = kmalloc(PATH_MAX, GFP_ATOMIC);
                if (!rel_path_tilde) {
                        pr_err("%s: error in kmalloc (rel_path_tilde)\n", MODNAME);
                        return NULL; 
                }

                strcpy(rel_path_tilde, rel_path);
                strcat(rel_path_tilde, "~");

                ret = kern_path(rel_path_tilde, LOOKUP_FOLLOW, &path);

                kfree(rel_path_tilde);
        }
        if (ret) {
                pr_info("%s: full path not found (error %d) for file %s\n", MODNAME, ret, rel_path);
                kfree(k_full_path);
                return NULL;
        }

        ret = snprintf(k_full_path, PATH_MAX, "%s", d_path(&path, k_full_path, PATH_MAX));
        if (ret < 0 || ret >= PATH_MAX) {
                kfree(k_full_path);
                pr_err("%s: full path is too long\n", MODNAME);
        }

        tilde_pos = strrchr(k_full_path, '~');
        if (tilde_pos != NULL) {
                *tilde_pos = '\0'; 
        }

        return k_full_path;
}

unsigned long retrieve_inode_number(char *path) {

        struct path lookup_path;
        struct inode *inode;

        if (kern_path(path, 0, &lookup_path) != 0) {
                pr_err("%s: Failed to lookup path %s\n", MODNAME, path);
                return -1;
        }

        inode = lookup_path.dentry->d_inode;

        return inode->i_ino;

}


int is_directory(const char *path) {
        struct path p;
        int error;
        struct inode *inode;

        error = kern_path(path, LOOKUP_FOLLOW, &p);
        if(error) {
                pr_err("%s: error in kern_path (is_directory)\n", MODNAME);
                return 0;
        }

        inode = p.dentry->d_inode;
        
        return S_ISDIR(inode->i_mode);
}


char *get_dir_path_from_fd(int fd) {

        struct file *file;
        char *buffer, *path_name;
        int ret;
	struct path p;
	struct dentry *d;

        file = fget(fd);
        if (!file) {
                printk(KERN_ERR "Failed to get file from file descriptor\n");
                return NULL;
        }

        p = file->f_path;
        d = p.dentry;

        buffer = (char *)__get_free_page(GFP_ATOMIC);
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

char *get_full_path_from_fd(int fd, const char *filename) {

	char *dir, *full_path;

        /* get parent directory full path */
        dir = get_dir_path_from_fd(fd);
        if (!dir) {
                pr_err("%s: failed to get dir path\n", MODNAME);
                return NULL;
        }

        /* concatenate parent directory and filename */
        full_path = strcat(dir, filename);
        return full_path;
}



static struct file *open_program_file(char *filename) {
        
	struct file *file;
	
	file = filp_open(filename, O_RDONLY, 0);
        if (IS_ERR(file)) {

                /* if path starts with '/root/', replace it with '/' */
                if (strncmp(filename, "/root", 5) == 0) {
                        memmove(filename, filename + 5, strlen(filename) - 4);
                }

                file = filp_open(filename, O_RDONLY, 0);

                if (IS_ERR(file)) {
                        printk(KERN_ERR "Failed to open file %s\n", filename);
                        return NULL;
                }
        }

        return file;
}


char *calc_fingerprint(char *filename) {
        struct crypto_shash *hash_tfm;
        struct file *file;
        struct shash_desc *desc;
        unsigned char *digest;
        char *result = NULL;
        loff_t pos = 0;
        int ret, i;

        /* hash transform allocation */
        hash_tfm = crypto_alloc_shash("sha256", 0, 0);
        if (IS_ERR(hash_tfm)) {
                pr_err("Failed to allocate hash transform\n");
                return NULL;
        }

        /* offending program file opening */
        file = open_program_file(filename);
        if (!file) {
                crypto_free_shash(hash_tfm);
                return NULL;
        }

        /* hash descriptor allocation */
        desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(hash_tfm), GFP_ATOMIC);
        if (!desc) {
                pr_err("Failed to allocate hash descriptor\n");
                goto out;
        }
        desc->tfm = hash_tfm;

        /* digest allocation */
        digest = kmalloc(32, GFP_ATOMIC);
        if (!digest) {
                pr_err("Failed to allocate hash buffer\n");
                goto out;
        }

        /* hash computation */
        crypto_shash_init(desc);
        while (1) {
                char buf[512];
                ret = kernel_read(file, buf, sizeof(buf), &pos);
                if (ret <= 0)
                break;
                crypto_shash_update(desc, buf, ret);
        }
        crypto_shash_final(desc, digest);

        /* result allocation */
        result = kmalloc(2 * 32 + 1, GFP_ATOMIC);
        if (!result) {
                pr_err("Failed to allocate memory for result\n");
                goto out;
        }

        for (i = 0; i < 32; i++)
                sprintf(&result[i * 2], "%02x", digest[i]);
                
out:
        if (digest)
                kfree(digest);
        if (desc)
                kfree(desc);
        if (file)
                filp_close(file, NULL);
        if (hash_tfm)
                crypto_free_shash(hash_tfm);

        return result;
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
	int i;

        /* hash transform allocation */
        hash_tfm = crypto_alloc_shash("sha256", 0, 0);
        if (IS_ERR(hash_tfm)) {
                printk(KERN_ERR "Failed to allocate hash transform\n");
                return NULL;
        }

        /* hash descriptor allocation */
        desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(hash_tfm), GFP_ATOMIC);
        if (!desc) {
                printk(KERN_ERR "Failed to allocate hash descriptor\n");
                goto out;
        }
        desc->tfm = hash_tfm;

        /* digest allocation */
        digest = kmalloc(32, GFP_ATOMIC);
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
        result = kmalloc(2 * 32 + 1, GFP_ATOMIC);
        if (!result) {
                printk(KERN_ERR "Failed to allocate memory for result\n");
                goto out;
        }

        /* printing result */
        for (i = 0; i < 32; i++)
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


char *add_trailing_slash(char *input) {
    
	size_t len;
	char *result;

  	len = strlen(input);
    	result = kmalloc(len + 2, GFP_ATOMIC); 

    	if (result == NULL) {
        	pr_err("Errore di allocazione di memoria\n");
        	return NULL;
    	}

    	strcpy(result, input); 
    	result[len] = '/';      
    	result[len + 1] = '\0'; 

    	return result;
}

