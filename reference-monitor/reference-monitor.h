#define MODNAME "REFERENCE MONITOR"
#define LOG_FILE "/mnt/ref-monitor-fs/ref-monitor-log.txt"
#define PASSW_LEN 32
#define AUDIT if(1)
#define NUM_KRETPROBES 6

/* syscall remove from blacklist modes */
#define DELETE_DIRS_ONLY 0		// remove only directory and eventual subdirectories
#define DELETE_ALL 1			// remove both directory and files/subdirectories

char *encrypt_password(const char *password);
int add_directory_to_rf(struct file *dir, char *dir_name);

struct nameidata {
	struct path	path;
	struct qstr	last;
	struct path	root;
	struct inode	*inode; /* path.dentry.d_inode */
	unsigned int	flags, state;
	unsigned	seq, next_seq, m_seq, r_seq;
	int		last_type;
	unsigned	depth;
	int		total_link_count;
	struct saved {
		struct path link;
		struct delayed_call done;
		const char *name;
		unsigned seq;
	} *stack, internal[2];
	struct filename	*name;
	struct nameidata *saved;
	unsigned	root_seq;
	int		dfd;
	vfsuid_t	dir_vfsuid;
	umode_t		dir_mode;
};

struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};

struct invalid_operation_data {
        char *message;
};


struct blacklist_entry {
        struct list_head list;
        char *path;
        char *filename;
        unsigned long inode_number;
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
};


struct log_data {
        int tid;
        int tgid;
        unsigned int uid;
        unsigned int euid;
        char *exe_path;
        char *hash;
};



typedef struct _packed_work{
        void* buffer;
        struct log_data *log_data;
        struct work_struct the_work;
} packed_work;


struct custom_dir_context {
    struct dir_context dir_ctx; 
    char *dir_path; 
};