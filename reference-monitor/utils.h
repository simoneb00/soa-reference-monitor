char *get_path_from_dentry(struct dentry *dentry);
char *get_full_path(const char *rel_path);
unsigned long retrieve_inode_number(char *path);
int is_directory(const char *path);
char *get_dir_path_from_fd(int fd);
char *get_full_path_from_fd(int fd, const char *filename);
char *calc_fingerprint(char *filename);
char *encrypt_password(const char *password);
char *add_trailing_slash(char *input);
