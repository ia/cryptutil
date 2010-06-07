#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "libcryptutil.h"

/* is path already mounted? */
int is_mounted(const char *path)
{
	/* init mount information */
	char *mount_file = MOUNT_FILE;
	FILE *file_pointer = NULL;
	struct mntent *file_system;
	/* get mount information */
	file_pointer = setmntent(mount_file, "r");
	if (file_pointer == NULL) {
		fprintf(stderr, "%s: %s: cannot open: %s (%s)\n", NAME, "ERROR", path, strerror(errno));
		exit(1);
	}
	/* detect mount status of path */
	int status = 0;
	while ((file_system = getmntent(file_pointer)) != NULL)
		if ((strcmp(file_system->mnt_fsname, path) == 0) || (strcmp(file_system->mnt_dir, path) == 0)) {
			printf("%s: %s: %s is mounted as %s\n", NAME, "ERROR", path, file_system->mnt_fsname);
			status = 1;
		}
	/* release pointer */
	endmntent(file_pointer);
	/* exit */
	return status;
}

/* is directory already encrypted? */
int directory_is_encrypted(const char *directory)
{
	/* re-init directory */
	char dir_path[PATH_MAX + 1];
	strncpy(dir_path, directory, sizeof(dir_path));
	/* /path/to/directory -> /path/to/directory/ */
	size_t dir_len = strlen(directory);
	if (dir_path[dir_len - 1] != '/') {
		dir_path[dir_len] = '/';
		dir_path[dir_len + 1] = '\0';
		++dir_len;
	}
	/* /path/to/directory/ -> /path/to/directory/.ecryptfs */
	char dir_enc[PATH_MAX];
	strcpy(dir_enc, dir_path);
	strcat(dir_enc, ".ecryptfs");
	/* get stat information about .ecryptfs dir */
	struct stat st;
	if (lstat(dir_enc, &st)) {
		return 0;
	}
	if (!(S_ISDIR(st.st_mode))) {
		return 0;
	}
	/* status of directory */
	int empty = 1;
	/* signature for encrypted data */
	char *sign = SIGNATURE;
	/* search directory for signature */
	DIR *dir = opendir(dir_enc);
	struct dirent *entry;
	while((entry = readdir(dir)) != NULL) {
		if ((strcmp(entry->d_name, ".") != 0) && (strcmp(entry->d_name, "..") != 0))
			if (strstr(entry->d_name, sign)) {
				empty = 0;
				break;
			}
	}
	/* release directory */
	closedir(dir);
	/* return result */
	if (!empty)
		return 1;
	else
		return 0;
}

/* decrypt directory */
int decrypt_directory(const char *directory)
{
	/* re-init directory */
	char dir_path[PATH_MAX];
	strncpy(dir_path, directory, sizeof(dir_path));
	/* /path/to/directory -> /path/to/directory/ */
	size_t dir_len = strlen(dir_path);
	if (dir_path[dir_len - 1] != '/') {
		dir_path[dir_len] = '/';
		dir_path[dir_len + 1] = '\0';
		++dir_len;
	}
	/* /path/to/directory -> /path/to/directory/.ecryptfs */
	char dir_enc[PATH_MAX];
	strcpy(dir_enc, dir_path);
	strcat(dir_enc, ".ecryptfs");
	/* init mount options for ecryptfs file system */
	char *const mount_argv[] = {"mount",
				"-tecryptfs",
				"-okey=passphrase",
				"-oecryptfs_cipher=aes",
				"-oecryptfs_key_bytes=16",
				"-oecryptfs_passthrough=no",
				"-oecryptfs_enable_filename_crypto=yes",
				"-ono_sig_cache",
				dir_enc,
				dir_path,
				NULL};
	/* show warning message */
	printf("%s: %s: on FNEK asking just hit enter\n", NAME, "WARNING");
	/* init child process for mounting ecryptfs */
	int status;
	pid_t child;
	if (!(child = fork())) {
		execvp("mount", mount_argv);
		exit(0);
	}
	waitpid(child, &status, 0);
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		;
	} else {
		printf("%s: %s: cannot decrypt directory %s\n", NAME, "ERROR", dir_path);
	}
	/* status of decryption */
	int wrong_password = 0;
	/* signature for encrypted data */
	char * signature = SIGNATURE;
	/* search directory for undecrypted data */
	DIR *dir = opendir(dir_path);
	struct dirent* entry;
	while((entry = readdir(dir)) != NULL) {
		if ((strcmp(entry->d_name, ".") != 0) && (strcmp(entry->d_name, "..") != 0))
			if (strstr(entry->d_name, signature)) {
				wrong_password = 1;
				break;
			}
	}
	/* release directory */
	closedir(dir);
	/* init umount options */
	char *const umount_argv[] = {"umount", dir_path, NULL};
	/* if password wrong and decrypted data is mess then unmount ecryptfs */
	if (wrong_password) {
		printf("%s: %s: wrong password for decrypting directory %s\n", NAME, "ERROR", dir_path);
		if (!(child = fork())) {
			execvp("umount", umount_argv);
			exit(0);
		}
		waitpid(child, &status, 0);
		if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
			;
		}
		else {
			printf("%s: %s: cannot unmount directory %s\n", NAME, "ERROR", dir_path);
		}
	}
	/* exit */
	return 0;
}

/* encrypt directory */
int encrypt_directory(const char *directory)
{
	/* re-init directory */
	char dir_path[PATH_MAX];
	strncpy(dir_path, directory, sizeof(dir_path));
	/* /path/to/directory -> /path/to/directory/ */
	size_t dir_len = strlen(dir_path);
	if (dir_path[dir_len - 1] != '/') {
		dir_path[dir_len] = '/';
		dir_path[dir_len + 1] = '\0';
		++dir_len;
	}
	/* /path/to/directory -> /path/to/directory/.ecryptfs */
	char dir_enc[PATH_MAX];
	strcpy(dir_enc, dir_path);
	strcat(dir_enc, ".ecryptfs");
	/* /path/to/directory -> /path/to/directory_ENCTMP */
	char dir_tmp[PATH_MAX];
	strcpy(dir_tmp, dir_path);
	dir_tmp[dir_len - 1] = '\0';
	strcat(dir_tmp, "_ENCTMP");
	/* move unencrypted data in temp directory before encryption */
	if (rename(dir_path, dir_tmp)) {
		fprintf(stderr, "%s: %s: cannot rename %s to %s (%s)\n", NAME, "ERROR", dir_path, dir_tmp, strerror(errno));
		return 1;
	}
	/* set up access rights rwx --- --- for encrypted dirs */
	mode_t mode = S_IRWXU;
	/* create dirs for EcryptFS handle */
	mkdir(dir_path, mode);
	mkdir(dir_enc, mode);
	/* get information about temp dir */
	struct stat st;
	if (lstat(dir_tmp, &st)) {
		fprintf(stderr, "%s: %s: cannot get information from %s (%s)\n", NAME, "ERROR", dir_tmp, strerror(errno));
		return 1;
	}
	/* return owner/group rights for dirs */
	chown(dir_path, st.st_uid, st.st_gid);
	chown(dir_tmp, st.st_uid, st.st_gid);
	chown(dir_enc, st.st_uid, st.st_gid);
	/* init mount options for ecryptfs file system */
	char *const mount_argv[] = {"mount",
				"-tecryptfs",
				"-okey=passphrase",
				"-oecryptfs_cipher=aes",
				"-oecryptfs_key_bytes=16",
				"-oecryptfs_passthrough=no",
				"-oecryptfs_enable_filename_crypto=yes",
				"-ono_sig_cache",
				dir_enc,
				dir_path,
				NULL};
	/* warning message */
	printf("%s: %s: on FNEK asking just hit enter\n", NAME, "WARNING");
	printf("%s: %s: passphrase for encryption will be asked only one time!\n", NAME, "WARNING");
	/* init child process for mounting ecryptfs */
	int status;
	pid_t child;
	if (!(child = fork())) {
		execvp("mount", mount_argv);
		exit(0);
	}
	waitpid(child, &status, 0);
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		;
	} else {
		printf("%s: %s: cannot encrypt directory %s\n", NAME, "ERROR", dir_path);
	}
	/* init mv options for moving dir with data to new EcryptFS file system */
	char *const mv_argv[] = {"mv", dir_tmp, dir_path, NULL};
	/* init child process for moving files */
	if (!(child = fork())) {
		execvp("mv", mv_argv);
		exit(0);
	}
	waitpid(child, &status, 0);
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		;
	} else {
		printf("%s: %s: cannot move directory from %s to %s\n", NAME, "ERROR", dir_tmp, dir_path);
	}
	/* /path/to/directory -> /path/to/directory/directory_ENCTMP */
	char new_dir_path[PATH_MAX];
	strcpy(new_dir_path, dir_path);
	char *pos = strrchr(dir_tmp, '/');
	strcat(new_dir_path, ++pos);
	/* /path/to/directory/directory_ENCTMP handle */
	char src_entry_path[PATH_MAX + 1];
	size_t src_path_len = strlen(new_dir_path);
	strncpy(src_entry_path, new_dir_path, sizeof(src_entry_path));
	/* /path/to/directory/directory handle */
	char dest_entry_path[PATH_MAX + 1];
	size_t dest_path_len = strlen(dir_path);
	strncpy(dest_entry_path, dir_path, sizeof(dest_entry_path));
	/* /path/to/directory/directory_ENCTMP -> /path/to/directory/directory_ENCTMP/ */
	if (src_entry_path[src_path_len - 1] != '/') {
		src_entry_path[src_path_len] = '/';
		src_entry_path[src_path_len + 1] = '\0';
		++src_path_len;
	}
	/* move data from old directory to new encrypted directory */
	struct dirent *entry;
	DIR *dir = opendir(new_dir_path);
	while((entry = readdir(dir)) != NULL) {
		if ((strcmp(entry->d_name, ".") != 0) && (strcmp(entry->d_name, "..") != 0)) {
			strncpy(src_entry_path + src_path_len, entry->d_name, sizeof(src_entry_path) - src_path_len);
			strncpy(dest_entry_path + dest_path_len, entry->d_name, sizeof(dest_entry_path) - dest_path_len);
			if (rename(src_entry_path, dest_entry_path))
				fprintf(stderr, "%s: %s: cannot rename %s to %s (%s)\n", NAME, "ERROR", src_entry_path, dest_entry_path, strerror(errno));
		}
	}
	/* release dir */
	closedir(dir);
	/* delete old directory */
	rmdir(new_dir_path);
	/* exit */
	return 0;
}

/* encrypt path */
int encrypt(const char *path)
{
	/* validate path argument */
	switch(validation(path, TYPE_ARGUMENT)) {
		case ARG_DIR:
			if (is_mounted(path)) {
				return 1;
			}
			if (directory_is_encrypted(path)) {
				printf("%s: %s: directory %s is encrypted already\n", NAME, "ERROR", path);
				return 1;
			}
			encrypt_directory(path);
			break;
		case ARG_PART:
			printf("%s: %s: encrypt partition %s is not implemented yet\n", NAME, "TODO", path);
			break;
		case ARG_DISK:
			printf("%s: %s: encrypt disk %s is not implemented yet\n", NAME, "TODO", path);
			break;
		default:
			printf("%s: %s: file type of %s doesn't support\n", NAME, "ERROR", path);
			break;
	}
	/* exit */
	return 0;
}

/* decrypt path */
int decrypt(const char *path)
{
	/* validate path argument */
	switch(validation(path, TYPE_ARGUMENT)) {
		case ARG_DIR:
			if (is_mounted(path)) {
				return 1;
			}
			if (!(directory_is_encrypted(path))) {
				printf("%s: %s: directory %s is not encrypted\n", NAME, "ERROR", path);
				return 1;
			}
			decrypt_directory(path);
			break;
		case ARG_PART:
			printf("%s: %s: decrypt partition %s is not implemented yet\n", NAME, "TODO", path);
			break;
		case ARG_DISK:
			printf("%s: %s: decrypt disk %s is not implemented yet\n", NAME, "TODO", path);
			break;
		default:
			printf("%s: %s: file type of %s doesn't support\n", NAME, "ERROR", path);
			break;
	}
	/* exit */
	return 0;
}

/* show help message */
int help(void)
{
	printf("%s %s\n", NAME, VERSION);
	printf("Usage: %s <action> <options>\n", NAME);
	printf("Available <action>:\n");
	printf("\thelp\t\t-\tshow this help message\n");
	printf("\tencrypt\t\t-\tencrypt directory/partition/disk\n");
	printf("\tdecrypt\t\t-\tdecrypt directory/partition/disk\n");
	/* exit */
	return 0;
}
