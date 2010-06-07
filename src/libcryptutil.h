#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <wait.h>
#include <dirent.h>
#include <mntent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <parted/parted.h>
/* information about application */
#define 	NAME		"cryptutil"
#define 	VERSION		"0.0.1"
/* types of arguments */
#define		ARG_WRONG	-1
#define		ARG_DIR		1
#define 	ARG_PART	2
#define 	ARG_DISK	3
/* types of data for validation */
#define 	TYPE_ACTION	0
#define 	TYPE_ARGUMENT	1
/* additional information */
#define MOUNT_FILE		"/etc/mtab"
#define SIGNATURE		"ECRYPTFS_FNEK_ENCRYPTED"
/* additional functions */
int help(void);
int validation(const char *arg, int type);
int block_device_type(const char *arg);
int is_mounted(const char *path);
/* basis functions */
int encrypt(const char *path);
int decrypt(const char *path);
/* functions for directory */
int directory_is_encrypted(const char *directory);
int encrypt_directory(const char *directory);
int decrypt_directory(const char *directory);
