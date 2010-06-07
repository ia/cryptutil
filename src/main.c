#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "libcryptutil.h"

/* generate usage message */
int usage(const char *name)
{
	/* show generic info */
	printf("%s: missing action\n", name);
	printf("Usage: %s <action> <options>\n", name);
	printf("Available <action>:\n");
	printf("\thelp\t\t-\tshow help message\n");
	printf("\tencrypt\t\t-\tencrypt directory/partition/disk\n");
	printf("\tdecrypt\t\t-\tdecrypt directory/partition/disk\n");
	/* exit */
	return 1;
}

/* validate actions and arguments */
int validation(const char *arg, int type)
{
	/* list of avilable actions */
	const char *actions[] = {"encrypt", "decrypt", "help", NULL};
	struct stat st;
	int count = 0;
	switch(type) {
		/* validate action */
		case TYPE_ACTION:
			for (count = 0; actions[count]; count++)
				if (strcmp(actions[count], arg) == 0)
					break;
			if (!actions[count])
				return usage(NAME);
			else
				return 0;
			break;
		/* validate type of argument and return it */
		case TYPE_ARGUMENT:
			if (lstat(arg, &st))
				return ARG_WRONG;
			if (S_ISDIR(st.st_mode))
				return ARG_DIR;
			else if (S_ISBLK(st.st_mode))
				return block_device_type(arg);
			else
				return ARG_WRONG;
			break;
	}
	return 0;
}

/* check type of block device argument */
int block_device_type(const char *arg)
{
	/* init vars for libparted library */
	PedDevice *device = NULL;
	PedDisk *disk = NULL;
	PedPartition *part = NULL;
	/* get block devices */
	ped_device_probe_all ();
	/* check block device for disk */
	while ((device = ped_device_get_next(device))) {
		disk = ped_disk_new(device);
		char disk_name[PATH_MAX];
		strcpy(disk_name, device->path);
		if (strcmp(disk_name, arg) == 0) {
			return ARG_DISK;
		}
		/* check block device for parition */
		for (part = ped_disk_next_partition (disk, NULL); part; part = ped_disk_next_partition (disk, part)) {
			if (part->num != -1) {
				char partition_num[PATH_MAX];
				sprintf(partition_num, "%d", part->num);
				char partition_name[PATH_MAX];
				strcpy(partition_name, device->path);
				strcat(partition_name, partition_num);
				if (strcmp(partition_name, arg) == 0)
					return ARG_PART;
				/* clean up buffers for checking next partition */
				int i;
				for (i = 0; i < PATH_MAX; i++) {
					partition_num[i] = '\0';
					partition_name[i] = '\0';
				}
			}
		}
	}
	return ARG_WRONG;
}

/* get administrative rights */
int root(const char *argv[])
{
	/* init buffer with arguments */
	char *args[PATH_MAX];
	args[0] = "sudo";
	/* copy input arguments */
	int i = 0, j = 1;
	while(argv[i])
		args[j++] = argv[i++];
	/* init getting root */
	int status;
	pid_t child;
	if (!(child = fork())) {
		execvp("sudo", args);
		exit(0);
	}
	/* wait for get root and return result */
	waitpid(child, &status, 0);
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
		return 0;
	else {
		printf("%s: %s: cannot get administrative rights to perform action\n", NAME, "ERROR");
		return -1;
	}
}

/* main */
int main(int argc, const char *argv[])
{
	/* detect application name */
	const char *name = argv[0];
	/* detect first argument */
	if (!argv[1])
		return usage(name);
	/* detect primary action */
	const char *action = argv[1];
	if (validation(action, TYPE_ACTION))
		return 1;
	if (strcmp(action, "help") == 0) {
		help();
		return 0;
	}
	/* detect primary argument */
	if (!argv[2])
		return 1;
	/* check primary argument */
	const char *arg = argv[2];
	char resolved_arg[PATH_MAX];
	/* get real path for argument */
	if (!realpath(arg, resolved_arg)) {
		fprintf(stderr, "%s: %s: cannot resolve %s (%s)\n", NAME, "ERROR", resolved_arg, strerror(errno));
		return 1;
	}
	/* get root rights */
	if (getuid() && !(root(argv)))
		return 1;
	/* detect and perform action */
	if (strcmp(action, "encrypt") == 0)
		encrypt(resolved_arg);
	else if (strcmp(action, "decrypt") == 0)
		decrypt(resolved_arg);
	else
		return usage(name);
	/* exit */
	return 0;
}
