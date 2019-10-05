#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <errno.h>

int main(int argc, char *argv[])
{
	int result;
	
	//
	// announce that we are here, in the INIT program
	//
	result = printf("INIT: performing switch_root\n");
	if(result <= 0) exit(1);

	//
	// mount the procfs, sysfs and devtmpfs
	//
	result = mount("none", "/proc", "proc", MS_SILENT, NULL);
	if(result != 0) exit(2);

	result = mount("none", "/sys", "sysfs", MS_SILENT, NULL);
	if(result != 0) exit(3);

	result = mount("none", "/dev", "devtmpfs", MS_SILENT, NULL);
	if(result != 0) exit(4);

	//
	// mount our new rootfs that we want to switch to.  This is all hard
	// coded but if we wanted to be more flexible we could read the
	// /proc/cmdline parameters and parse out a new "root" and "rootfstype"
	// and "rootflags" and "init" to dynamically modify the behavior.
	//
	result = mount("/dev/sda1", "/mnt/root", "ext4", MS_SILENT, NULL);
	if(result != 0) {
		if(errno == ENOENT) {
			printf("INIT: waiting for root device /dev/sda1\n");
			do {
				if(errno == ENOENT) {
					printf("Goal 1\n");
					usleep(10000);
					result = mount("/dev/sda1", "/mnt", "ext3", MS_SILENT, NULL);
				} else {
					perror("mount failed");
					printf("errno = %d\n", errno);
					exit(5);
				}
			} while(result != 0);
		} else {
			perror("mount failed");
			printf("errno = %d\n", errno);
			exit(6);
		}
	}
	printf("Goal 1\n");
	//
	// execute switch_root to our new rootfs and run /sbin/init from it
	//
	static char *my_argv[]={"switch_root","/mnt", "/sbin/init", NULL};
	printf("Goal 2\n");
	execv("/sbin/switch_root", my_argv);
	printf("Goal 3\n");
	
	//
	// we only get here if execv() fails
	//
	exit(6);
}

