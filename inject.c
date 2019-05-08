#include <stdio.h>
#include <stdlib.h>
#include <linux/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <android/log.h>
#include <elf.h>

int getPidFromName(char *targetName)
{
	if (targetName == NULL) {
		printf("err: targetName is NULL.\n");
		return -1;
	}

	int pid = -1;
	DIR *pDir = NULL;
	struct dirent *dirEntry;
	int tmpPid = -1;
	char cmdline[128] = {0};
	char appName[1024] = {0};
	int fd = -1;
	int ret = -1;

	pDir = opendir("/proc");

	while ((dirEntry = readdir(pDir)) != NULL) {
		tmpPid = atoi(dirEntry->d_name);
		if (tmpPid == 0) {
			continue;
		}
		sprintf(cmdline, "/proc/%d/cmdline", tmpPid);
		
		fd = open(cmdline, O_RDONLY);
		if (fd < 0) {
			printf("open err: %s\n", strerror(errno));
			goto out;
		}
		ret = read(fd, appName, sizeof(appName));
		if (ret < 0) {
			printf("read err: %s\n", strerror(errno));
			goto out;
		}
		close(fd);

		if (strcmp(appName, targetName) == 0) {
			pid = tmpPid;
			break;
		}

		memset(cmdline, 0, sizeof(cmdline));
		memset(appName, 0, sizeof(appName));
	}
	
out:
	return pid;
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		printf("err: please input the target app name...\n");
		goto out;
	}
	int result = -1, ret = -1;
	char *targetName = argv[1];
	pid_t targetPid = -1;

	targetPid = getPidFromName(targetName);
	if (targetPid == -1) {
		printf("err: getPidFromName found pid failed.\n");
		goto out;
	}
	printf("pid: %d\n", targetPid);

	ret = ptrace(PTRACE_ATTACH, targetPid, NULL, NULL);
	if (ret < 0) {
		printf("err: attach %d failed: %s\n", targetPid, strerror(errno));
		goto out;
	}
	wait(NULL);
	printf("attach target ok.\n");

	ret = ptrace(PTRACE_CONT, targetPid, NULL, NULL);
	if (ret < 0) {
		printf("err: continue %d failed: %s\n", targetPid, strerror(errno));
	}

	sleep(50);

	result = 0;
out:
	return result;
}
