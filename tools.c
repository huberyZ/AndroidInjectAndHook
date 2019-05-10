/*================================================================
*   Copyright (C) 2019 Sangfor Ltd. All rights reserved.
*   
*   @File name：tools.c
*   @Author: nathan
*   @Date: 2019年05月09日
================================================================*/

#include "tools.h"

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

