/*================================================================
*   Copyright (C) 2019 Sangfor Ltd. All rights reserved.
*   
*   @File name：tools.c
*   @Author: nathan
*   @Date: 2019年05月09日
================================================================*/

#include "Tools.h"

int GetPidFromName(char *pTargetName)
{
	if (pTargetName == NULL) {
		LOGE("pTargetName is NULL.\n");
		return -1;
	}

	int iPid = -1;
	DIR *pDir = NULL;
	struct dirent *psDirEntry;
	int iTmpPid = -1;
	char sCmdLine[128] = {0};
	char sAppName[1024] = {0};
	int fd = -1;

	pDir = opendir("/proc");

	while ((psDirEntry = readdir(pDir)) != NULL) {
		iTmpPid = atoi(psDirEntry->d_name);
		if (iTmpPid == 0) {
			continue;
		}
		sprintf(sCmdLine, "/proc/%d/cmdline", iTmpPid);
		
		fd = open(sCmdLine, O_RDONLY);
		if (fd < 0) {
			LOGE("open: %s\n", strerror(errno));
			goto out;
		}
		if (read(fd, sAppName, sizeof(sAppName)) < 0) {
			LOGE("read: %s\n", strerror(errno));
			goto out;
		}
		close(fd);

		if (strcmp(sAppName, pTargetName) == 0) {
			iPid = iTmpPid;
			break;
		}

		memset(sCmdLine, 0, sizeof(sCmdLine));
		memset(sAppName, 0, sizeof(sAppName));
	}
	
out:
	return iPid;
}

