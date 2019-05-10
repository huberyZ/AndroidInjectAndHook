/*================================================================
*   Copyright (C) 2019 Sangfor Ltd. All rights reserved.
*   
*   @File name：inject.c
*   @Author: nathan
*   @Date: 2019年05月09日
================================================================*/

#include "tools.h"
#include "inject.h"

int ptraceAttach(pid_t pid)
{
	int result = -1;
	
	result = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	if (result < 0) {
		LOGD("err: attach %d failed: %s\n", pid, strerror(errno));
		goto out;
	}
	waitpid(pid, NULL, WUNTRACED);

	result = ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
	if (result < 0) {
		LOGD("err: ptrace syscall failed: %s\n", strerror(errno));
		goto out;
	}

	waitpid(pid, NULL, WUNTRACED);

out:
	return result;
}


int ptraceReadData(pid_t pid, void *targetAddr, uint8_t *data, size_t size)
{
	union u {
		long value;
		char chars[sizeof(long)];
	} dataBuf;
	int loop = size / sizeof(long);
	int tail = size % sizeof(long);
	int i = 0, result = -1;
	uint8_t *tmpData = data;

	for (i = 0; i < loop; i++) {
		
	}
out:
	return result;
}

int ptraceWriteData(pid_t pid, void *targetAddr, void *data, size_t size)
{

}

int ptraceWriteString(pid_t pid, void *targetAddr, char *str)
{

}

int ptraceCallFunc(pid_t pid, void *funcAddr, long *params, uint32_t paramsNum, PT_REGS *regs)
{

}

long ptraceRetValue(PT_REGS *regs)
{

}

int ptraceGetRegs(pid_t pid, PT_REGS *regs)
{

}

int ptraceSetRegs(pid_t pid, PT_REGS *regs)
{

}

int ptraceContinue(pid_t pid)
{

}

int ptraceDetach(pid_t pid)
{

}




int main(int argc, char *argv[])
{
	if (argc < 2) {
		LOGD("err: please input the target app name...\n");
		goto out;
	}
	int result = -1, ret = -1;
	char *targetName = argv[1];
	pid_t targetPid = -1;

	printf("unsigned long %lu\n", sizeof(unsigned long));
	printf("long %ld\n", sizeof(long));

	targetPid = getPidFromName(targetName);
	if (targetPid == -1) {
		LOGD("err: getPidFromName found pid failed.\n");
		goto out;
	}
	LOGD("pid: %d\n", targetPid);

	ret = ptrace(PTRACE_ATTACH, targetPid, NULL, NULL);
	if (ret < 0) {
		LOGD("err: attach %d failed: %s\n", targetPid, strerror(errno));
		goto out;
	}
	wait(NULL);
	LOGD("attach target ok.\n");

	ret = ptrace(PTRACE_CONT, targetPid, NULL, NULL);
	if (ret < 0) {
		LOGD("err: continue %d failed: %s\n", targetPid, strerror(errno));
	}

	sleep(50);

	result = 0;
out:
	return result;
}
