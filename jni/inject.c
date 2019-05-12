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
		LOGE("attach %d failed: %s\n", pid, strerror(errno));
		goto out;
	}
	waitpid(pid, NULL, WUNTRACED);

	result = ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
	if (result < 0) {
		LOGE("ptrace syscall failed: %s\n", strerror(errno));
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
		dataBuf.value = ptrace(PTRACE_PEEKTEXT, pid, targetAddr, NULL);
        if (dataBuf.value == -1) {
            LOGE("ptrace readData failed: %s\n", strerror(errno));
            goto out;
        }
        memcpy(tmpData, dataBuf.chars, sizeof(dataBuf.value));
        targetAddr ++;
        tmpData += sizeof(dataBuf.value);
	}

    if (tail > 0) {
		dataBuf.value = ptrace(PTRACE_PEEKTEXT, pid, targetAddr, NULL);
        if (dataBuf.value == -1) {
            LOGE("ptrace readData failed: %s\n", strerror(errno));
            goto out;
        }
        memcpy(tmpData, dataBuf.chars, tail);
    }
    
    result = 0;
out:
	return result;
}

int ptraceWriteData(pid_t pid, void *targetAddr, uint8_t *data, size_t size)
{
	union u {
		long value;
		char chars[sizeof(long)];
	} dataBuf;
	int loop = size / sizeof(long);
	int tail = size % sizeof(long);
	int i = 0, result = -1, ret = -1;
	uint8_t *tmpData = data;
    size_t stepLength = sizeof(dataBuf.value);

    for (i = 0; i < loop; i++) {
        memcpy(dataBuf.chars, tmpData, stepLength);
        ret = ptrace(PTRACE_POKETEXT, pid, targetAddr, dataBuf.value);
        if (ret == -1) {
            LOGE("ptrace writeData failed: %s\n", strerror(errno));
            goto out;
        }
        tmpData += stepLength;
        targetAddr++;
    }

    if (tail > 0) {
        dataBuf.value = ptrace(PTRACE_PEEKTEXT, pid, targetAddr, NULL);
        if (dataBuf.value == -1) {
            LOGE("ptrace writeData(prepare write tail) failed: %s\n", strerror(errno));
            goto out;
        }

		for (i = 0; i < tail; i++) {
			dataBuf.chars[i] = *tmpData++;
		}

		ret = ptrace(PTRACE_POKETEXT, pid, targetAddr, dataBuf.value);
		if (ret == -1) {
			LOGE("ptrace writeData(write tail) failed: %s\n", strerror(errno));
			goto out;
		}
    }

    result = 0;
out:
    return result;
}

int ptraceWriteString(pid_t pid, void *targetAddr, char *str)
{
	ptraceWriteData(pid, targetAddr, (uint8_t *)str, strlen(str) + 1);
}

#if __LP64__
int ptraceCallFunc(pid_t pid, void *funcAddr, long *params, uint32_t paramsNum, PT_REGS *regs)
{

}
#else
int ptraceCallFunc(pid_t pid, void *funcAddr, long *params, uint32_t paramsNum, PT_REGS *regs)
{
	int i;
	int result = -1;
	
	// 前4个参数存入r0 ~ r3
	for (i = 0; i < paramsNum && i < 4; i++) {
		regs->uregs[i] = params[i];
	}

	// 多余4个参数的，入栈
	if (i < paramsNum) {
		regs->ARM_sp -= (paramsNum - i) * sizeof(long);
		ptraceWriteData(pid, (void *)regs->ARM_sp, (uint8_t *)&params[i], (paramsNum - i) *sizeof(long));
	}

	// 把要执行的函数地址赋给pc寄存器
	regs->ARM_pc = (unsigned long)funcAddr;
	if (regs->ARM_pc & 1) {
		// thumb
		regs->ARM_pc &= (~1u);
		regs->ARM_cpsr |= CPSR_T_MASK;
	}
	else {
		// arm
		regs->ARM_cpsr &= ~CPSR_T_MASK;
	}

	regs->ARM_lr = 0; //置子程序的返回地址为空，以便函数执行完后，返回到null地址，产生SIGSEGV错误

	result = ptraceSetRegs(pid, regs);
	if (result < 0) {
		LOGE("ptraceSetRegs failed.\n");
		goto out;
	}

	result = ptraceContinue(pid);
	if (result < 0) {
		LOGE("ptraceContinue failed.\n");
		goto out;
	}
	
	int status = 0;
	waitpid(pid, &status, WUNTRACED);	// 等待目标进程中的函数执行完成后返回（返回到null地址，产生SIGSEGV信号）
	if (WSTOPSIG (status) != SIGSEGV) {
		 result = ptraceContinue(pid);
		 if (result < 0) {
			LOGE("ptrace call err.\n");
			goto out;
		}
		waitpid(pid, &status, WUNTRACED);
	}
	
out:
	return result;
}
#endif

long ptraceRetValue(PT_REGS *regs)
{
#if __LP64__
	return regs->regs[0];
#else
	return regs->ARM_r0;
#endif
}

int ptraceGetRegs(pid_t pid, PT_REGS *regs)
{
	int result = ptrace(PTRACE_GETREGS, pid, NULL, regs);
	if (result < 0) {
		LOGE("ptrace getregs: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int ptraceSetRegs(pid_t pid, PT_REGS *regs)
{
	int result = ptrace(PTRACE_SETREGS, pid, NULL, regs);
	if (result < 0) {
		LOGE("ptrace setregs: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int ptraceContinue(pid_t pid)
{
	int result = ptrace(PTRACE_CONT, pid, NULL, NULL);
	if (result < 0) {
		LOGE("ptrace continue: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int ptraceDetach(pid_t pid)
{
	int result = ptrace(PTRACE_DETACH, pid, NULL, NULL);
	if (result < 0) {
		LOGE("ptrace detach: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}


int main(int argc, char *argv[])
{
	if (argc < 2) {
		LOGE("please input the target app name...\n");
		goto out;
	}
	int result = -1, ret = -1;
	char *targetName = argv[1];
	pid_t targetPid = -1;

	targetPid = getPidFromName(targetName);
	if (targetPid == -1) {
		LOGE("err: getPidFromName found pid failed.\n");
		goto out;
	}
	LOGD("pid: %d\n", targetPid);

	ret = ptrace(PTRACE_ATTACH, targetPid, NULL, NULL);
	if (ret < 0) {
		LOGE("attach %d failed: %s\n", targetPid, strerror(errno));
		goto out;
	}
	wait(NULL);
	LOGD("attach target ok.\n");

	ret = ptrace(PTRACE_CONT, targetPid, NULL, NULL);
	if (ret < 0) {
		LOGE("continue %d failed: %s\n", targetPid, strerror(errno));
	}

	sleep(50);

	result = 0;
out:
	return result;
}
