/*================================================================
*   Copyright (C) 2019 Sangfor Ltd. All rights reserved.
*   
*   @File name：inject.h
*   @Author: nathan
*   @Date: 2019年05月09日
================================================================*/

#ifndef __INJECT_H__
#define __INJECT_H__

#include <stdio.h>
#include <linux/ptrace.h>
#include <sys/wait.h>
#include <asm/ptrace.h>

#if __LP64__
typedef struct user_pt_regs PT_REGS;
#else 
typedef struct pt_regs PT_REGS;
#endif

int ptraceReadData(pid_t pid, void *targetAddr, uint8_t *data, size_t size);
int ptraceWriteData(pid_t pid, void *targetAddr, void *data, size_t size);
int ptraceWriteString(pid_t pid, void *targetAddr, char *str);
int ptraceCallFunc(pid_t pid, void *funcAddr, long *params, uint32_t paramsNum, PT_REGS *regs);
int ptraceGetRegs(pid_t pid, PT_REGS *regs);
int ptraceSetRegs(pid_t pid, PT_REGS *regs);
int ptraceContinue(pid_t pid);
int ptraceAttach(pid_t pid);
int ptraceDetach(pid_t pid);
long ptraceRetValue(PT_REGS *regs);

#endif
