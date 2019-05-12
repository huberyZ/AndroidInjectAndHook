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

#include "log.h"

#define CPSR_T_MASK        ( 1u << 5 )

#if __LP64__
#define ARM_sp sp
#define ARM_pc pc
#define ARM_cpsr	pstate
#define ARM_lr		regs[30]
#define ARM_r0		regs[0]
#define PTRACE_SETREGS PTRACE_SETREGSET
#define PTRACE_GETREGS PTRACE_GETREGSET
typedef struct user_pt_regs PT_REGS;
#define uregs regs

#define PARAM_REGS_NUM 8
#else 
typedef struct pt_regs PT_REGS;

#define PARAM_REGS_NUM 4
#endif

int ptraceReadData(pid_t pid, void *targetAddr, uint8_t *data, size_t size);
int ptraceWriteData(pid_t pid, void *targetAddr, uint8_t *data, size_t size);
int ptraceWriteString(pid_t pid, void *targetAddr, char *str);
int ptraceCallFunc(pid_t pid, void *funcAddr, long *params, uint32_t paramsNum, PT_REGS *regs);
int ptraceGetRegs(pid_t pid, PT_REGS *regs);
int ptraceSetRegs(pid_t pid, PT_REGS *regs);
int ptraceContinue(pid_t pid);
int ptraceAttach(pid_t pid);
int ptraceDetach(pid_t pid);
long ptraceRetValue(PT_REGS *regs);

#endif
