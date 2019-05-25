/*================================================================
*   Copyright (C) 2019 Sangfor Ltd. All rights reserved.
*   
*   @File name：InlineHook.h
*   @Author: nathan
*   @Date: 2019年05月19日
================================================================*/

#ifndef __INLINEHOOK_H__
#define __INLINEHOOK_H__

#include "../Inject/Inject.h"
#include "../Utils/Tools.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE	4096
#endif

#define PAGE_ALINE(addr)	((addr) & (~(PAGE_SIZE - 1)))
#define SET_BIT0(addr)		(addr | 1)

#if __LP64__
#define CLEAR_BIT(addr)		(addr & 0xFFFFFFFFFFFFFFFE)
#else
#define CLEAR_BIT(addr)		(addr & 0xFFFFFFFE)
#endif

typedef struct InlineHookInfo {
	void *pHookAddr;		// 要hook的地址
	void *pStubAddr;		// 跳转的桩的地址
	void **ppOriginalAddr;	
	void (*onCallBack)(PT_REGS *);
} STInlineHookInfo;

typedef struct HookTargetInfo {
	int iTargetOffset;
	int iInstructMode;
	char pTargetSoname[512];
} STHookItem;


int InlineHook(void *pHookItemArray, int iHookItemArrayLength, void *pCallBackFunc);

int HookThumb(STInlineHookInfo *pstInlineHookInfo);

int InitHookThumb(STInlineHookInfo *pstInlineHookInfo);

int HookArm(STInlineHookInfo *pstInlineHookInfo);

int InitHookArm(STInlineHookInfo *pstInlineHookInfo);

int CreateStub(STInlineHookInfo *pstInlineHookInfo);



#endif
