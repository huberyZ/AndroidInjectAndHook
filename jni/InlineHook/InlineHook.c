/*================================================================
*   Copyright (C) 2019 Sangfor Ltd. All rights reserved.
*   
*   @File name：InlineHook.c
*   @Author: nathan
*   @Date: 2019年05月19日
================================================================*/

#include "InlineHook.h"

/*
 *	@pHookItemArray 要hook的目标条目数组
 *	@iHookItemArrayLength 数组的长度
 *	@pCallBackFunc 要跳转到的自定义的函数地址
 */
int InlineHook(void *pHookItemArray, int iHookItemArrayLength, void *pCallBackFunc)
{
	int i = 0;
	int iRet = -1;
	unsigned long ulHookAddr = 0;

	STInlineHookInfo *pstInlineHookInfo = NULL;

	if (pHookItemArray == NULL || pCallBackFunc == NULL || iHookItemArrayLength <= 0) {
		LOGE("check params\n");
		goto out;
	}

	for (i = 0; i < iHookItemArrayLength; i++) {
		
	}

	iRet = 0;
out:
	return iRet;
}


int HookThumb(STInlineHookInfo *pstInlineHookInfo)
{

}

int InitHookThumb(STInlineHookInfo *pstInlineHookInfo);

int HookArm(STInlineHookInfo *pstInlineHookInfo);

int InitHookArm(STInlineHookInfo *pstInlineHookInfo);

int CreateStub(STInlineHookInfo *pstInlineHookInfo);


