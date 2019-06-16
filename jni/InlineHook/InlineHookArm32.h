/*================================================================
*   Copyright (C) 2019 Sangfor Ltd. All rights reserved.
*   
*   @File name：InlineHookArm32.h
*   @Author: nathan
*   @Date: 2019年05月19日
================================================================*/

#ifndef __INLINEHOOK_H__
#define __INLINEHOOK_H__

#include <sys/mman.h>

#include "../Inject/Inject.h"
#include "../Utils/Tools.h"
#include "Ihook.h"

extern unsigned long _shellcode_start_arm32;
extern unsigned long _shellcode_end_arm32;
extern unsigned long _hookstub_function_addr_arm32;
extern unsigned long _original_function_addr_arm32;


int HookArm32(STInlineHookInfo *pstInlineHookInfo);

int InitHookArm32(STInlineHookInfo *pstInlineHookInfo);

int BackupOpcodeArm32(STInlineHookInfo *pstInlineHookInfo);

int BuildStubArm32(STInlineHookInfo *pstInlineHookInfo);

int BuildJumpBackFuncArm32(STInlineHookInfo *pstInlineHookInfo);

int BuildJumpInstArm32(void *pCurrentAddress, void *pJumpAddress);

int BuildHookTargetArm32(STInlineHookInfo *pstInlineHookInfo);

int LengthOfFixArm32(uint32_t uiOpcode);

static int GetTypeOfInstArm32(uint32_t uiInst);

int FixPCOpcodeArm32(void *pFixOpcodes, STInlineHookInfo *pstInlineHookInfo);

int _FixPCOpcodeArm32(uint32_t pc, uint32_t lr, uint32_t instruction, uint32_t *pTrampolineInstructions, STInlineHookInfo* pstInlineHook);


#endif
