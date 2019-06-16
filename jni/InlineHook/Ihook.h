/*================================================================
*   Copyright (C) 2019 Sangfor Ltd. All rights reserved.
*   
*   @File name：Ihook.h
*   @Author: nathan
*   @Date: 2019年06月16日
================================================================*/

#ifndef __IHOOK_H__
#define __IHOOK_H__

#include "../Inject/Inject.h"
#include "../Utils/Tools.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE	4096
#endif

#define PAGE_ALINE(addr)	((addr) & (~(PAGE_SIZE - 1)))
#define SET_BIT0(addr)		(addr | 1)
#define BACKUP_FIX_INST_MAX 10
#define BACKUP_OPCODE_MAX_LEN   12

#if __LP64__
#define CLEAR_BIT(addr)		(addr & 0xFFFFFFFFFFFFFFFE)
#else
#define CLEAR_BIT(addr)		(addr & 0xFFFFFFFE)
#define ALIGN_PC(pc)	(pc & 0xFFFFFFFC)
#endif

enum INSTRUCTION_TYPE {
	// B <label>
	B1_THUMB16,
    // B <label>
    B1_BEQ_THUMB16,
    // B <label>
    B1_BNE_THUMB16,
    // B <label>
    B1_BCS_THUMB16,
    // B <label>
    B1_BCC_THUMB16,
    // B <label>
    B1_BMI_THUMB16,
    // B <label>
    B1_BPL_THUMB16,
    // B <label>
    B1_BVS_THUMB16,
    // B <label>
    B1_BVC_THUMB16,
    // B <label>
    B1_BHI_THUMB16,
    // B <label>
    B1_BLS_THUMB16,
    // B <label>
    B1_BGE_THUMB16,
    // B <label>
    B1_BLT_THUMB16,
    // B <label>
    B1_BGT_THUMB16,
    // B <label>
    B1_BLE_THUMB16,
	// B <label>
	B2_THUMB16,
	// BX PC
	BX_THUMB16,
	// ADD <Rdn>, PC (Rd != PC, Rn != PC) 在对ADD进行修正时，采用了替换PC为Rr的方法，当Rd也为PC时，由于之前更改了Rr的值，可能会影响跳转后的正常功能。
	ADD_THUMB16,
	// MOV Rd, PC
	MOV_THUMB16,
	// ADR Rd, <label>
	ADR_THUMB16,
	// LDR Rt, <label>
	LDR_THUMB16,

	// CB{N}Z <Rn>, <label>
	CB_THUMB16,


	// BLX <label>
	BLX_THUMB32,
	// BL <label>
	BL_THUMB32,
	// B.W <label>
	B1_THUMB32,
    // B.W <label>
    B1_BEQ_THUMB32,
    // B.W <label>
    B1_BNE_THUMB32,
    // B.W <label>
    B1_BCS_THUMB32,
    // B.W <label>
    B1_BCC_THUMB32,
    // B.W <label>
    B1_BMI_THUMB32,
    // B.W <label>
    B1_BPL_THUMB32,
    // B.W <label>
    B1_BVS_THUMB32,
    // B.W <label>
    B1_BVC_THUMB32,
    // B.W <label>
    B1_BHI_THUMB32,
    // B.W <label>
    B1_BLS_THUMB32,
    // B.W <label>
    B1_BGE_THUMB32,
    // B.W <label>
    B1_BLT_THUMB32,
    // B.W <label>
    B1_BGT_THUMB32,
    // B.W <label>
    B1_BLE_THUMB32,
	// B.W <label>
	B2_THUMB32,
	// ADR.W Rd, <label>
	ADR1_THUMB32,
	// ADR.W Rd, <label>
	ADR2_THUMB32,
	// LDR.W Rt, <label>
	LDR_THUMB32,
	// TBB [PC, Rm]
	TBB_THUMB32,
	// TBH [PC, Rm, LSL #1]
	TBH_THUMB32,

	// BLX <label>
	BLX_ARM,
	// BL <label>
	BL_ARM,
	// B <label>
	B_ARM,

    // <Add by GToad>
    // B <label>
	BEQ_ARM,
    // B <label>
	BNE_ARM,
    // B <label>
	BCS_ARM,
    // B <label>
	BCC_ARM,
    // B <label>
	BMI_ARM,
    // B <label>
	BPL_ARM,
    // B <label>
	BVS_ARM,
    // B <label>
	BVC_ARM,
    // B <label>
	BHI_ARM,
    // B <label>
	BLS_ARM,
    // B <label>
	BGE_ARM,
    // B <label>
	BLT_ARM,
    // B <label>
	BGT_ARM,
    // B <label>
	BLE_ARM,
    // </Add by GToad>

	// BX PC
	BX_ARM,
	// ADD Rd, PC, Rm (Rd != PC, Rm != PC) 在对ADD进行修正时，采用了替换PC为Rr的方法，当Rd也为PC时，由于之前更改了Rr的值，可能会影响跳转后的正常功能;实际汇编中没有发现Rm也为PC的情况，故未做处理。
	ADD_ARM,
	// ADR Rd, <label>
	ADR1_ARM,
	// ADR Rd, <label>
	ADR2_ARM,
	// MOV Rd, PC
	MOV_ARM,
	// LDR Rt, <label>
	LDR_ARM,

	UNDEFINE,
};



typedef struct InlineHookInfo {
	void *pHookAddr;		// 要hook的地址
	void *pStubAddr;		// 跳转的桩的地址
	void **ppOriginalFuncAddr;	// 构造返回到hook点的函数地址
    unsigned char backupOpcodes[BACKUP_OPCODE_MAX_LEN];      
    int backupLength;
    int backupFixLengthArray[BACKUP_FIX_INST_MAX];
	void (*onCallBack)(PT_REGS *);
    uint32_t *pNewEntryForOriginalFuncAddr;
} STInlineHookInfo;

typedef struct HookTargetInfo {
	int iTargetOffset;
	int iInstructMode;
	char pTargetSoname[512];
} STHookItem;



#endif
