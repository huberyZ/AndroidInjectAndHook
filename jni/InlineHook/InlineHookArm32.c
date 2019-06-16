/*================================================================
*   Copyright (C) 2019 Sangfor Ltd. All rights reserved.
*   
*   @File name：InlineHookArm32.c
*   @Author: nathan
*   @Date: 2019年05月19日
================================================================*/

#include "InlineHookArm32.h"

int HookArm32(STInlineHookInfo *pstInlineHookInfo)
{
	int iRet = -1;

	if (pstInlineHookInfo == NULL) {
		LOGE("pstInlineHookInfo is NULL.\n");
		goto err;
	}

	if (InitHookArm32(pstInlineHookInfo)) {
		LOGE("init hookarm err.\n");
		goto err;
	}

    if (BuildHookTargetArm32(pstInlineHookInfo)) {
        LOGE("BuildHookTarget err.\n");
        goto err;
    }
	
	iRet = 0;
err:
	return iRet;
}

int BuildHookTargetArm32(STInlineHookInfo *pstInlineHookInfo)
{
    int iRet = -1;

    if (pstInlineHookInfo == NULL) {
        LOGE("pstInlineHookInfo is NULL.\n");
        goto err;
    }

    if (ChangePageAttr(pstInlineHookInfo->pHookAddr, 12, PROT_READ|PROT_WRITE|PROT_EXEC)) {
        LOGE("change page property failed.\n");
        goto err;
    }

    if (BuildJumpInstArm32(pstInlineHookInfo->pHookAddr, pstInlineHookInfo->pStubAddr)) {
        LOGE("BuildJumpInstArm32 failed.\n");
        goto err;
    }

    iRet = 0;
err:
    return iRet;
}

int BuildStubArm32(STInlineHookInfo *pstInlineHookInfo)
{
    int iRet = -1;

    if (pstInlineHookInfo == NULL) {
        LOGE("pstInlineHookInfo is NULL\n");
        goto err;
    }
    
    void *pShellcodeStartArm32 = &_shellcode_start_arm32;
    void *pShellcodeEndArm32 = &_shellcode_end_arm32;
    void *pHookstubFunctionAddrArm32 = &_hookstub_function_addr_arm32;
    void *pOriginalFunctionAddrArm32 = &_original_function_addr_arm32;

    size_t ulShellCodeLength = pShellcodeEndArm32 - pShellcodeStartArm32;

    // 申请一块内存，用于构造shellcode
    void *pNewShellcode = malloc(ulShellCodeLength);
    if (pNewShellcode == NULL) {
        LOGE("shellcode malloc failed.\n");
        goto err;
    }
    memcpy(pNewShellcode, pShellcodeStartArm32, ulShellCodeLength);

    // 更改页属性，改成可读可写可执行
    if (ChangePageAttr(pNewShellcode, ulShellCodeLength, PROT_READ|PROT_WRITE|PROT_EXEC)) {
        LOGE("ChangePageAttr shellcode failed.\n");
        goto err;
    }

    // 设置跳转到回调函数
    void **ppHookStubFuncAddr = pNewShellcode + (pHookstubFunctionAddrArm32 - pShellcodeStartArm32);
    *ppHookStubFuncAddr = pstInlineHookInfo->onCallBack;

    // 填充回调函数返回后跳转的函数地址（构造返回到hook点的函数）
    pstInlineHookInfo->ppOriginalFuncAddr = pNewShellcode + (pOriginalFunctionAddrArm32 - pShellcodeStartArm32);

    // 设置shellcode地址到hookinfo中，用于构造hook点的跳转
    pstInlineHookInfo->pStubAddr = pNewShellcode;

    iRet = 0;
err:
    return iRet;
}


int BuildJumpInstArm32(void *pCurrentAddress, void *pJumpAddress)
{
    int iRet = -1;
    
    if (pCurrentAddress == NULL || pJumpAddress == NULL) {
        LOGE("params is NULL.\n");
        goto err;
    }

    // ldr pc, [pc, #-4] 对应的机器码为 0xE51FF004
    // addr 要跳转的地址
    unsigned char ucLdrOpcodes[8] = {0x04, 0xf0, 0x1f, 0xe5};
    memcpy(ucLdrOpcodes + 4, &pJumpAddress, 4);

    // 将构造好的跳转指令写入pCurrentAddress，并刷缓存
    memcpy(pCurrentAddress, ucLdrOpcodes, 8);
    cacheflush(*((char *)pCurrentAddress), 8, 0);

    iRet = 0;
err:
    return iRet;
}

int BuildJumpBackFuncArm32(STInlineHookInfo *pstInlineHookInfo)
{
    int iRet = -1;
    void *pFixOpcodes = MAP_FAILED;
    int fixLength = -1;
    
    if (pstInlineHookInfo == NULL) {
        LOGE("pstInlineHookInfo is NULL.\n");
        goto err;
    }

    pFixOpcodes = mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC,  \
            MAP_ANONYMOUS|MAP_PRIVATE, 0, 0);
    if (pFixOpcodes == MAP_FAILED) {
        LOGE("BuildJumpBackFuncArm32 mmap failed.\n");
        goto err;
    }
    
    void *pOrigionalFunction = malloc(200);
    if (pOrigionalFunction == NULL) {
        LOGE("pOrigionalFunction malloc failed.\n");
        goto err;
    }

    pstInlineHookInfo->pNewEntryForOriginalFuncAddr = pOrigionalFunction;
    if (ChangePageAttr(pOrigionalFunction, 200, PROT_READ|PROT_WRITE|PROT_EXEC)) {
        LOGE("change new entry for origin function address failed.\n");
        goto err;
    }

    fixLength = fixPCOpcodeArm(pFixOpcodes, pstInlineHookInfo);
    memcpy(pOrigionalFunction, pFixOpcodes, fixLength);

    if (BuildJumpInstArm32(pOrigionalFunction + fixLength, pstInlineHookInfo->pHookAddr + pstInlineHookInfo->backupLength)) {
        LOGE("BuildJumpInstArm32 failed.\n");
        goto err;
    }

    // 填充shellcode里stub的回调地址
    *(pstInlineHookInfo->ppOriginalFuncAddr) = pOrigionalFunction;

    iRet = 0;
err:
    return iRet;
}

int BackupOpcodeArm32(STInlineHookInfo *pstInlineHookInfo)
{
    int iRet = -1;
    uint32_t *pCurrentOpcode = pstInlineHookInfo->pHookAddr;
    int i = 0;

    if (pstInlineHookInfo == NULL) {
        LOGE("pstInlineHookInfo is NULL\n");
        goto err;
    }

    for (i = 0; i < BACKUP_FIX_INST_MAX; i++) {
        pstInlineHookInfo->backupFixLengthArray[i] = -1;
    }

    pstInlineHookInfo->backupLength = 8;
    memcpy(pstInlineHookInfo->backupOpcodes, pstInlineHookInfo->pHookAddr, pstInlineHookInfo->backupLength);

    for (i = 0; i < 2; i++) {
        LOGI("Fix length: %d\n", lengthFixArm32(*pCurrentOpcode));
        pstInlineHookInfo->backupFixLengthArray[i] = lengthFixArm32(*pCurrentOpcode);
        pCurrentOpcode++;
    }

    iRet = 0;
err:
    return iRet;
}

int InitHookArm32(STInlineHookInfo *pstInlineHookInfo)
{
    int iRet = -1;

    if (BackupOpcodeArm32(pstInlineHookInfo)) {
        LOGE("BackupOpcodeArm32 err.\n");
        goto err;
    }

    if (BuildStubArm32(pstInlineHookInfo)) {
        LOGE("BuildStubArm32 err.\n");
        goto err;
    }

    if (BuildJumpBackFuncArm32(pstInlineHookInfo)) {
        LOGE("BuildJumpBackFuncArm32 err.\n");
        goto err;
    }

    iRet = 0;
err:
    return iRet;
}

int LengthOfFixArm32(uint32_t uiOpcode)
{
    int type;
    type = GetTypeOfInstArm32(uiOpcode);
    switch(type)
    {
        case BEQ_ARM:
        case BNE_ARM:
        case BCS_ARM:
        case BCC_ARM:
        case BMI_ARM:
        case BPL_ARM:
        case BVS_ARM:
        case BVC_ARM:
        case BHI_ARM:
        case BLS_ARM:
        case BGE_ARM:
        case BLT_ARM:
        case BGT_ARM:
        case BLE_ARM:return 12;break;
        case BLX_ARM:
        case BL_ARM:return 12;break;
        case B_ARM:
        case BX_ARM:return 8;break;
        case ADD_ARM:return 24;break;
        case ADR1_ARM:
        case ADR2_ARM:
        case LDR_ARM:
        case MOV_ARM:return 12;break;
        case UNDEFINE:return 4;
    }    
}

static int GetTypeOfInstArm32(uint32_t uiInst)
{
    LOGI("GetTypeOfInstArm32 : %x", uiInst);
	if ((uiInst & 0xFE000000) == 0xFA000000) {
		return BLX_ARM;
	}
	if ((uiInst & 0xF000000) == 0xB000000) {
		return BL_ARM;
	}
	if ((uiInst & 0xFE000000) == 0x0A000000) {
		return BEQ_ARM;
	}
    if ((uiInst & 0xFE000000) == 0x1A000000) {
		return BNE_ARM;
	}
    if ((uiInst & 0xFE000000) == 0x2A000000) {
		return BCS_ARM;
	}
    if ((uiInst & 0xFE000000) == 0x3A000000) {
		return BCC_ARM;
	}
    if ((uiInst & 0xFE000000) == 0x4A000000) {
		return BMI_ARM;
	}
    if ((uiInst & 0xFE000000) == 0x5A000000) {
		return BPL_ARM;
	}
    if ((uiInst & 0xFE000000) == 0x6A000000) {
		return BVS_ARM;
	}
    if ((uiInst & 0xFE000000) == 0x7A000000) {
		return BVC_ARM;
	}
    if ((uiInst & 0xFE000000) == 0x8A000000) {
		return BHI_ARM;
	}
    if ((uiInst & 0xFE000000) == 0x9A000000) {
		return BLS_ARM;
	}
    if ((uiInst & 0xFE000000) == 0xAA000000) {
		return BGE_ARM;
	}
    if ((uiInst & 0xFE000000) == 0xBA000000) {
		return BLT_ARM;
	}
    if ((uiInst & 0xFE000000) == 0xCA000000) {
		return BGT_ARM;
	}
    if ((uiInst & 0xFE000000) == 0xDA000000) {
		return BLE_ARM;
	}
    if ((uiInst & 0xFE000000) == 0xEA000000) {
		return B_ARM;
	}
    
    /*
    if ((uiInst & 0xFF000000) == 0xFA000000) {
		return BLX_ARM;
	} *//*
    if ((uiInst & 0xF000000) == 0xA000000) {
		return B_ARM;
	}*/
    
	if ((uiInst & 0xFF000FF) == 0x120001F) {
		return BX_ARM;
	}
	if ((uiInst & 0xFEF0010) == 0x8F0000) {
		return ADD_ARM;
	}
	if ((uiInst & 0xFFF0000) == 0x28F0000) {
		return ADR1_ARM;
	}
	if ((uiInst & 0xFFF0000) == 0x24F0000) {
		return ADR2_ARM;		
	}
	if ((uiInst & 0xE5F0000) == 0x41F0000) {
		return LDR_ARM;
	}
	if ((uiInst & 0xFE00FFF) == 0x1A0000F) {
		return MOV_ARM;
	}
	return UNDEFINE;
}

int FixPCOpcodeArm32(void *pFixOpcodes , STInlineHookInfo* pstInlineHook)
{
    uint32_t pc;
    uint32_t lr;
    int backUpPos = 0;
    int fixPos = 0;
    int offset = 0;
    //int isConditionBcode = 0;
    uint32_t *currentOpcode;
    uint32_t tmpFixOpcodes[40]; //对于每条PC命令的修复指令都将暂时保存在这里。
    //uint32_t tmpBcodeFix;
    //uint32_t tmpBcodeX = 0;

    LOGI("Fixing Arm !!!!!!!");

    currentOpcode = pstInlineHook->backupOpcodes + sizeof(uint8_t)*backUpPos;
    LOGI("sizeof(uint8_t) : %D", sizeof(uint8_t));

    pc = pstInlineHook->pHookAddr + 8; //pc变量用于保存原本指令执行时的pc值
    lr = pstInlineHook->pHookAddr + pstInlineHook->backupLength;

    if(pstInlineHook == NULL)
    {
        LOGI("pstInlineHook is null");
    }

    while(1) // 在这个循环中，每次都处理一个thumb命令
    {
        LOGI("-------------START----------------");
        LOGI("currentOpcode is %x",*currentOpcode);
        
        offset = fixPCOpcodeArm32(pc, lr, *currentOpcode, tmpFixOpcodes, pstInlineHook);
        //LOGI("isConditionBcode : %d", isConditionBcode);
        LOGI("offset : %d", offset);
        memcpy(pFixOpcodes+fixPos, tmpFixOpcodes, offset);
        /*
        if (isConditionBcode==1) { // the first code is B??
            if (backUpPos == 4) { // the second has just been processed
                LOGI("Fix the first b_code.");
                LOGI("offset : %d",offset);
                tmpBcodeFix += (offset/4 +1);
                memcpy(pFixOpcodes, &tmpBcodeFix, 4);
                LOGI("Fix the first b_code 1.");

                tmpBcodeFix = 0xE51FF004;
                LOGI("Fix the first b_code 1.5");
                memcpy(pFixOpcodes+fixPos+offset, &tmpBcodeFix, 4);
                LOGI("Fix the first b_code 2.");

                tmpBcodeFix = pstInlineHook->pHookAddr + 8;
                memcpy(pFixOpcodes+fixPos+offset+4, &tmpBcodeFix, 4);
                LOGI("Fix the first b_code 3.");

                tmpBcodeFix = 0xE51FF004;
                memcpy(pFixOpcodes+fixPos+offset+8, &tmpBcodeFix, 4);
                LOGI("Fix the first b_code 4.");

                tmpBcodeFix = tmpBcodeX;
                memcpy(pFixOpcodes+fixPos+offset+12, &tmpBcodeFix, 4);
                LOGI("Fix the first b_code 5.");

                offset += 4*4;
            }
            else if (backUpPos == 0) { //save the first B code
                tmpBcodeFix = (*currentOpcode & 0xFE000000);
                tmpBcodeX = (*currentOpcode & 0xFFFFFF) << 2; // x*4
                LOGI("tmpBcodeX : %x", tmpBcodeX);
                tmpBcodeX = tmpBcodeX + 8 + pstInlineHook->pHookAddr;
            }
        }*/
        
        backUpPos += 4; //arm32的话下一次取后面4 byte偏移的指令
        pc += sizeof(uint32_t);

        fixPos += offset;
        LOGI("fixPos : %d", fixPos);
        LOGI("--------------END-----------------");

        if (backUpPos < pstInlineHook->backupLength)
        {
            currentOpcode = pstInlineHook->backupOpcodes + sizeof(uint8_t)*backUpPos;
        }
        else{
            LOGI("pstInlineHook->backupLength : %d", pstInlineHook->backupLength);
            LOGI("backUpPos : %d",backUpPos);
            LOGI("fixPos : %d", fixPos);
            LOGI("Fix finish !");
            return fixPos;
        }
    }

    LOGI("Something wrong in arm fixing...");

    return 0;
}

int _FixPCOpcodeArm32(uint32_t pc, uint32_t lr, uint32_t instruction, uint32_t *pTrampolineInstructions, STInlineHookInfo* pstInlineHook)
{
    int type;
	//int offset;
    int trampoline_pos;
    uint32_t new_entry_addr = (uint32_t)pstInlineHook->pNewEntryForOriginalFuncAddr;
    LOGI("new_entry_addr : %x",new_entry_addr);

    trampoline_pos = 0;
    LOGI("THE ARM32 OPCODE IS %x",instruction);
    type = GetTypeOfInstArm32(instruction);     //判断该arm指令的种类
    if (type == BEQ_ARM || type == BNE_ARM || type == BCS_ARM || type == BCC_ARM || 
        type == BMI_ARM || type == BPL_ARM || type == BVS_ARM || type == BVC_ARM || 
        type == BHI_ARM || type == BLS_ARM || type == BGE_ARM || type == BLT_ARM || 
        type == BGT_ARM || type == BLE_ARM) {
        LOGI("BEQ_ARM BNE_ARM BCS_ARM BCC_ARM BMI_ARM BPL_ARM BVS_ARM BVC_ARM BHI_ARM BLS_ARM BGE_ARM BLT_ARM BGT_ARM BLE_ARM");
		uint32_t x;
		int top_bit;
		uint32_t imm32;
		uint32_t value;
//        uint32_t flag=0;
        //uint32_t ins_info;

        pTrampolineInstructions[trampoline_pos++] = (uint32_t)(((instruction & 0xFE000000)+1)^0x10000000);
        pTrampolineInstructions[trampoline_pos++] = 0xE51FF004; // LDR PC, [PC, #-4]
/*        flag = (uint32_t)(instruction & 0xFFFFFF);
        if (flag == 0xffffff) {
            LOGI("BACKUP TO BACKUP !");

        }*/

        x = (instruction & 0xFFFFFF) << 2; // 4*x
        top_bit = x >> 25;
		imm32 = top_bit ? (x | (0xFFFFFFFF << 26)) : x;
        value = x + pc;
        if(isTargetAddrInBackup(value, (uint32_t)pstInlineHook->pHookAddr, pstInlineHook->backupLength)){
            LOGI("B TO B in Arm32");
            int offset_in_backup;
            int cnt = (value - (uint32_t)pstInlineHook->pHookAddr)/4;
            if(cnt==0){
                value = new_entry_addr;
            }else if(cnt==1){
                value = new_entry_addr + pstInlineHook->backupFixLengthArray[0];
            }else{
                LOGI("cnt !=1or0, something wrong !");
            }
            //value = new_entry_addr+12;
        }
        pTrampolineInstructions[trampoline_pos++] = value; // hook_addr + 12 + 4*x

        /*
        if (backUpPos == 0) { //the B_code is the first backup code
            *isConditionBcode = 1;
            //ins_info = (uint32_t)(instruction & 0xF0000000)>>28;
            LOGI("INS_INFO : %x", ins_info);

            pTrampolineInstructions[trampoline_pos++] = (uint32_t)(((instruction & 0xFE000000)+1)^0x10000000); //B??_ARM 16 -> 0X?A000002
            LOGI("B code on the first.");
            LOGI("%x",(uint32_t)(instruction & 0xFE000000));
        }
        else if (backUpPos == 4) { //THE B_code is the second backup code
            LOGI("B code on the second.");
            pTrampolineInstructions[trampoline_pos++] = (uint32_t)(instruction & 0xFE000000)+1; //B??_ARM 12 -> 0X?A000001
            LOGI("%x",(uint32_t)(instruction & 0xFE000000)+1);

            pTrampolineInstructions[trampoline_pos++] = 0xE51FF004; // LDR PC, [PC, #-4]
            value = pc-4;
            pTrampolineInstructions[trampoline_pos++] = value; // hook_addr + 8

            pTrampolineInstructions[trampoline_pos++] = 0xE51FF004; // LDR PC, [PC, #-4]
            x = (instruction & 0xFFFFFF) << 2; // 4*x
            value = x + pc;
            pTrampolineInstructions[trampoline_pos++] = value; // hook_addr + 12 + 4*x
        }*/

        return 4*trampoline_pos;
    }
	if (type == BLX_ARM || type == BL_ARM || type == B_ARM || type == BX_ARM) {
        LOGI("BLX_ARM BL_ARM B_ARM BX_ARM");
		uint32_t x;
		int top_bit;
		uint32_t imm32;
		uint32_t value;
//        uint32_t flag = 0;

		if (type == BLX_ARM || type == BL_ARM) {
            LOGI("BLX_ARM BL_ARM");
			pTrampolineInstructions[trampoline_pos++] = 0xE28FE004;	// ADD LR, PC, #4
		}
		pTrampolineInstructions[trampoline_pos++] = 0xE51FF004;  	// LDR PC, [PC, #-4]
		if (type == BLX_ARM) {
            LOGI("BLX_ARM");
			x = ((instruction & 0xFFFFFF) << 2) | ((instruction & 0x1000000) >> 23); //BLX_ARM
            LOGI("BLX_ARM : X : %d",x);
		}
		else if (type == BL_ARM || type == B_ARM) {
            LOGI("BL_ARM B_ARM");
			x = (instruction & 0xFFFFFF) << 2;                                       //BL_ARM B_ARM
/*            flag = (uint32_t)(instruction & 0xFFFFFF);
            if (flag == 0xffffff) {
                LOGI("BACKUP TO BACKUP !");
            }*/
		}
		else {
            LOGI("BX_ARM");
			x = 0;                                                                   //BX_ARM
		}
		
		top_bit = x >> 25;
		imm32 = top_bit ? (x | (0xFFFFFFFF << 26)) : x;
        LOGI("top_bit : %d",top_bit);
        LOGI("imm32 : %d",imm32);
        LOGI("PC : %d",pc);

		if (type == BLX_ARM) {
            LOGI("BLX_ARM");
			value = pc + imm32 + 1;
            LOGI("BLX_ARM : value : %d",imm32);
		}
		else {
            LOGI("BL_ARM B_ARM BX_ARM");
			value = pc + imm32;
            LOGI("value : %d", value);
            if(isTargetAddrInBackup(value, (uint32_t)pstInlineHook->pHookAddr, pstInlineHook->backupLength)){
                LOGI("Backup to backup!");
                value = new_entry_addr+4*(trampoline_pos+1);
            }
		}
		pTrampolineInstructions[trampoline_pos++] = value;
		
	}
	else if (type == ADD_ARM) {
        LOGI("ADD_ARM");
		int rd;
		int rm;
		int r;
		
		rd = (instruction & 0xF000) >> 12;
		rm = instruction & 0xF;
		
		for (r = 12; ; --r) { //找一个既不是rm,也不是rd的寄存器
			if (r != rd && r != rm) {
				break;
			}
		}
		
		pTrampolineInstructions[trampoline_pos++] = 0xE52D0004 | (r << 12);	// PUSH {Rr}
		pTrampolineInstructions[trampoline_pos++] = 0xE59F0008 | (r << 12);	// LDR Rr, [PC, #8]
		pTrampolineInstructions[trampoline_pos++] = (instruction & 0xFFF0FFFF) | (r << 16);
		pTrampolineInstructions[trampoline_pos++] = 0xE49D0004 | (r << 12);	// POP {Rr}
		pTrampolineInstructions[trampoline_pos++] = 0xE28FF000;	// ADD PC, PC MFK!这明明是ADD PC, PC, #0好么！
		pTrampolineInstructions[trampoline_pos++] = pc;
	}
	else if (type == ADR1_ARM || type == ADR2_ARM || type == LDR_ARM || type == MOV_ARM) {
        LOGI("ADR1_ARM ADR2_ARM LDR_ARM MOV_ARM");
		int r;
		uint32_t value;
		
		r = (instruction & 0xF000) >> 12;
		
		if (type == ADR1_ARM || type == ADR2_ARM || type == LDR_ARM) {
            LOGI("ADR1_ARM ADR2_ARM LDR_ARM");
			uint32_t imm32;
			
			imm32 = instruction & 0xFFF;
			if (type == ADR1_ARM) {
                LOGI("ADR1_ARM");
				value = pc + imm32;
			}
			else if (type == ADR2_ARM) {
                LOGI("ADR2_ARM");
				value = pc - imm32;
			}
			else if (type == LDR_ARM) {
                LOGI("LDR_ARM");
				int is_add;
	
				is_add = (instruction & 0x800000) >> 23;
				if (is_add) {
					value = ((uint32_t *) (pc + imm32))[0];
				}
				else {
					value = ((uint32_t *) (pc - imm32))[0];
				}
			}
		}
		else {
            LOGI("MOV_ARM");
			value = pc;
		}
			
		pTrampolineInstructions[trampoline_pos++] = 0xE51F0000 | (r << 12);	// LDR Rr, [PC]
		pTrampolineInstructions[trampoline_pos++] = 0xE28FF000;	// ADD PC, PC
		pTrampolineInstructions[trampoline_pos++] = value;
	}
	else {
        LOGI("OTHER_ARM");
		pTrampolineInstructions[trampoline_pos++] = instruction;
        return 4*trampoline_pos;
	}
	//pc += sizeof(uint32_t);
	
	//pTrampolineInstructions[trampoline_pos++] = 0xe51ff004;	// LDR PC, [PC, #-4]
	//pTrampolineInstructions[trampoline_pos++] = lr;
    return 4*trampoline_pos;
}


