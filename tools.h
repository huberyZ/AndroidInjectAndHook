/*================================================================
*   Copyright (C) 2019 Sangfor Ltd. All rights reserved.
*   
*   @File name：tools.h
*   @Author: nathan
*   @Date: 2019年05月09日
================================================================*/

#ifndef __INJECT_TOOLS__
#define __INJECT_TOOLS__

#include <stdio.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>

#if ANDROID_LOG
#define LOG_TAG "ANDROID_INJECT"
#define LOGD(fmt, args...)	__android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)
#else
#define LOGD printf
#endif



int getPidFromName(char *targetName);

#endif
