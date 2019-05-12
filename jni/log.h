/*================================================================
*   Copyright (C) 2019 Sangfor Ltd. All rights reserved.
*   
*   @File name：log.h
*   @Author: nathan
*   @Date: 2019年05月12日
================================================================*/

#ifndef __INJECT_LOG_H__
#define __INJECT_LOG_H__

#include <android/log.h>
#include <time.h>
#include <stdio.h>
#include <string.h>

typedef enum {
    Debug = 0,
    Info,
    Error,
} LogLevel;

void printLog(LogLevel level, const char *fileName, int line, const char *func, const char *format, ...);

#define LOGD(format, args...) do {\
    printLog(Debug, __FILE__, __LINE__, __FUNCTION__, format, ##args); \
} while(0)

#define LOGI(format, args...) do {\
    printLog(Info, __FILE__, __LINE__, __FUNCTION__, format, ##args); \
} while (0)

#define LOGE(format, args...) do {\
    printLog(Error, __FILE__, __LINE__, __FUNCTION__, format, ##args); \
} while (0)

//#if ANDROID_LOG
//#define LOG_TAG "ANDROID_INJECT"
//#define LOGD(fmt, args...)	__android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)
//#else
//#define LOGD printf
//#endif



#endif
