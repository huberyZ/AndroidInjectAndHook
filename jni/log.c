/*================================================================
*   Copyright (C) 2019 Sangfor Ltd. All rights reserved.
*   
*   @File name：log.c
*   @Author: nathan
*   @Date: 2019年05月12日
================================================================*/

#include "log.h"

#if LOG_LEVEL_DEBUG
LogLevel logLevel = Debug;
#elif LOG_LEVEL_INFO
LogLevel logLevel = Info;
#elif LOG_LEVEL_ERROR
LogLevel logLevel = Error;
#else
LogLevel logLevel = Error;
#endif

//void androidPrintLog
#define LOGCAT(fmt, args...)	__android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)

#if ANDROID_LOGCAT
#define LOG_TAG "ANDROID_INJECT"
void logcat(LogLevel level, char *buf) 
{
	switch (level) {
		case Debug:
			__android_log_write(ANDROID_LOG_DEBUG, LOG_TAG, buf);
			break;
		
		case Info:
			__android_log_write(ANDROID_LOG_INFO, LOG_TAG, buf);
			break;
			
		case Error:
			__android_log_write(ANDROID_LOG_ERROR, LOG_TAG, buf);
			break;
		default:
			break;
	}
}
#endif
void printLog(LogLevel level, const char *fileName, int line, const char *func, \
        const char *format, ...)
{
    char buf[4096] = {0};
    char logLevelName[64] = {0};

    switch (level) {
        case Debug:
            strncpy(logLevelName, "DEBUG", sizeof(logLevelName));
            break;

        case Info:
            strncpy(logLevelName, "INFO", sizeof(logLevelName));
            break;

        case Error:
            strncpy(logLevelName, "ERROR", sizeof(logLevelName));
            break;

        default:
            break;
    }

    if (level >= logLevel) {
        va_list args;
        va_start(args, format);

        sprintf(buf, "%lu:%s:%s:%d:%s():(%d):\t", time(NULL), logLevelName, fileName, line, func, gettid());

#if ANDROID_LOGCAT
		vsprintf(buf + strlen(buf), format, args);
		logcat(level, buf);
        
#else
        printf("%s", buf);
        fflush(stdout);
        vprintf(format, args);
#endif
    }
}
