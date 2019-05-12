LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
    LOCAL_MODULE := inject
    LOCAL_SRC_FILES := inject.c	tools.c log.c
    LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog
    APP_CFLAGS := -DLOG_LEVEL_DEBUG
include $(BUILD_EXECUTABLE)

