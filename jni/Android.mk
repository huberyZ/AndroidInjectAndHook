LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := inject
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog
APP_CFLAGS := -DLOG_LEVEL_DEBUG

LOCAL_C_INCLUDES += $(LOCAL_PATH)/.
LOCAL_C_INCLUDES += $(LOCAL_PATH)/Inject
#LOCAL_C_INCLUDES += $(LOCAL_PATH)/InlineHook
LOCAL_C_INCLUDES += $(LOCAL_PATH)/Utils

SRC_FILES += $(subst $(LOCAL_PATH)/,,$(wildcard $(LOCAL_PATH)/*.c))
SRC_FILES += $(subst $(LOCAL_PATH)/,,$(wildcard $(LOCAL_PATH)/Inject/*.c))
SRC_FILES += $(subst $(LOCAL_PATH)/,,$(wildcard $(LOCAL_PATH)/InlineHook/*.c))
SRC_FILES += $(subst $(LOCAL_PATH)/,,$(wildcard $(LOCAL_PATH)/InlineHook/*.s))
SRC_FILES += $(subst $(LOCAL_PATH)/,,$(wildcard $(LOCAL_PATH)/Utils/*.c))

LOCAL_SRC_FILES += $(SRC_FILES)
include $(BUILD_EXECUTABLE)

