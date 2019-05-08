#================================================================
#   Copyright (C) 2019 Sangfor Ltd. All rights reserved.
#   
#   @File name:Makefile
#   @Author: nathan
#   @Date: 2019年04月15日
#
#================================================================
all: inject

inject:
	ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Inject.mk APP_PLATFORM=android-21 APP_ABI="arm64-v8a"


push: all
	adb push libs/arm64-v8a/inject /data/local/tmp/

clean:
	rm -rf libs
	rm -rf obj
