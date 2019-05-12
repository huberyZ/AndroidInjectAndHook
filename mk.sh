#!/bin/bash

#================================================================
#   Copyright (C) 2019 Sangfor Ltd. All rights reserved.
#   
#   @File name:make.sh
#   @Author: nathan
#   @Date: 2019年05月12日
#
#================================================================

if [ $# -lt 1 ]
then
	ndk-build
	exit
fi

if [ $1 == "clean" ]
then
	rm -rf libs obj
	exit
fi


if [ $1 == "push" ]
then
	ndk-build
	adb push libs/arm64-v8a/inject /data/local/tmp
	exit
fi

