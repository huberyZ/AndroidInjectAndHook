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

#include "log.h"

int getPidFromName(char *targetName);


#endif
