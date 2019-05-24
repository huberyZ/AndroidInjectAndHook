/*================================================================
*   Copyright (C) 2019 Sangfor Ltd. All rights reserved.
*   
*   @File name：Vector.h
*   @Author: nathan
*   @Date: 2019年05月23日
================================================================*/

#ifndef __VECTOR_H__
#define __VECTOR_H__

#include "Log.h"

typedef struct sVector {
	int size;
	int iMaxSize;
	size_t lNodeEntryLength;
	char *node;
} *Vector;

Vector NewVector(size_t lNodeEntryLength, int iMaxSize);
int PushVector(Vector v, void *pNode);
void *PopVector(Vector v);
void *GetVector(Vector v, int index);
int VectorSize(Vector v);
void FreeVector(Vector v);

#endif
