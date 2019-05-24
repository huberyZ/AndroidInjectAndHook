/*================================================================
*   Copyright (C) 2019 Sangfor Ltd. All rights reserved.
*   
*   @File name：Vector.c
*   @Author: nathan
*   @Date: 2019年05月24日
================================================================*/

#include "Vector.h"

Vector NewVector(size_t lNodeEntryLength, int iMaxSize)
{
	Vector psVector = NULL;

	psVector = (Vector)malloc(sizeof(struct sVector));
	if (psVector == NULL) {
		LOGE("malloc()");
		return NULL;
	}

	psVector->node = NULL;
	psVector->size = 0;
	psVector->iMaxSize = iMaxSize;
	psVector->lNodeEntryLength = lNodeEntryLength;
	psVector->node = (char *)malloc(lNodeEntryLength * iMaxSize);
	if (psVector->node == NULL) {
		LOGE("node malloc()");
		goto err;
	}
	
	return psVector;

err:
	if (psVector->node != NULL) {
		free(psVector->node);
	}

	if (psVector != NULL) {
		free(psVector);
	}

	return NULL;
}

int PushVector(Vector v, void *pNode)
{
	if (v->size + 1 > v->iMaxSize) {
		v->node = (char *)realloc(v->node, v->lNodeEntryLength * v->iMaxSize * 2);
		if (v->node == NULL) {
			LOGE("realloc()");
			return -1;
		}
		v->iMaxSize = v->iMaxSize * 2;
	}

	memcpy((char *)v->node + v->size * v->lNodeEntryLength, (char *)pNode, v->lNodeEntryLength);
	v->size ++;
	
	return 0;
}

void *PopVector(Vector v)
{
	void *pNode = NULL;

	return pNode;
}

void *GetVector(Vector v, int index)
{
	void *pNode = NULL;

	if (v == NULL) {
		LOGE("vector is NULL.\n");
		goto err;
	}

	if (index > v->size && index < 0) {
		LOGE("Index OutOfBounds.\n");
		goto err;
	}

	pNode = (void *)(v->node + v->lNodeEntryLength * index);

err:
	return pNode;
}

int VectorSize(Vector v)
{
	if (v == NULL) {
		LOGE("vector is NULL. \n");
		return -1;
	}
	return v->size;
}

void FreeVector(Vector v)
{
	if (v->node != NULL) {
		free(v->node);
	}

	if (v != NULL) {
		free(v);
	}
}

