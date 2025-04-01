#pragma once
#include "MemoryObject.h"


//vt 6BBF68h
class CObject : public MemoryObject
{
public:
	/* 18 */ LPVOID _unkn18;	//  MemoryObject_data base;			6BC200h
	/* 20 */ LPVOID _unkn20;	//  CWorld *pWorld;					9D3B4B0h	for creature : 683FE8h - some kind of data filler
	/* 28 */ UINT nDBID;
	/* 2C */ UINT nObjectID;
	/* 30 */ UINT nObjectType;
	/* 34 */ UINT nTimerStateType;
};
