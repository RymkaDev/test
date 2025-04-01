#pragma once
#define _WINSOCKAPI_
#include <windows.h>

class CIOBufferExt
{
public:
	static void Init();
	static LPVOID Malloc(UINT32 size);
};