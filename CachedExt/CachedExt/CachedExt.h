#pragma once
#define _WINSOCKAPI_
#include <windows.h>
#include <winsock2.h>

#include "Utils.h"
#include "CPacket.h"
#include "MemoryTools.h"
#include "Logger.h"
#include "Config.h"
#include "CLog.h"
#include "DBConn.h"
#include "MemoryObject.h"
#include "SPointer.h"
#include "PacketHandler.h"
#include "BuffSlot.h"

#include "CSocket.h"
#include "CIOBuffer.h"
#include "CIOBufferExt.h"
#include "CQuerySocket.h"
#include "CUser.h"
#include "CPledge.h"
#include "CItem.h"
#include "Quests.h"
#include "ClassExtender.h"
#include "CUserDB.h"
#include "CWareHouse.h"

#pragma warning(disable:4018)
#pragma warning(disable:4244)
#pragma warning(disable:4996)
#pragma warning(disable:4244)

class CachedExt
{
public:
	static void SetHook(BYTE opCode, DWORD dwBaseAddr, DWORD fnAddr, int nNops);
	static void Initialize();
	static void HookAbnormalStatus();
	static void WriteMemoryBYTES(DWORD Address, VOID *bytes, int len);
	static void WriteMemoryQWORD(DWORD Address, INT64 value);
	static void WriteMemoryDWORD(DWORD Address, DWORD value);
	static void WriteMemoryWORD(DWORD Address, WORD value);
	static void WriteMemoryBYTE(DWORD Address, BYTE value);
};