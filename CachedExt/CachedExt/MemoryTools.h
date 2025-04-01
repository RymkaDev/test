#pragma warning( disable : 4312 ) 
#pragma warning( disable : 4996 ) 
#pragma warning( disable : 4309 )
#pragma warning( disable : 4311 )

#define _WINSOCKAPI_
#include "windows.h"
#include <stdio.h>
#include <string>
#include <sstream>

using namespace std;

#define ASM_CALL 0xE8
#define ASM_JUMP 0xE9

void WriteInstruction(INT32 Address, INT32 NewAddress, INT32 NopZone, INT8 Instruction);
void NOPMemory(INT32 Address, INT32 len);
void NULLMemory(INT32 Address, INT32 len);

void WriteMemoryBYTES(INT32 Address, VOID *bytes, INT32 len);
void WriteMemoryQWORD(INT32 Address, INT64 value);
void WriteMemoryFWORD(INT32 Address, INT64 value);
void WriteMemoryDWORD(INT32 Address, INT32 value);
void WriteMemoryWORD(INT32 Address, INT16 value);
void WriteMemoryBYTE(INT32 Address, INT8 value);

void ReadMemoryBYTES(INT32 Address, VOID *bytes, INT32 len);
void ReadMemoryQWORD(INT32 Address, INT64 *Value);
void ReadMemoryDWORD(INT32 Address, INT32 *Value);
void ReadMemoryWORD(INT32 Address, INT16 *Value);
void ReadMemoryBYTE(INT32 Address, INT8 *Value);

void EnlargeMemoryDWORD(INT32 Address, INT32 value);
void EnlargeMemoryWORD(INT32 Address, INT16 value);

// Array Tools
UINT64 WriteRelativeAddress(INT64 nOrgAddress, INT64 nWriteFrom, VOID *pArray, INT64 nOffsetIndex);

//inline void bitsetn(INT32 & i, unsigned bitposition) { i|= 1<<(bitposition); }
//inline INT32 readbitn(INT32 i, unsigned bitposition) { return (i>>(bitposition))&1; }