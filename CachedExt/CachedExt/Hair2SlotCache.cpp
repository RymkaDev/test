#include "CachedExt.h"
#include "Hair2SlotCache.h"

void Hair2Slot::Initialize() {
	//CachedExt::SetHook(0xE8, 0x4A5DFB, (DWORD)Hair2Slot::HookAssembleSSQInfo, 0);
	CachedExt::SetHook(0xE8, 0x47416A, (DWORD)Hair2Slot::HookSocketSend, 0);
}

int Hair2Slot::HookAssembleSSQInfo(char* buf, int bufLen, const char* format, int a0, int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8, int a9, int a10, int a11) {
	//g_Log.Add(CLog::Blue, "Hair2Slot::HookAssembleSSQInfo");
	return Assemble(buf, bufLen, "dddddddddddddd", a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, 64, 128);
}

void Hair2Slot::HookSocketSend(CSocket* pSocket, const char *format, int opcode, int nSocketIndex, int nBlobSize, char *nBlob) {
//	g_Log.Add(CLog::Blue, "Hair2Slot::HookSocketSend [%d]", opcode);

	WCHAR name[34];
	int nCharID;
	Disassemble((const unsigned char*)nBlob, "Sd", sizeof(name), name, &nCharID);

	int hair2 = 0;
	int hairall = 0;
	DBConn *pDBConn = new DBConn();
	pDBConn->Bind(&hair2);
	pDBConn->Bind(&hairall);
	if(pDBConn->Execute(L"SELECT ST_hair_deco, ST_hair_all FROM user_data where char_id = %d", nCharID))
		pDBConn->Fetch();
	delete pDBConn;
//	g_Log.Add(CLog::Blue, "hair2(%d) hairall(%d)", hair2, hairall);
	pSocket->Send("cdddb", opcode, hair2, hairall, nSocketIndex, nBlobSize, nBlob);
}