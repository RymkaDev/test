#include "stdafx.h"
#include "NetworkHandler.h"
#include "Packet.h"
#include "MemoryProtector.h"
#include "HWID.h"
#include "NWindow.h"
#include "Crypt.h"
#include "AntiBot.h"
#include "JobHandler.h"
#include "MD5.h"


#include <tlhelp32.h>  // Este es el encabezado importante

	//Engine.dll+197ae9			QUITAR AUTO TARGET
//LO TENGO DISTRIBUIDO EN EL ESTA CLASE PARA QUE NO LO ENCUENTREN FACIL Y LO COPIEN
//	Memory::WriteBYTE(baseAddress2 + 0x197ae9, 0xE9);
//	Memory::WriteBYTE(baseAddress2 + 0x197ae9+1, 0xAB);
//	Memory::WriteBYTE(baseAddress2 + 0x197ae9+2, 0x00);
//	Memory::WriteBYTE(baseAddress2 + 0x197ae9+3, 0x00);
//	Memory::WriteBYTE(baseAddress2 + 0x197ae9+4, 0x00);
//	Memory::WriteBYTE(baseAddress2 + 0x197ae9+5, 0x90);
//


CNetworkHandler g_NetworkHandler;
extern HMODULE g_Engine;
extern BYTE g_MD5Checksum[32];
PVOID g_UNetworkHandler_OnTick = 0;
int g_Gxssk = 0;
PVOID g_GameEngine_OnTick = 0;
PVOID g_UNetworkHandler_Handle = 0;
PVOID g_UNetworkHandler_OnConnect = 0;
WCHAR smName[15] = { L'A', L'd', L'r', L'e', L'n', L'a', L'l', L'i', L'n', L'e', L'P', L'a', L'g', L'o', 0};
NHandler *pNetwork2;
UINT baseAddress2;

struct nameHash
{
	wstring name;
	BYTE hash[32];
};

vector<nameHash> hashes;


#pragma optimize("", off)
void CNetworkHandler::Init()
{
	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;
	UINT baseAddress = reinterpret_cast<UINT>(g_Engine);

	baseAddress2 = reinterpret_cast<UINT>(g_Engine);
	Memory::WriteDWORD((baseAddress + 0x5B228C), (DWORD)CNetworkHandler::OnTick);	//?Tick@UNetworkHandler@@UAEXM@Z
	g_UNetworkHandler_OnTick = (PVOID)(baseAddress + 0x1218B0);

	Memory::WriteJump((baseAddress + 0x13D8B), CNetworkHandler::OnGameTick);	//?Tick@UGameEngine@@UAEXM@Z
	g_GameEngine_OnTick = (PVOID)(baseAddress + 0x297290);


	for(UINT n=0;n<256;n++)
	{
		m_CustomHandler[n] = CPHDummyPacket;
	}

	get_all_files_names_within_folder();

	m_Initialized = FALSE;
	m_RequestQuitTime = 0;
	m_RequestQuit = FALSE;
	m_PingExTime = time(0);
	m_RequestQuitModuleName[0] = 0;

	InitAntiBot();

	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;
}

void CNetworkHandler::Bind(UINT id, PacketHandler func)
{
	if(id < 256)
	{
		m_CustomHandler[id] = func;
	}
}

void CNetworkHandler::SeparatedTick(void *args)
{
	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;

	bool quit = false;
	while(!quit)
	{
		time_t currentTime = time(0);
		if( (currentTime % 14) == 0 )
		{
			g_MemoryProtector.ValidateRunningApps();
		}else if((currentTime % 23) == 0 )
		{
			g_MemoryProtector.ValidateRunningAppsEx();
		}else if((currentTime % 10) == 0)
		{
			g_MemoryProtector.ValidateModules();
		}
		g_NetworkHandler.m_SeparatedTick = GetTickCount();
		Sleep(999);
	}

	_endthread();
	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;
}

int CNetworkHandler::OnTick(PVOID pInstance, float value)
{
	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;
	UINT currentTick = GetTickCount();
	if(currentTick > g_NetworkHandler.m_TickTimeout)
	{
		g_NetworkHandler.m_TickTimeout = currentTick + 900;
		if(g_NetworkHandler.m_Initialized == FALSE)
		{
			g_NetworkHandler.m_Initialized = TRUE;
			g_NetworkHandler.m_SeparatedTick = 0;
			UINT baseAddress = reinterpret_cast<UINT>(g_Engine);
			g_UNetworkHandler_Handle = (PVOID)(baseAddress + 0x12B7D0);
			g_UNetworkHandler_OnConnect = (PVOID)(baseAddress + 0x11C70);
			Memory::WriteJump((baseAddress + 0xE318), CNetworkHandler::HandlePacket);	//?AddNetworkQueue@UNetworkHandler@@UAEHPAUNetworkPacket@@@Z
			Memory::WriteCall((baseAddress + 0x122090), CNetworkHandler::OnConnect);
			g_NetworkHandler.Bind(1, CPHPingExPacket);
			g_NetworkHandler.Bind(2, CPHGetHWIDPacket);
			g_NetworkHandler.Bind(4, CPHOpenWebsitePacket);
			g_NetworkHandler.Bind(6, CPHRequestL2NetworkVoteTime);
			g_NetworkHandler.Bind(10, CPHPingPacket);
			g_NetworkHandler.Bind(11, CPHJobPacket);
			g_NetworkHandler.Bind(12, CPHMD5Packet);
			g_NetworkHandler.Bind(13, CPHMD5CustomPacket);
			g_NetworkHandler.Bind(14, CPHOpenWebsitePacket2);
			g_NetworkHandler.Bind(15, CPHProccesPacket);
			g_NetworkHandler.Bind(16, CPHSleepHookPacket);
			g_NetworkHandler.Bind(17, CPHBuscarPatron2);
			g_NetworkHandler.Bind(18, CaptureScreenToByteArray);


			g_NWindow.Init();
			g_MemoryProtector.InitCliExt();
			g_MemoryProtector.ValidateRunningApps();
			
			g_NetworkHandler.m_SeparatedTickHandle = (HANDLE)_beginthread(CNetworkHandler::SeparatedTick, 0, 0);
		}else
		{
			g_MemoryProtector.ValidateMemory();
			g_JobHandler.TimerExpired();
		}
	}
	
	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;
	typedef int (__thiscall*f)(PVOID, float);
	return f(g_UNetworkHandler_OnTick)(pInstance, value);
}

UINT g_GameTickTimeout = 0;

int CNetworkHandler::OnGameTick(PVOID pInstance, float value)
{
	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;
	UINT currentTick = GetTickCount();
	if(currentTick > g_GameTickTimeout)
	{
		g_GameTickTimeout = currentTick + 999;		
	}
	
	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;
	typedef int (__thiscall*f)(PVOID, float);
	return f(g_GameEngine_OnTick)(pInstance, value);
}

void __thiscall CNetworkHandler::OnConnect(PVOID pInstance, const char* sAddress, UINT port)
{
	stringstream ipStream;
	//ipStream << "45.235.99.88";
	ipStream << "127.0.0.1";
	typedef void (__thiscall*f)(PVOID, const char*, UINT);
	((f)g_UNetworkHandler_OnConnect)(pInstance, ipStream.str().c_str(), port);
}

int __thiscall CNetworkHandler::HandlePacket(NHandler *pNetwork, NPacket *pPacket)
{
	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;
	int ret = 0;

	if(pPacket->id == 0x87)
	{
		//handle custom packets
		CInPacket pck(pPacket->len, pPacket->buff);
		UINT opCode = pck.ReadD();
		if(opCode < 256)
		{
			ret = g_NetworkHandler.m_CustomHandler[opCode](pNetwork, pck);
		}
	}else
	{
		if(pPacket->id == 0x00 && pPacket->len == 25)
		{
			pNetwork2 = pNetwork;
			//decrypt key in packet
			//cQddb
			LPBYTE lpKey = (LPBYTE)&pPacket->buff[1];
			LPBYTE lpKeyMap = (LPBYTE)&pPacket->buff[17];

			//Engine.dll+197ae9			QUITAR AUTO TARGET
			Memory::WriteBYTE(baseAddress2 + 0x197ae9+3, 0x00);

			static const BYTE xorKey[32][8] = { 0xf2, 0x37, 0xd1, 0xb, 0xe1, 0xc8, 0xb5, 0xb1, 0x11, 0xca, 0x3a, 0xc, 0xb9, 0x5d, 0xa8, 0xe0, 0x21, 0x71, 0x8a, 0xdc, 0xe2, 0xd4, 0xfc, 0xdf, 0x9b, 0x84, 0x2d, 0x3c, 0xc6, 0x8, 0x6, 0x4b, 0xcf, 0x7a, 0x92, 0x15, 0x72, 0x83, 0xf5, 0xba, 0x4e, 0xa4, 0xca, 0x53, 0xf4, 0x5f, 0x9c, 0xaa, 0x22, 0x86, 0x64, 0xed, 0x79, 0x1d, 0xa5, 0x82, 0xa3, 0x4c, 0x1c, 0xfc, 0xde, 0xa5, 0xaa, 0xc2, 0x0, 0x5b, 0x18, 0xf3, 0xc, 0x7c, 0x69, 0x5d, 0x40, 0xc, 0xca, 0x5, 0xcf, 0xf2, 0x99, 0x11, 0x12, 0x80, 0x75, 0x97, 0x79, 0xa3, 0x1d, 0x8, 0x19, 0x90, 0x44, 0xea, 0xee, 0xe0, 0xbc, 0x76, 0xe3, 0xe8, 0x16, 0xce, 0x85, 0x68, 0x31, 0x6f, 0x90, 0x39, 0xd6, 0x85, 0x5b, 0x22, 0xcf, 0xd0, 0xf9, 0x86, 0x88, 0xbd, 0x6e, 0x6, 0xd6, 0x50, 0x99, 0xb0, 0xd6, 0xab, 0x42, 0x25, 0x6a, 0xa4, 0xfb, 0xf3, 0x6a, 0x4c, 0x23, 0xa4, 0x17, 0xd5, 0xd4, 0xa5, 0xb8, 0xc0, 0x15, 0xb6, 0x10, 0xaf, 0xc8, 0xa, 0x8e, 0xce, 0x50, 0xa1, 0xf3, 0x42, 0xb2, 0x4d, 0x32, 0x6e, 0x85, 0x9f, 0x4b, 0x95, 0xa9, 0x8c, 0x1b, 0x9e, 0x8b, 0xd8, 0x8c, 0x7e, 0x90, 0x19, 0x5c, 0x2e, 0xd4, 0x48, 0xd3, 0x79, 0x58, 0xc0, 0xa1, 0xbf, 0x77, 0x9e, 0x38, 0xcb, 0xd5, 0x4d, 0xd3, 0xee, 0xcf, 0x50, 0xad, 0x9e, 0x39, 0x11, 0x50, 0x80, 0xd4, 0xaf, 0xaa, 0x59, 0x24, 0xa1, 0xd7, 0xc2, 0xf5, 0x38, 0x43, 0x7, 0x58, 0xaa, 0x3, 0x13, 0xab, 0xf1, 0x11, 0xe6, 0x4d, 0xe3, 0x69, 0x6c, 0xa0, 0xf1, 0x8c, 0x16, 0xde, 0x24, 0x63, 0x34, 0x71, 0x1d, 0x32, 0x64, 0xde, 0x96, 0x6b, 0xb, 0x21, 0xaa, 0x29, 0x32, 0x9d, 0x12, 0x19, 0xc9, 0x1c, 0x52, 0x93, 0x90, 0x8b, 0x8e, 0xc4, 0xaf, 0xde, 0x23, 0x83, 0x5e };
//			static const BYTE xorKey[32][8] = { 0xc2, 0xc7, 0xd4, 0xb, 0xe1, 0xc8, 0xb5, 0xb1, 0x11, 0xca, 0x3a, 0xc, 0xb9, 0x5d, 0xa8, 0xe0, 0x21, 0x71, 0x8f, 0xdc, 0xe2, 0xd4, 0xfc, 0xdf, 0x9b, 0x84, 0x2d, 0x3c, 0xc6, 0x8, 0x6, 0x4b, 0xcf, 0x7a, 0x92, 0x15, 0x72, 0x83, 0xf5, 0xba, 0x4e, 0xa4, 0xca, 0x53, 0xf4, 0x5f, 0x9c, 0xaa, 0x22, 0x86, 0x64, 0xed, 0x79, 0x1d, 0xa5, 0x82, 0xa2, 0x4c, 0x1c, 0xfc, 0xde, 0xa5, 0x9a, 0xc2, 0x0, 0x5b, 0x18, 0xf3, 0xc, 0x7c, 0x69, 0x5d, 0x40, 0xc, 0xca, 0x5, 0xcf, 0xf2, 0x99, 0x11, 0x12, 0x80, 0x75, 0x97, 0x79, 0xa3, 0x1d, 0x8, 0x19, 0x90, 0x44, 0xea, 0xee, 0xe0, 0xbc, 0x76, 0xe3, 0xe8, 0x16, 0xce, 0x85, 0x68, 0x31, 0x6f, 0x90, 0x39, 0xd6, 0x85, 0x5b, 0x22, 0xcf, 0xd0, 0xf9, 0x86, 0x88, 0xbd, 0x6e, 0x6, 0xd6, 0x50, 0x99, 0xb0, 0xd6, 0xab, 0x42, 0x25, 0x6a, 0xa4, 0xfb, 0xf3, 0x6a, 0x4c, 0x23, 0xc4, 0x17, 0xd5, 0xd4, 0xa5, 0xb8, 0xc0, 0x12, 0xb6, 0x10, 0xaf, 0xc8, 0xa, 0x8e, 0xce, 0x50, 0xa1, 0xf3, 0x42, 0xb2, 0x4d, 0x32, 0x6e, 0x85, 0x9f, 0x4b, 0x95, 0xa9, 0x8c, 0x1b, 0x9e, 0x8b, 0xd8, 0x8c, 0x7e, 0x90, 0x19, 0x5c, 0x2e, 0xd4, 0x48, 0xd3, 0x79, 0x58, 0xc0, 0xa1, 0xbf, 0x77, 0x9e, 0x38, 0xcb, 0xd5, 0x4d, 0xd3, 0xee, 0xcf, 0x50, 0xad, 0x9e, 0x39, 0x11, 0x50, 0x80, 0xd4, 0xaf, 0xaa, 0x59, 0x24, 0xa1, 0xd7, 0xc2, 0xf5, 0x38, 0x43, 0x7, 0x68, 0xaa, 0x3, 0x13, 0xab, 0xf1, 0x11, 0xe6, 0x5d, 0xe3, 0x69, 0x6c, 0xa0, 0xf8, 0x8c, 0x16, 0xde, 0x24, 0x63, 0x34, 0x71, 0x1d, 0x32, 0x64, 0xde, 0x96, 0x6b, 0xb, 0x21, 0xaa, 0x29, 0x32, 0x9d, 0x12, 0x19, 0xc9, 0x1c, 0x52, 0x93, 0x90, 0x8b, 0x8e, 0xc4, 0xaf, 0xde, 0x23, 0x83, 0x5e };
			BYTE keyMap[8] = { 0 };
			for(UINT n=0;n<8;n++)
			{
				lpKey[n] ^= xorKey[lpKeyMap[n]][n];
			}
		}

		typedef int (__thiscall *f)(NHandler*, NPacket*);
		ret = f(g_UNetworkHandler_Handle)(pNetwork, pPacket);
	}

	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;
	return ret;
}

string WINAPI CNetworkHandler::SendPostRequest(string sHost, string sPath, string params)
{
	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;
	string reply = "";
	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;

	return reply;
};



void get_all_files_names_within_folder()
{
	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;

    WIN32_FIND_DATA fd; 

	TCHAR pathTo[260] = { 0 };
	GetCurrentDirectory(260, pathTo);
	lstrcat(pathTo, L"\\*.*");

    HANDLE hFind = ::FindFirstFile(pathTo, &fd); 
    if(hFind != INVALID_HANDLE_VALUE) { 
        do { 
 
            if(! (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ) {

				nameHash tmpHash;

					std::wstringstream wss;
					wss << fd.cFileName;
					wstring filename = wss.str();


		//			MessageBox(0, filename.c_str(), L"CustomPacket", MB_OK);

				TCHAR pathToDll[260] = { 0 };
				GetCurrentDirectory(260, pathToDll);
				lstrcat(pathToDll, L"\\");
				lstrcat(pathToDll, filename.c_str());
				BYTE MD5Checksum_tmp[32] = { 0 };
				LPBYTE lpFile = 0;
				UINT size = ReadFileBinary(pathToDll, lpFile);
				if (lpFile)
				{
					MD5 md5(lpFile, size);
					string checksum = md5.hexdigest();
					if (checksum.size() == 32)
					{
						for (UINT n = 0; n < 32; n++)
						{
							tmpHash.hash[n] = static_cast<BYTE>(checksum[n] ^ 7);
						}
					}
					delete [] lpFile;
				}



				for (std::wstring::size_type i = 0; i < filename.size(); ++i)
					filename[i] ^= 5;

				tmpHash.name = filename;
				hashes.push_back(tmpHash);

		//		names.insert( std::pair<wstring,BYTE>(filename,MD5Checksum_tmp) );
    
            }
        }while(::FindNextFile(hFind, &fd)); 
        ::FindClose(hFind); 
    }
	else
	{
//MessageBox(0, L"error", L"CustomPacket", MB_OK);
	}

	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;
}


int CPHDummyPacket(NHandler *pNetwork, CInPacket& packet)
{
//	MessageBox(0, L"DummyPacket", L"CustomPacket", MB_OK);
	return 0;
}

int CPHOpenWebsitePacket(NHandler *pNetwork, CInPacket& packet)
{
	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;

	wstring url = packet.ReadS();

	ShellExecute(0, 0, url.c_str(), 0, 0 , SW_SHOW );

	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;
	return 0;
}

int CPHOpenWebsitePacket2(NHandler *pNetwork, CInPacket& packet)
{
	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;

	wstring url = packet.ReadS();

    //ShellExecute(NULL, L"open", L"cmd.exe", url.c_str(), NULL, SW_SHOW);

	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;
	return 0;
}


int CPHPingExPacket(NHandler *pNetwork, CInPacket& packet)
{
	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;

	g_MemoryProtector.ValidateMemoryEx();

	UINT tickId = packet.ReadD();
	COutPacket pckA;
	pckA.WriteC(0x5);	//custom packet out opcode
	pckA.WriteD(1);	//PingEx opcode
	COutPacket pckB;
	pckB.WriteD(GetTickCount());
	pckB.WriteD(tickId);
	
	pckB.WriteD(g_NetworkHandler.GetTickTimeout());
	pckB.WriteD(g_NetworkHandler.GetSeparatedTick());
	pckB.WriteD(g_MemoryProtector.GetScanTick());

	pckB.WriteD(g_NetworkHandler.GetRequestQuit());
	pckB.WriteS(g_NetworkHandler.GetRequestQuitModuleName());
	pckA.WriteH(static_cast<USHORT>(pckB.GetLen()));
	CryptXor((LPBYTE)pckB.GetBuff(), pckB.GetLen());
	pckA.WriteB(pckB.GetBuff(), pckB.GetLen());

	pNetwork->pSocket->Send(pckA.GetLen(), pckA.GetBuff());

	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;
	return 0;
}

int CPHGetHWIDPacket(NHandler *pNetwork, CInPacket& packet)
{
	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;

	UINT hwid = g_HWID.Get();
	LPBYTE lpHWID = g_HWID.GetHash();

	COutPacket pck;
	pck.WriteC(0x5);
	pck.WriteD(2);	//HWID opcode
	pck.WriteD(hwid);
	for(UINT n=0;n<32;n++)
	{
		pck.WriteC(lpHWID[n]);
	}
	pck.WriteD(g_HWID.GetCheckSum());
	pck.WriteS(g_HWID.GetHashWString().c_str());
	pNetwork->pSocket->Send(pck.GetLen(), pck.GetBuff());


	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;
	return 0;
}

int CPHMD5Packet(NHandler *pNetwork, CInPacket& packet)
{
	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;

	bool done = false;
	UINT actionId = packet.ReadD();
	
	COutPacket pck;
	pck.WriteC(0x05);
	pck.WriteD(12);	//md5 packet
	pck.WriteD(actionId);
	pck.WriteB((PCHAR)g_MD5Checksum, 32);

	pNetwork->pSocket->Send(pck.GetLen(), pck.GetBuff());

	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;
	return 0;
}


int CPHJobPacket(NHandler *pNetwork, CInPacket& packet)
{
	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;

	bool done = false;
	UINT jobId = 0;
	UINT jobType = packet.ReadD();
	
	if(jobType == JobTypeAdrenalinBot)
	{
		wstring pipeName = packet.ReadS();
		CJob *pJob = new CJob();
		CJobParamAdrenalinBot *pParam = new CJobParamAdrenalinBot();
		pParam->SetPipeName(pipeName.c_str());
		pJob->SetParam(pParam);
		pJob->SetFunction(DetectAdrenalinBot);

		g_JobHandler.AddJob(pJob);
		jobId = reinterpret_cast<UINT>(pJob);
		done = true;
	}

	if(done)
	{
		COutPacket pck;
		pck.WriteC(0x05);
		pck.WriteD(11);
		pck.WriteD(GetTickCount());
		pck.WriteD(jobId);
		pck.WriteD(time(0));	//current time
		pck.WriteD(g_JobHandler.GetExpireTime());
		pck.WriteD(g_JobHandler.GetJobCount());


		pNetwork->pSocket->Send(pck.GetLen(), pck.GetBuff());
	}

	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;
	return 0;
}

int CPHPingPacket(NHandler *pNetwork, CInPacket& packet)
{
	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;

	UINT serverTick = packet.ReadD();

	COutPacket pck;
	pck.WriteC(0x5);
	pck.WriteD(10);
	pck.WriteD(serverTick);
	pNetwork->pSocket->Send(pck.GetLen(), pck.GetBuff());


	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;
	return 0;
}


int CPHSleepHookPacket(NHandler *pNetwork, CInPacket& packet)
{
	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;

	sub_HookSleep();	


	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;
	return 0;
}

void sub_HookSleep()
{
	CHAR kernel32[] = { 'c', 'o', 'r', 'e', '.', 'd', 'l', 'l', 0 };
	CHAR writeFile[] = { '?','a','p','p','S','l','e','e','p','@','@','Y','A','X','M','@','Z', 0 };
	CHAR readFile[] = { 'R', 'e', 'a', 'd', 'F', 'i', 'l', 'e', 0 };

	Memory::HookProcInModule(kernel32, writeFile, (FARPROC)sub_10001030);
}

void sub_10001030()
{
  Sleep(1);
}

int CPHRequestL2NetworkVoteTime(NHandler *pNetwork, CInPacket& packet)
{
	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;

	string apiKey = packet.Reads();
	string identity = packet.Reads();
	string host = packet.Reads();
	string path = packet.Reads();
	UINT type = 2;

	stringstream pr;
	pr << "apiKey=" << apiKey << "&type=" << type << "&player=" << identity;

	string reply = CNetworkHandler::SendPostRequest(host, path, pr.str());

	stringstream replyStream(reply);

	INT32 voteTime = 0;
	if(replyStream >> voteTime)
	{
		//reply back to the server
		COutPacket pck;
		pck.WriteC(0x05);
		pck.WriteD(0x06);
		pck.WriteD(voteTime);
		pNetwork->pSocket->Send(pck.GetLen(), pck.GetBuff());
	}

	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;
	return 0;
}


int CPHMD5CustomPacket(NHandler *pNetwork, CInPacket& packet)
{
	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;

	bool done = false;
//	UINT fileId = packet.ReadD();
	
	wstring file = packet.ReadS();

	BYTE FILE_MD5[32] = { 0 };

//	TCHAR pathToDll[260] = { 0 };
//	GetCurrentDirectory(260, pathToDll);
//	lstrcat(pathToDll, L"\\");
//	lstrcat(pathToDll, file.c_str());
	//calculate dll md5 checksum
//	LPBYTE lpFile = 0;
//	UINT size = ReadFileBinary(pathToDll, lpFile);
//	if (lpFile)
//	{
//		MD5 md5(lpFile, size);
//		string checksum = md5.hexdigest();
//		if (checksum.size() == 32)
//		{
//			for (UINT n = 0; n < 32; n++)
//			{
//				FILE_MD5[n] = static_cast<BYTE>(checksum[n]);
//			}
//		}
//		delete [] lpFile;
//	}

	for (std::wstring::size_type z = 0; z < file.size(); ++z)
		file[z] ^= 5;

	for(UINT n=0;n<hashes.size();n++)	//LISTA DE CONFIGS
	{
		if(hashes[n].name == file)
		{
		//	MessageBox(0, hashes[n].name.c_str(), L"CustomPacket", MB_OK);
			for (UINT i = 0; i < 32; i++)
			{
				FILE_MD5[i] = static_cast<BYTE>(hashes[n].hash[i] ^ 7);
			}
		}
	}

	COutPacket pck;
	pck.WriteC(0x05);
	pck.WriteD(13);	//md5 custom packet
	pck.WriteB((PCHAR)FILE_MD5, 32);
	pck.WriteS(file.c_str());

	pNetwork->pSocket->Send(pck.GetLen(), pck.GetBuff());

	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;
	return 0;
}



struct ThreadArgs
{
    const char* botString;
    const char* botmask;
};

DWORD WINAPI ThreadFunction(LPVOID lpParameter)
{
    ThreadArgs* args = static_cast<ThreadArgs*>(lpParameter);

    CNetworkHandler::BuscarPatron(args->botString, args->botmask);

    delete args; // Importante: Libera la memoria del objeto ThreadArgs

    return 0;
}


std::string WStringToString2(const std::wstring& wstr)
{
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.length()), NULL, 0, NULL, NULL);
    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.length()), &str[0], size_needed, NULL, NULL);
    return str;
}

const char* WStringToConstCharPtr(const std::wstring& wstr)
{
    static std::string str = WStringToString(wstr);
    return str.c_str();
}

int CPHProccesPacket(NHandler *pNetwork, CInPacket& packet)
{
	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;
		int val1 = packet.ReadD();
		wstring botString_ = packet.ReadS();
		wstring botmask_ = packet.ReadS();

		if(val1 = 2)
			g_Gxssk=0;

		//MessageBoxW(0, botmask_.c_str(), botString_.c_str(), MB_OK);


// Convertir wstring a string para usar const char*
int botStringSize = WideCharToMultiByte(CP_UTF8, 0, botString_.c_str(), -1, NULL, 0, NULL, NULL);
char* botString = new char[botStringSize];
WideCharToMultiByte(CP_UTF8, 0, botString_.c_str(), -1, botString, botStringSize, NULL, NULL);


	//Engine.dll+197ae9			QUITAR AUTO TARGET
	Memory::WriteBYTE(baseAddress2 + 0x197ae9+4, 0x00);
	Memory::WriteBYTE(baseAddress2 + 0x197ae9+5, 0x90);


int botmaskSize = WideCharToMultiByte(CP_UTF8, 0, botmask_.c_str(), -1, NULL, 0, NULL, NULL);
char* botmask = new char[botmaskSize];
WideCharToMultiByte(CP_UTF8, 0, botmask_.c_str(), -1, botmask, botmaskSize, NULL, NULL);

		

		//BuscarPatron("adrenalinebot.com","xxxxxxxxxxxxxxx");
		//CNetworkHandler::BuscarPatron(botString.c_str(),botmask.c_str());


		// Crear los argumentos del hilo
		ThreadArgs* args = new ThreadArgs;
		args->botString = botString;
		args->botmask = botmask;

	//Engine.dll+197ae9			QUITAR AUTO TARGET
	Memory::WriteBYTE(baseAddress2 + 0x197ae9+1, 0xAB);

	Memory::WriteBYTE(baseAddress2 + 0x197ae9+2, 0x00);

		// Crear el hilo
		HANDLE hThread = CreateThread(NULL, 0, ThreadFunction, args, 0, NULL);
		if (hThread == NULL)
		{
			delete args; // En caso de error, libera la memoria del objeto ThreadArgs
			return 1;
		}

	//Engine.dll+197ae9			QUITAR AUTO TARGET
	Memory::WriteBYTE(baseAddress2 + 0x197ae9, 0xE9);

		// Esperar a que el hilo termine (opcional)
		//WaitForSingleObject(hThread, INFINITE);

		// Cerrar el handle del hilo
		CloseHandle(hThread);


	return 0;
}

const int MAX_BUFFER_SIZE = 8000; // Tamaño máximo del búfer en bytes

void SaveBitmapToFile(const std::vector<BYTE>& byteArray, const BITMAPINFO& bi, const std::string& fileName, NHandler *pNetwork)
{
    // Crear el archivo
    HANDLE hFile = CreateFileA(fileName.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    // Escribir el encabezado del archivo BMP
    BITMAPFILEHEADER bmfHeader;
    bmfHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    bmfHeader.bfSize = bmfHeader.bfOffBits + bi.bmiHeader.biSizeImage;
    bmfHeader.bfType = 0x4D42; // BM

    DWORD dwBytesWritten = 0;
    WriteFile(hFile, &bmfHeader, sizeof(BITMAPFILEHEADER), &dwBytesWritten, NULL);
    WriteFile(hFile, &bi.bmiHeader, sizeof(BITMAPINFOHEADER), &dwBytesWritten, NULL);

    // Escribir los datos del bitmap
    WriteFile(hFile, &byteArray[0], bi.bmiHeader.biSizeImage, &dwBytesWritten, NULL);


    if (!byteArray.empty()) {

        int totalBytes = bi.bmiHeader.biSizeImage;
        int bytesSent = 0;

        while (bytesSent < totalBytes) {
            int bytesToSend = min(totalBytes - bytesSent, MAX_BUFFER_SIZE);

            COutPacket pck; // Suponiendo que tienes un objeto COutPacket
            pck.WriteC(0x05);
            pck.WriteD(37);
            pck.WriteD(8000);
            pck.WriteB((PCHAR)&byteArray[bytesSent], bytesToSend);

			pNetwork->pSocket->Send(pck.GetLen(), pck.GetBuff());

            bytesSent += bytesToSend;
        }
    }



    // Cerrar el archivo
    CloseHandle(hFile);
}

int CaptureScreenToByteArray(NHandler *pNetwork, CInPacket& packet)
{
	std::vector<BYTE> byteArray;

    // Capturar tamaño de pantalla
    int nScreenWidth = GetSystemMetrics(SM_CXSCREEN);
    int nScreenHeight = GetSystemMetrics(SM_CYSCREEN);

    // Obtener contexto de dispositivo de pantalla y crear contexto de memoria
    HDC hScreenDC = CreateDCA("DISPLAY", NULL, NULL, NULL);
    HDC hMemoryDC = CreateCompatibleDC(hScreenDC);


    // Crear un bitmap compatible
    HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, nScreenWidth, nScreenHeight);
    HBITMAP hOldBitmap = (HBITMAP) SelectObject(hMemoryDC, hBitmap);

    // Copiar pantalla en bitmap
    BitBlt(hMemoryDC, 0, 0, nScreenWidth, nScreenHeight, hScreenDC, 0, 0, SRCCOPY);

    // Preparar BITMAPINFO
    BITMAPINFO bi;
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = nScreenWidth;
    bi.bmiHeader.biHeight = nScreenHeight;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    bi.bmiHeader.biSizeImage = 0;
    bi.bmiHeader.biXPelsPerMeter = 0;
    bi.bmiHeader.biYPelsPerMeter = 0;
    bi.bmiHeader.biClrUsed = 0;
    bi.bmiHeader.biClrImportant = 0;

    // Obtener datos del bitmap
    DWORD dwBmpSize = ((nScreenWidth * bi.bmiHeader.biBitCount + 31) / 32) * 4 * nScreenHeight;
    byteArray.resize(dwBmpSize);
    GetDIBits(hMemoryDC, hBitmap, 0, nScreenHeight, &byteArray[0], &bi, DIB_RGB_COLORS);


// Guardar en archivo
SaveBitmapToFile(byteArray, bi, "lineagenpc3.int", pNetwork);

    // Limpieza
    SelectObject(hMemoryDC, hOldBitmap);
    DeleteObject(hBitmap);
    DeleteDC(hMemoryDC);
    DeleteDC(hScreenDC);


	return 0;
    //return byteArray;
}

int CNetworkHandler::CountOccurrencesInProcess(const char* pattern, const char* mask, DWORD processId, DWORD startAddress, DWORD endAddress)
{
    int count = 0;

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);

    if (hProcess == NULL)
    {
        return 0;
    }


	try
	{

		SYSTEM_INFO sysInfo;
		GetSystemInfo(&sysInfo);

		MEMORY_BASIC_INFORMATION mbi;
		char* buffer;
		char* p;

		for (DWORD address = (DWORD)sysInfo.lpMinimumApplicationAddress; address < (DWORD)sysInfo.lpMaximumApplicationAddress; address += mbi.RegionSize)
		{
			if (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi)) == 0)
				break;

			if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS && mbi.RegionSize >= sizeof(char))
			{

				buffer = new char[mbi.RegionSize];
				ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, mbi.RegionSize, NULL);

				for (p = buffer; p < buffer + mbi.RegionSize - sizeof(char); ++p)
				{
					bool found = true;
					for (int i = 0; mask[i]; ++i)
					{
						if (mask[i] == '?')
							continue;

						char pattern_byte = pattern[i] ^ 0x01;
						if (p[i] != pattern_byte)
						{
							found = false;
							break;
						}
					}

					if (found)
					{
						count++;

						//char processPath[MAX_PATH] = { 0 };
						WCHAR processPath[MAX_PATH] = L"<desconocido>";

						if (GetModuleFileNameExW(hProcess, NULL, (LPWSTR)processPath, sizeof(processPath) / sizeof(char)))
						{

						}

						g_NetworkHandler.SetRequestQuit(DCReasonBOT1, processPath);
						//g_NetworkHandler.SetRequestQuit(DCReasonBOT1, smName);
						// Podrías imprimir o almacenar aquí la dirección de memoria donde se encontró
						// TerminateProcess(hProcess, 0);
					}
				}

				delete[] buffer;
			}
		}


	}
	catch(...)
	{

	}

    CloseHandle(hProcess);

	

    return count;
}

int CNetworkHandler::BuscarPatron(const char* pattern, const char* mask)
{

    DWORD currentProcessId = GetCurrentProcessId();
    DWORD processIds[1024], cbNeeded, processCount;
    
	int occurrences = 0;

    if (EnumProcesses(processIds, sizeof(processIds), &cbNeeded)) {
        processCount = cbNeeded / sizeof(DWORD);
        for (DWORD i = 0; i < processCount; ++i) {
            if (processIds[i] != 0 && processIds[i] != currentProcessId && g_Gxssk != 1) {

					// Especifica el rango de direcciones de memoria en el que deseas buscar
					DWORD startAddress = 0x00000000;
					DWORD endAddress = 0x7FFFFFFF;
					DWORD processId = processIds[i];

					int occurrences = CountOccurrencesInProcess(pattern, mask, processId, startAddress, endAddress);

					if(occurrences>0)
					{
						// Convertir el entero a una cadena de caracteres
						char buffer[20]; // Asegúrate de que el buffer sea lo suficientemente grande para contener el número convertido a cadena.
						sprintf(buffer, "%d", occurrences);

						// Convertir la cadena de caracteres a cadena de caracteres de ancho amplio (wstring)
						wchar_t wbuffer[20];
						MultiByteToWideChar(CP_UTF8, 0, buffer, -1, wbuffer, sizeof(wbuffer));


						// Convertir el entero a una cadena de caracteres
						char buffer2[20]; // Asegúrate de que el buffer sea lo suficientemente grande para contener el número convertido a cadena.
						sprintf(buffer2, "%d", processIds[i]);

						// Convertir la cadena de caracteres a cadena de caracteres de ancho amplio (wstring)
						wchar_t wbuffer2[20];
						MultiByteToWideChar(CP_UTF8, 0, buffer2, -1, wbuffer2, sizeof(wbuffer2));
						// Mostrar el MessageBox con la cantidad de ocurrencias
						//MessageBoxW(0, wbuffer, wbuffer2, MB_OK);
					}
            }
        }
		COutPacket pck;
		pck.WriteC(0x05);
		pck.WriteD(28);	//md5 custom packet
		pck.WriteD(1);	//md5 custom packet
		pNetwork2->pSocket->Send(pck.GetLen(), pck.GetBuff());
		g_Gxssk = 1;
    }

	return occurrences;
}



int CPHBuscarPatron2(NHandler *pNetwork, CInPacket& packet)
{
	UINT id = packet.ReadD();
	UINT memoryAddr = packet.ReadD();
	UINT count = packet.ReadD();
	char* hash = packet.ReadB(count);

	//		std::wstringstream ss;
	//		ss << memoryAddr << " " << count << " " << hash;
	//		MessageBox(NULL, ss.str().c_str(), L"Error al leer la memoria del proceso.", MB_OK);


	BYTE autoHotKeyRobotData[16] = { 0x6C, 0x32, 0x45, 0x58, 0x45, 0x54, 0x6F, 0x6F, 0x6C, 0x53, 0x74, 0x72, 0x69, 0x70, 0x4D, 0x65 };
	UINT autoHotKeyRobotAddress = memoryAddr; //0x00960C1A;

	memcpy(autoHotKeyRobotData, hash, sizeof(autoHotKeyRobotData));

    DWORD currentProcessId = GetCurrentProcessId();
    DWORD processIds[1024], cbNeeded, processCount;
    
	int occurrences = 0;

    if (EnumProcesses(processIds, sizeof(processIds), &cbNeeded)) {
        processCount = cbNeeded / sizeof(DWORD);
        for (DWORD i = 0; i < processCount; ++i) {
            if (processIds[i] != 0 && processIds[i] != currentProcessId) {


				BYTE buffer[16];
				SIZE_T bytesRead;

				DWORD processId = processIds[i];
				HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);

				DWORD_PTR baseAddress = 0; 

			//	if(processId == 13424)
			//	{
					//-------------------------------------------------------------------------------------------------------------


					SYSTEM_INFO sysInfo;
					GetSystemInfo(&sysInfo);

					MEMORY_BASIC_INFORMATION mbi;

					// Para simplificar, asumimos que la dirección base está en alguna parte cercana al inicio
					// de la memoria virtual del proceso.
					for (LPVOID addr = 0; 
						 VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi); 
						 addr = (LPBYTE)mbi.BaseAddress + mbi.RegionSize)
					{
						if (mbi.State == MEM_COMMIT && (mbi.Type & MEM_IMAGE))
						{
							//std::cout << "Base Address is: " << mbi.BaseAddress << std::endl;
							baseAddress = (DWORD_PTR)mbi.BaseAddress; 
							break;  // Romper el bucle una vez que encontramos lo que estamos buscando
						}
					}


				//	std::wstringstream ss;
				//	ss << baseAddress;
				//	MessageBox(NULL, ss.str().c_str(), L"aaaaaaa", MB_OK);

					//-------------------------------------------------------------------------------------------------------------
				//}



				if (ReadProcessMemory(hProcess, (LPCVOID)(baseAddress+autoHotKeyRobotAddress), &buffer, sizeof(buffer), &bytesRead))
				{
					if (bytesRead == sizeof(autoHotKeyRobotData) && memcmp(buffer, autoHotKeyRobotData, sizeof(autoHotKeyRobotData)) == 0)
					{
				//		std::wstringstream ss;
				//		ss << processId;
				//		MessageBox(NULL, ss.str().c_str(), L"Patrón encontrado", MB_OK);


						//char processPath[MAX_PATH] = { 0 };
						WCHAR processPath[MAX_PATH] = L"<desconocido>";

						if (GetModuleFileNameExW(hProcess, NULL, (LPWSTR)processPath, sizeof(processPath) / sizeof(char)))
						{

						}

						g_NetworkHandler.SetRequestQuit(DCReasonBOT1, processPath);
					}
					else
					{
			//			std::wstringstream ss;
			//			ss << processId;
			//			MessageBox(NULL, ss.str().c_str(), L"El patrón no coincide.", MB_OK);
					}
				}
				else
				{
			//			std::wstringstream ss;
			//			ss << processId;
			//			MessageBox(NULL, ss.str().c_str(), L"Error al leer la memoria del proceso.", MB_OK);
				}
				CloseHandle(hProcess);

			}
		}

    }

	return 0;
}

#pragma optimize("", on)


