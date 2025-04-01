#pragma once
#include "DBSocket.h"

class CPostLoad
{

public:
	static void Initialize();
	static void InitKey(LPVOID pInstance, CLog::LogType Type, wchar_t* Msg);
	static void FirstLoad(LPVOID fnAddr);
	static void SecondLoad(LPVOID fnAddr);
	static void ThirdLoad(LPVOID pInstance);
	static CDBSocket *OnAuthConstruct(CDBSocket *pSocket, SOCKET s, void *packettable);
	static bool IsHardwareIdHack();

};