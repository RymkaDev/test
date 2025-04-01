#pragma once

#include "DBSocket.h"

typedef bool (*_CmdFunc)(wstring);

class AdminCommand
{
public:
	wstring pName;
	_CmdFunc Func;
	void Set(wstring sName, _CmdFunc Function)
	{
		pName = sName;
		Func = Function;
	}
};



class AdminCachedCommand
{
	map<wstring, AdminCommand> mData;
public:
	bool Init();
	static bool GetCommandGM(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	bool Handle(wstring wsBuff);

	static bool Ep(wstring wsParams);
	static bool GetPersonaje(std::wstring wsParams);

};




extern AdminCachedCommand g_AdminCachedCommand;
