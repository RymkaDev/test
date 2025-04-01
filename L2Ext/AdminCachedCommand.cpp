#include "StdAfx.h"
#include "AdminCachedCommand.h"
#include "DB.h"
#include "ObjectDB.h"
#include "PlayerAction.h"
#include "PvPEvents.h"


AdminCommand* pHandler;

AdminCachedCommand g_AdminCachedCommand;

bool AdminCachedCommand::Init()
{
	AdminCommand Info;
	Info.Set(L"ep", Ep);	mData.insert(pair<wstring, AdminCommand>(L"ep", Info));
	return true;
}


bool AdminCachedCommand::GetCommandGM(CDBSocket *pSocket, const unsigned char* packet, UINT packetId)
{
	guard;

	WCHAR wCommand[255];
	memset(wCommand, 0, sizeof(wCommand));
	Disassemble(packet, "S", sizeof(wCommand), wCommand);
	
	g_AdminCachedCommand.Handle(wCommand);

	unguard;
	return false;
}


bool AdminCachedCommand::Handle(wstring wsBuff)
{
	guard;

		try
		{
			wstringstream sstr;
			wstring sCommand;
			sstr << wsBuff;
			sstr >> sCommand;

			map<wstring, AdminCommand>::iterator Iter = mData.find(sCommand);
			if(Iter!=mData.end())
			{
				wstring sParams;
				getline(sstr, sParams);
				return Iter->second.Func(sParams);
			}


		}catch(...)
		{
			g_Log.Add(CLog::Error, "[%s] Exception Detected - [%S]!", __FUNCTION__, wsBuff.c_str());
			return false;
		}

	unguard;
	return false;
}


bool AdminCachedCommand::Ep(std::wstring wsParams)
{
	guard;
		try
		{
			g_PvPEvents.CommandCacheD(wsParams);

	//		wstring nCharName;
	//		int nLocX, nLocY, nLocZ;
	//		wstringstream sstr;
	//		sstr << wsParams;
	//		sstr >> nCharName >> nLocX >> nLocY >> nLocZ;

	//		if(User *pUser = g_UserDB.GetUserByName(nCharName))
	//		{
	//			PlayerAction::OnTeleportToLocation(pUser, (int)nLocX, (int)nLocY, (int)nLocZ, false);
	//		}
	//		else
	//			g_Log.Add(CLog::Error, "[%s] Exception Detected - [%S] No esta online!", __FUNCTION__, nCharName.c_str());

		}catch(...)
		{
			g_Log.Add(CLog::Error, "[%s] Exception Detected - [%S]!", __FUNCTION__, wsParams.c_str());
			return false;
		}

	unguard;
	return true;
}


bool AdminCachedCommand::GetPersonaje(std::wstring wsParams)
{
	guard;
		try
		{
			wstring nCharName;
			wstringstream sstr;
			sstr << wsParams;
			sstr >> nCharName;

			if(User *pUser = g_UserDB.GetUserByName(nCharName))
			{

			}
			else
				g_Log.Add(CLog::Error, "[%s] Exception Detected - [%S] No esta online!", __FUNCTION__, nCharName.c_str());

		}catch(...)
		{
			g_Log.Add(CLog::Error, "[%s] Exception Detected - [%S]!", __FUNCTION__, wsParams.c_str());
			return false;
		}

	unguard;
	return true;
}



