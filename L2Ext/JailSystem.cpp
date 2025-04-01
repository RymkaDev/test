#include "StdAfx.h"
#include "JailSystem.h"
#include "HtmlCache.h"
#include "PlayerAction.h"
#include "DB.h"
#include "Captcha.h"

CJailSystem g_Jail;

CJailSystem::CJailSystem()
{
}

CJailSystem::~CJailSystem()
{
}

void CJailSystem::Init()
{
	m_Enabled = FALSE;
	JKickX = 0;
	JKickY = 0;
	JKickZ = 0;
	JailX = 0;
	JailY = 0;
	JailZ = 0;

	LoadINI();
	if(m_Enabled)
	{
		g_Log.Add(CLog::Blue, "[%s] Feature is enabled.", __FUNCTION__);
	}
}
/*
[JailSystem]
Enabled=1
JailPos=0/0/0
JailKickOutPos=0/0/0
*/

void CJailSystem::LoadINI()
{
	const TCHAR * section = _T("JailSystem");
	m_Enabled = GetPrivateProfileInt(section, _T("Enabled"), 0, g_ConfigFile);

	TCHAR sTemp[0x8000];
	memset(sTemp, 0, sizeof(sTemp));

	if(GetPrivateProfileString(section, _T("JailKickOutPos"), 0, sTemp, 8192, g_ConfigFile))
	{
		tstring pos = sTemp;
		pos = Utils::ReplaceString(pos, _T("/"), _T(" "), true);
		tstringstream sstr;
		sstr << pos;
		sstr >> JKickX >> JKickY >> JKickZ;
	}else
	{
		JKickX = 0;
		JKickY = 0;
		JKickZ = 0;
	}

	if(GetPrivateProfileString(section, _T("JailPos"), 0, sTemp, 8192, g_ConfigFile))
	{
		tstring pos = sTemp;
		pos = Utils::ReplaceString(pos, _T("/"), _T(" "), true);
		tstringstream sstr;
		sstr << pos;
		sstr >> JailX >> JailY >> JailZ;
	}else
	{
		JailX = 0;
		JailY = 0;
		JailZ = 0;
	}
}


void CJailSystem::SendPlayerJail(User *pUser,UINT timejail)
{
	guard;
	if(pUser->ValidUser())
	{
		UINT timeminutes = timejail;
		timejail = timejail * 60;

		pUser->pED->jailtimeout = static_cast<UINT>(time(0) + timejail);
		PlayerAction::OnTeleportToLocation(pUser, JailX, JailY, JailZ, false);

		//2637	1	You have been jailed for $s1 minute(s).	0	79	9B	B0	FF			0	0	0	0	0		none
		CSystemMessage msg(2637);
		msg.AddNumber(timeminutes);
		pUser->SendSystemMessage(&msg);

		g_DB.RequestSaveJailStatus(pUser->nDBID, pUser->pED->jailtimeout);
	}
	unguard;
}

void CJailSystem::RemovePlayerJail(User *pUser,bool sendcaptcha = false)
{
	guard;
	if(pUser->ValidUser())
	{
		pUser->pED->jailtimeout = 0;
		PlayerAction::OnTeleportToLocation(pUser, JKickX, JKickY, JKickZ, false);
		//2638	1	You have been unjailed.	0	79	9B	B0	FF			0	0	0	0	0		none
		pUser->pSocket->SendSystemMessage(2638);

		if(sendcaptcha)
		{
			Sleep(3000);
			g_Captcha.DoCaptcha(pUser,true,false);
		}

		g_DB.RequestSaveJailStatus(pUser->nDBID, 0);
	}
	unguard;
}
