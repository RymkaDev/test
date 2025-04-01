#include "StdAfx.h"
#include "Antibot.h"

CAntibot g_Antibot;

/*
[Antibot]
Enabled=1
;Time Allowed between Skills - in millseconds [BETA]
TimeBetweenSkills=2000

*/
void CAntibot::Init()
{
	const TCHAR* section = _T("Antibot");
	//reading data
	m_Enabled = GetPrivateProfileInt(section, _T("Enabled"), 0, g_ConfigFile);
	n_TimeBetweenSkills = GetPrivateProfileInt(section, _T("TimeBetweenSkills"), 0, g_ConfigFile);
	if(m_Enabled)
	{
		g_Log.Add(CLog::Error, "[%s] Feature is enabled! Time Allowed between skills[%d].", __FUNCTION__, n_TimeBetweenSkills);
	}
}

void CAntibot::OnEnterWorld(User *pUser, HWID hwid)
{
	if(pUser->ValidUser())
	{
		if(m_Enabled)
		{
			if ( computers.find(hwid) == computers.end() ) 
			{
				Lock();
				computers.insert(pair<HWID, DWORD>(hwid, 0));
				Unlock();
			}
		}
	}
}

void CAntibot::OnMagicSkillUse(User *pUser, HWID hwid)
{
	guard;
	if(pUser->ValidUser())
	{
		if(m_Enabled)
		{
			map<HWID, DWORD>::iterator i = computers.find(hwid);

			if (i == computers.end()) 
			{ 
				/* Not found */ 
			}
			else 
			{ 
				/* Found, i->first is f, i->second is ++-- */ 
				if( i->second >= GetTickCount())
				{
					//do the update here
					Lock();
					computers.erase(i);

					DWORD SafeTime = GetTickCount() + n_TimeBetweenSkills;

					computers.insert(pair<HWID, DWORD>(hwid, SafeTime));
					Unlock();
				}
				else
				{
					//kick user
					Lock();
					computers.erase(i);
					Unlock();

					pUser->Kick();

					g_Log.Add(CLog::Error, "[%s] User[%S] Kicked because he used bot program!", __FUNCTION__, pUser->pSD->wszName);
				}
			}

		}
	}
	unguard;
}