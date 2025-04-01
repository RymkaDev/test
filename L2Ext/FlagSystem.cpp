#include "stdafx.h"
#include "FlagSystem.h"
#include "ObjectDB.h"

CFlagSystem g_FlagSystem;

void CFlagSystem::Init()
{
	m_Enabled = false;
	LoadINI();
	if(m_Enabled)
	{
		g_Log.Add(CLog::Blue, "[%s] Feature is enabled, loaded [%d] npc(s).", __FUNCTION__, m_Npcs.size());
	}
}

/*
[FlagSystem]
Enabled=1
Range=300
NpcList=
*/

void CFlagSystem::LoadINI()
{
	const WCHAR* section = _T("FlagSystem");
	m_Enabled = GetPrivateProfileInt(section, _T("Enabled"), 0, g_ConfigFile);
	m_Range = GetPrivateProfileInt(section, _T("Range"), 0, g_ConfigFile);
	TCHAR temp[0x8000] = { 0 };
	if(GetPrivateProfileString(section, _T("NpcList"), 0, temp, 0x8000, g_ConfigFile))
	{
		wstringstream npcStream(temp);
		wstring npcName;
		while(npcStream >> npcName)
		{
			INT32 npcId = g_ObjectDB.GetClassIdFromName(npcName.c_str());
			if(npcId > 0)
			{
				m_Npcs.push_back(npcId);
			}			
		}
	}
}

void CFlagSystem::Handle(CNPC *pNpc)
{
	if(m_Enabled)
	{
		if(m_Range > 0)
		{
			for(UINT n=0;n<m_Npcs.size();n++)
			{
				if(pNpc->pSD->nNpcClassID == m_Npcs[n])
				{
					//check how far npc is from the spawn location
					//IVector pos(pNpc->pSD->Pos);
					//INT32 distance = pNpc->pSD->spawnPos.Distance(pos);

					g_UserDB.Lock();
					map<UINT, User*>& mData = g_UserDB.GetUserMap();
					for(map<UINT, User*>::iterator Iter = mData.begin(); Iter!=mData.end(); Iter++)
					{
						if(User *pTarget = Iter->second->SafeCastUser())
						{
							if(pTarget->IsInRange(pNpc, m_Range))
							{
								pTarget->SetPvPFlag();
								pTarget->SetUserInfoChanged();
								pTarget->SetCharInfoChanged();
							}
						}
					}
					g_UserDB.Unlock();

					break;
				}
			}
		}
	}
}
