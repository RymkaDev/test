#include "stdafx.h"
#include "LureProtection.h"
#include "ObjectDB.h"

CLureProtection g_LureProtection;

void CLureProtection::Init()
{
	m_Enabled = false;
	LoadINI();
	if(m_Enabled)
	{
		g_Log.Add(CLog::Blue, "[%s] Feature is enabled, loaded [%d] npc(s).", __FUNCTION__, m_Npcs.size());
	}
}

void CLureProtection::LoadINI()
{
	const WCHAR* section = _T("LureProtection");
	m_Enabled = GetPrivateProfileInt(section, _T("Enabled"), 0, g_ConfigFile);
	m_LureRange = GetPrivateProfileInt(section, _T("MaxLureRange"), 0, g_ConfigFile);
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

//void CLureProtection::Handle(CNPC *pNpc)
//{
//	if(m_Enabled)
//	{
//		if(m_LureRange > 0)
//		{
//			for(UINT n=0;n<m_Npcs.size();n++)
//			{
//				if(pNpc->pSD->nNpcClassID == m_Npcs[n])
//				{
					//check how far npc is from the spawn location
//					IVector pos(pNpc->pSD->Pos);
//					INT32 distance = pNpc->pSD->spawnPos.Distance(pos);
//					if(distance > m_LureRange)
//					{
//						CHAR buff[8190];
//						INT32 len = Assemble(buff, sizeof(buff), "cdd", 0x2A, pNpc->nObjectID, pNpc->pSD->nServerIndex);
//						NpcServer::Send(len, buff);
						//teleport to spawn loc
//						pNpc->TeleportToLocation(pNpc->pSD->spawnPos.x, pNpc->pSD->spawnPos.y, pNpc->pSD->spawnPos.z, 0);
//						g_Log.Add(CLog::Blue, "[%s] Npc[%S] is too far away form spawn pos - teleporting back to (%d/%d/%d).", __FUNCTION__, pNpc->pSD->wszName, pNpc->pSD->spawnPos.x, pNpc->pSD->spawnPos.y, pNpc->pSD->spawnPos.z);
//					}
//					break;
//				}
//			}
//		}
//	}
//}


void CLureProtection::Handle(CNPC *pNpc)
{
	if(m_Enabled)
	{
		if(pNpc->pSD->m_nAgroRange < m_LureRange)
		{
			IVector pos(pNpc->pSD->Pos);
			INT32 distance = pNpc->pSD->spawnPos.Distance(pos);
			INT32 agroRange = pNpc->pSD->m_nAgroRange;

			if(distance > agroRange + 500)
			{
				CHAR buff[8190];
				INT32 len = Assemble(buff, sizeof(buff), "cdd", 0x2A, pNpc->nObjectID, pNpc->pSD->nServerIndex);
				NpcServer::Send(len, buff);
				//teleport to spawn loc

				//g_Log.Add(CLog::Error, "[%s] Npc[%S] Pos(%d/%d/%d) spawnPos(%d/%d/%d) m_nAgroRange=%d distance=%d", __FUNCTION__, pNpc->pSD->wszName, (int)pNpc->pSD->Pos.x, (int)pNpc->pSD->Pos.y, (int)pNpc->pSD->Pos.z, pNpc->pSD->spawnPos.x, pNpc->pSD->spawnPos.y, pNpc->pSD->spawnPos.z, pNpc->pSD->m_nAgroRange, distance);
				pNpc->TeleportToLocation(pNpc->pSD->spawnPos.x, pNpc->pSD->spawnPos.y, pNpc->pSD->spawnPos.z, 0);
			}
		}
	}
}


bool CLureProtection::HandlePlayer(CCreature *pNpc, User* pUser)
{
	if(m_Enabled)
	{
		if(pNpc->pSD->m_nAgroRange < m_LureRange)
		{
			IVector pos(pNpc->pSD->Pos);
			INT32 distance = pNpc->pSD->spawnPos.Distance(pUser->pSD->Pos);
			if(distance > pNpc->pSD->m_nAgroRange)
			{
				CSystemMessage msg1(2901);
				msg1.AddText(L"No me lastimas de tan lejos.");
				pUser->pSocket->SendSystemMessage(&msg1);
				return true;
			}
		}
	}
	return false;
}
