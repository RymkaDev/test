#include "stdafx.h"
#include "ChampionNpc.h"

CChampionNpc g_ChampionNpc;

void CChampionNpc::Init()
{
	//VIRTUALIZER_TIGER_BLACK_START;
	m_Enabled = false;
	LoadINI();
	if(m_Enabled)
	{
		LoadChampionData();
		g_Log.Add(CLog::Blue, "[%s] Feature is enabled, loaded [%d] npc(s).", __FUNCTION__, m_Npc.size());
	}
	//VIRTUALIZER_TIGER_BLACK_END;
}

/*
[ChampionNpc]
Enabled=0
;HP/MP Addon to the original stats
BlueTeamHPMP=
RedTeamHPMP=
*/

void CChampionNpc::LoadINI()
{
	//VIRTUALIZER_TIGER_BLACK_START;
	const TCHAR* section = _T("ChampionNpc");
	m_Enabled = GetPrivateProfileInt(section, _T("Enabled"), 0, g_ConfigFile);
	m_BlueHPMP = GetPrivateProfileInt(section, _T("BlueTeamHPMP"), 0, g_ConfigFile);
	m_RedHPMP = GetPrivateProfileInt(section, _T("RedTeamHPMP"), 0, g_ConfigFile);
	//VIRTUALIZER_TIGER_BLACK_END;
}

void CChampionNpc::LoadChampionData()
{
	m_Npc.clear();
	ifstream file(g_ChangeFolders.NpcChampionData_txt.c_str());
	if(file)
	{
		string sLine;
		while(getline(file, sLine))
		{
			if(sLine.find("//") == 0)
				continue;

			if(sLine.find("npc_begin") == 0)
			{
				int npcId = CParser::GetValueInt(sLine, "npc_class_id");
				double chance_blue = CParser::GetValueDouble(sLine, "chance_blue_spawn");
				double chance_red = CParser::GetValueDouble(sLine, "chance_red_spawn");

				double blue_exp = CParser::GetValueDouble(sLine, "blue_exp");
				double red_exp = CParser::GetValueDouble(sLine, "red_exp");

				double blue_sp = CParser::GetValueDouble(sLine, "blue_sp");
				double red_sp = CParser::GetValueDouble(sLine, "red_sp");

				double blue_adena = CParser::GetValueDouble(sLine, "blue_adena");
				double red_adena = CParser::GetValueDouble(sLine, "red_adena");

				double blue_drop = CParser::GetValueDouble(sLine, "blue_drop");
				double red_drop = CParser::GetValueDouble(sLine, "red_drop");

				double blue_spoil = CParser::GetValueDouble(sLine, "blue_spoil");
				double red_spoil = CParser::GetValueDouble(sLine, "red_spoil");

				int blue_reputation_points = CParser::GetValueInt(sLine, "blue_reputation_points");
				int red_reputation_points = CParser::GetValueInt(sLine, "red_reputation_points");
				if(npcId > 0)
				{
					ChampionNpcInfo* pInfo = new ChampionNpcInfo();
					pInfo->NpcId = npcId;
					pInfo->chance_blue = chance_blue;
					pInfo->chance_red = chance_red;
					pInfo->blue_exp = blue_exp;
					pInfo->red_exp = red_exp;
					pInfo->blue_sp = blue_sp;
					pInfo->red_sp = red_sp;
					pInfo->blue_adena = blue_adena;
					pInfo->red_adena = red_adena;
					pInfo->blue_drop = blue_drop;
					pInfo->red_drop = red_drop;
					pInfo->blue_spoil = blue_spoil;
					pInfo->red_spoil = red_spoil;
					pInfo->blue_reputation_points = blue_reputation_points;
					pInfo->red_reputation_points = red_reputation_points;
					m_Npc.push_back(pInfo);
				}
			}
		}
	}
}

ChampionNpcInfo *CChampionNpc::GetChampionData(UINT npcClassID)
{
	ChampionNpcInfo *pData = NULL;
	for(UINT n=0;n<m_Npc.size();n++)
	{
		if(m_Npc[n]->NpcId == npcClassID)
		{
			pData = m_Npc[n];
		}
	}
	return pData;
}

bool CChampionNpc::IsChampionNPC(UINT npcClassID)
{
	for(UINT n=0;n<m_Npc.size();n++)
	{
		if(m_Npc[n]->NpcId == npcClassID)
		{
			return true;
		}
	}
	return false;
}

int CChampionNpc::GetExp(int baseExp, UINT nNPCclassID, int nTeam)
{
	if(IsEnabled())
	{
		if(nTeam)
		{
			if(IsChampionNPC(nNPCclassID))
			{
				ChampionNpcInfo* pInfo = GetChampionData(nNPCclassID);	
				if(nTeam == 1)
				{
					double exp = (double)baseExp;
					exp *= pInfo->blue_exp;

					return (int)exp;
				}
				else if(nTeam == 2)
				{
					double exp = (double)baseExp;
					exp *= pInfo->red_exp;

					return (int)exp;
				}

			}
		}
	}

	return baseExp;
}

int CChampionNpc::GetSP(int baseSP, UINT nNPCclassID, int nTeam)
{
	if(IsEnabled())
	{
		if(nTeam)
		{
			if(IsChampionNPC(nNPCclassID))
			{
				ChampionNpcInfo* pInfo = GetChampionData(nNPCclassID);			
				if(nTeam == 1)
				{
					double sp = (double)baseSP;
					sp *= pInfo->blue_sp;

					return (int)sp;
				}
				else if(nTeam == 2)
				{
					double sp = (double)baseSP;
					sp *= pInfo->red_sp;

					return (int)sp;
				}

			}
		}
	}
	return baseSP;
}