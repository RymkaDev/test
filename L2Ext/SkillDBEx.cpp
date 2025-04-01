#include "StdAfx.h"

map<INT32, INT32> g_MaxSkillLevel;

CSkillDBEx::~CSkillDBEx()
{
	map<CSkillKey, CSkillInfoEx*>::iterator Iter = mData.begin();
	for(;Iter!=mData.end();Iter++)
	{
		delete Iter->second;
		Iter->second = NULL;
	}
}

void CSkillDBEx::ReadData2()
{
	//[s_power_strike12] = 770
	wstring wData = ReadFileW(g_ChangeFolders.Skill_Pch_txt);
	wstringstream wsstr;
	wsstr << wData;
	wstring wLine;
	int Skills = 0;
	int Levels = 0;
	while(getline(wsstr, wLine))
	{
		if(wLine.find(L"//") == 0)
			continue;

		wstringstream skillData;
		wstring lineData = Parser::Replace(wLine, L'=', L' ');
		skillData << lineData;
		wstring wName;
		UINT SkillNameID = 0;
		skillData >> wName >> SkillNameID;

		if(SkillNameID > 0)
		{
			Levels++;
			SkillPchId key(SkillNameID);
			map<INT32, INT32>::iterator maxLevel = g_MaxSkillLevel.find(key.skillId);
			if(maxLevel != g_MaxSkillLevel.end())
			{
				if(maxLevel->second < key.level)
				{
					maxLevel->second = key.level;
				}
			}else
			{
				g_MaxSkillLevel.insert(pair<INT32, INT32>(key.skillId, key.level));
			}

			map<int, map<int, wstring>>::iterator Iter = mData2.find(key.skillId);
			if(Iter != mData2.end())
			{
				Skills++;
				Iter->second.insert(pair<int, wstring>(key.level, wName));
			}else
			{
				map<int, wstring> mSkill;
				mSkill.insert(pair<int, wstring>(key.level, wName));
				mData2.insert(pair<int, map<int, wstring>>(key.skillId, mSkill));
			}
		}
	}
	g_Log.Add(CLog::Blue, "[%s] Loaded [%d] skills and [%d] levels.", __FUNCTION__, Skills, Levels);
}

int CSkillDBEx::GetMaxSkillLevel(int SkillID)
{
	map<INT32, INT32>::iterator maxLevel = g_MaxSkillLevel.find(SkillID);
	if(maxLevel != g_MaxSkillLevel.end())
	{
		return maxLevel->second;
	}
	return 0;
}

int CSkillDBEx::GetMaxNotEnchantedSkillLevel(int SkillID)
{
	map<int, map<int, wstring>>::iterator Iter = mData2.find(SkillID);
	if(Iter!=mData2.end())
	{
		int nLevel = -1;
		for(map<int, wstring>::iterator LevelIter = Iter->second.begin();LevelIter!= Iter->second.end();LevelIter++)
		{
			if(LevelIter->first > nLevel)
			{
				if(LevelIter->first < 100)
				{
					nLevel = LevelIter->first;
				}else
					return nLevel;
			}
		}
		return nLevel;
	}
	return -1;
}

void CSkillDBEx::ReadData()
{
	ifstream file(g_ChangeFolders.SkillDataEx_txt.c_str());
	if(file)
	{
		string sLine;
		while(getline(file, sLine))
		{
			if(sLine.find("begin") == 0)
			{
				//reading stuff
				string sName = CParser::GetValueString(sLine, "skill_name");
				int nID = CParser::GetValueInt(sLine, "skill_id");
				int nLevel = CParser::GetValueInt(sLine, "level");
				double SoulshotBonus = CParser::GetValueDouble(sLine, "soulshot_bonus");
				double DamageBonus = CParser::GetValueDouble(sLine, "damage_bonus");
				bool AvoidShieldBlock = CParser::GetValueInt(sLine, "avoid_shield_block");
				bool MagicShieldBlock = CParser::GetValueInt(sLine, "magic_shield_block");
				bool DirectToHp = CParser::GetValueInt(sLine, "direct_to_hp");
				bool GeoDataTest = CParser::GetValueInt(sLine, "geodata_test");
				int StaticReuseTime = CParser::GetValueInt(sLine, "static_reuse_time");
				int StaticReuseTime_segundos = CParser::GetValueInt(sLine, "static_reuse_time_segundos", 0);

				int StaticReuseTimeWarrior = CParser::GetValueInt(sLine, "static_reuse_time_warrior");
				int StaticReuseTimeMago = CParser::GetValueInt(sLine, "static_reuse_time_mago");

				if(StaticReuseTime_segundos > 0)
					StaticReuseTime= StaticReuseTime_segundos*1000;

				CSkillInfoEx *pData = new CSkillInfoEx();
				if(pData)
				{
					pData->name = sName;
					pData->id = nID;
					pData->level = nLevel;
					pData->soulshotBonus = SoulshotBonus;
					pData->avoidShieldBlock = AvoidShieldBlock;
					pData->magicShieldBlock = MagicShieldBlock;
					pData->directToHp = DirectToHp;
					pData->geoDataTest = GeoDataTest;
					pData->staticReuseTime = StaticReuseTime;
					pData->damageBonus = DamageBonus;

					pData->staticReuseTimeWarrior = StaticReuseTimeWarrior;
					pData->staticReuseTimeMago = StaticReuseTimeMago;


					
					CSkillKey key(nID, nLevel);
					mData.insert(pair<CSkillKey, CSkillInfoEx*>(key, pData));
				}else
					g_Log.Add(CLog::Error, "[%s] Cannot allocate memory for pData", __FUNCTION__);
			}
		}
		g_Log.Add(CLog::Blue, "[%s] Loaded [%d] skills.", __FUNCTION__, mData.size());
	}else
		g_Log.Add(CLog::Error, "[%s] SkillDataEx.txt cannot be found!", __FUNCTION__);
}

void CSkillDBEx::Initialize()
{ 
	g_Log.Add(CLog::Blue, "[%s] Reading Data", __FUNCTION__); 

	mData.clear();
	mData2.clear();
	m_SkillNameE.clear();
	m_SkillGrp.clear();

	ReadData();
	ReadData2();

	LoadSkillNameData();
	LoadSkillGrpData();
}

CSkillInfoEx *CSkillDBEx::GetSkillInfoEx(int nSkillID, int nLevel)
{
	CSkillInfoEx *pData = NULL;
	CSkillKey key(nSkillID, nLevel);
	map<CSkillKey, CSkillInfoEx*>::iterator Iter = mData.find(key);
	if(Iter!=mData.end())
	{
		pData = Iter->second;
	}else
	{
		CSkillKey key0(nSkillID, 0);
		Iter = mData.find(key0);
		if(Iter!=mData.end())
			return Iter->second;
	}
	return pData;
};


void CSkillDBEx::LoadSkillNameData()
{
	guard;
	wstringstream file(ReadFileW(g_ChangeFolders.SkillName_txt));
	wstring line;
	while(getline(file, line))
	{
		if(line.find(L"\\") == 0)
		{
			continue;
		}

		//1	101	Triple Slash	Inflicts 3 quick slashes on opponent. Use with dual-sword. Over-hit is possible. Enchant Power: the power is increased. Power 2151.	+1 Power	Maximizes power of skill. Power Increases.

		vector<wstring> parts = Parser::Split(line, L"\t");
		if(parts.size() > 2)
		{
			int skillId = _wtoi(parts[0].c_str());
			int skilllev = _wtoi(parts[1].c_str());
			wstring skillname = parts[2];
			wstring skilldesc = parts[3];
			wstring skillench1 = parts[4];
			wstring skillench2 = parts[5];
			
			if(skillId > 0)
			{
				CSkillKey key(skillId, skilllev);

				//m_SkillNameE
				SkillNameE skill;
				skill.skillname = skillname;
				skill.skilldesc = skilldesc;
				skill.skillenchant1 = skillench1;
				skill.skillenchant2 = skillench2;

				m_SkillNameE.insert(pair<CSkillKey, SkillNameE>(key, skill));

			}
		}
	}
	g_Log.Add(CLog::Blue, "[%s] Loaded [%d] SkillName Info.", __FUNCTION__, m_SkillNameE.size());
	unguard;
}

void CSkillDBEx::LoadSkillGrpData()
{
	guard;
	wstringstream file(ReadFileW(g_ChangeFolders.SkillGrp_txt));
	wstring line;
	while(getline(file, line))
	{
		if(line.find(L"\\") == 0)
		{
			continue;
		}

		//skill_id	skill_level	oper_type	mp_consume	cast_range	cast_style	hit_time	is_magic	ani_char	desc	icon_name	extra_eff	is_ench	ench_skill_id	hp_consume	UNK_0	UNK_1
		//12000	1	1	41	-1	1	1.000000	0	D	skill.wh.1045	icon.skill1045	0	0	0	0	8	10

		vector<wstring> parts = Parser::Split(line, L"\t");
		if(parts.size() > 2)
		{
			int skillId = _wtoi(parts[0].c_str());
			int skilllev = _wtoi(parts[1].c_str());
			wstring skillicon = parts[10];
			
			if(skillId > 0)
			{
				CSkillKey key(skillId, skilllev);

				//m_SkillGrp
				SkillGrp skill;
				skill.skillicon = skillicon;

				m_SkillGrp.insert(pair<CSkillKey, SkillGrp>(key, skill));

			}
		}
	}

	g_Log.Add(CLog::Blue, "[%s] Loaded [%d] SkillGrp Info.", __FUNCTION__, m_SkillGrp.size());
	unguard;
}

wstring CSkillDBEx::GetSkillName(int nSkillID, int nSkillLev)
{
	CSkillKey key(nSkillID, nSkillLev);
	map<CSkillKey, SkillNameE>::iterator Iter = m_SkillNameE.find(key);
	if(Iter!=m_SkillNameE.end())
		return Iter->second.skillname;

	return L"Not Found";
}

wstring CSkillDBEx::GetSkillDesc(int nSkillID, int nSkillLev)
{
	CSkillKey key(nSkillID, nSkillLev);
	map<CSkillKey, SkillNameE>::iterator Iter = m_SkillNameE.find(key);
	if(Iter!=m_SkillNameE.end())
		return Iter->second.skilldesc;

	return L"Not Found";
}

wstring CSkillDBEx::GetSkillEnch1(int nSkillID, int nSkillLev)
{
	CSkillKey key(nSkillID, nSkillLev);
	map<CSkillKey, SkillNameE>::iterator Iter = m_SkillNameE.find(key);
	if(Iter!=m_SkillNameE.end())
		return Iter->second.skillenchant1;

	return L"Not Found";
}

wstring CSkillDBEx::GetSkillEnch2(int nSkillID, int nSkillLev)
{
	CSkillKey key(nSkillID, nSkillLev);
	map<CSkillKey, SkillNameE>::iterator Iter = m_SkillNameE.find(key);
	if(Iter!=m_SkillNameE.end())
		return Iter->second.skillenchant2;

	return L"Not Found";
}

wstring CSkillDBEx::GetSkillIcon(int nSkillID, int nSkillLev)
{
	CSkillKey key(nSkillID, nSkillLev);
	map<CSkillKey, SkillGrp>::iterator Iter = m_SkillGrp.find(key);
	if(Iter!=m_SkillGrp.end())
		return Iter->second.skillicon;

	return L"Not Found";
}