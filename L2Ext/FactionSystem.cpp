#include "StdAfx.h"
#include "FactionSystem.h"
#include "FactionCounter.h"

CFactionSystem g_FactionSystem;

//UINT m_RedTeamCount = 0;
//UINT m_GreenTeamCount = 0;

CFactionSystem::CFactionSystem()
{
}

CFactionSystem::~CFactionSystem()
{
}

void CFactionSystem::Init()
{
	guard;
	g_AntiFactionSkills.clear();
	LoadINI();
	unguard;
}

void CFactionSystem::LoadINI()
{
	guard;
	const TCHAR* section = _T("FactionSystem");
	TCHAR temp[8190] = { 0 };
	if(GetPrivateProfileString(section, _T("ForbidSkillsTeam"), 0, temp, 8190, g_ConfigFile))
	{
		wstringstream skillStream;
		skillStream << temp;
		int skillId = 0;
		while(skillStream >> skillId)
		{
			g_AntiFactionSkills.push_back(skillId);
		}

	}
	unguard;
}

bool CFactionSystem::SkillExist(int nSkillID)
{
	guard;
	for(UINT n=0;n<g_AntiFactionSkills.size();n++)
	{
		if(nSkillID == g_AntiFactionSkills[n])
		{
			return true;
		}
	}

	unguard;
	return false;
}
