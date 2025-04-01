#pragma once

class CFactionSystem
{
	vector<INT32> g_AntiFactionSkills;
	void LoadINI();
public:
	CFactionSystem();
	~CFactionSystem();
	void Init();
	bool SkillExist(int nSkillID);
};

extern CFactionSystem g_FactionSystem;
