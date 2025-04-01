#pragma once

class CAntibot : public CThreadSafe
{
	BOOL m_Enabled;
	UINT n_TimeBetweenSkills;

	map<HWID, DWORD> computers;
	 
public:
	CAntibot() {};
	~CAntibot() {};
	void Init();
	void OnEnterWorld(User *pUser, HWID hwid);
	void OnMagicSkillUse(User *pUser, HWID hwid);

	inline BOOL IsEnabled() { return m_Enabled; };
};

extern CAntibot g_Antibot;