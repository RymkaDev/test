#pragma once

class CFlagSystem
{
	bool m_Enabled;
	vector<UINT> m_Npcs;
	INT32 m_Range;
	
	void LoadINI();
public:
	void Init();
	void Handle(CNPC *pNpc);
	void PlayerFlag(User *pUser);
	inline bool Enabled() { return m_Enabled; }
};

extern CFlagSystem g_FlagSystem;
