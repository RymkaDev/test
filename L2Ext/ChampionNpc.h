#pragma once

struct ChampionNpcInfo
{
	UINT NpcId;
	double chance_blue;
	double chance_red;
	double blue_exp;
	double red_exp;
	double blue_sp;
	double red_sp;
	double blue_adena;
	double red_adena;
	double blue_drop;
	double red_drop;
	double blue_spoil;
	double red_spoil;
	UINT blue_reputation_points;
	UINT red_reputation_points;

	ChampionNpcInfo() : NpcId(0), chance_blue(0.0), chance_red(0.0), blue_exp(0.0), red_exp(0.0), blue_sp(0.0), red_sp(0.0), blue_adena(0.0), red_adena(0.0), blue_drop(0.0), red_drop(0.0), blue_spoil(0.0), red_spoil(0.0), blue_reputation_points(0), red_reputation_points(0) {};
};

class CChampionNpc
{
	bool m_Enabled;
	UINT m_BlueHPMP;
	UINT m_RedHPMP;
	vector<ChampionNpcInfo*> m_Npc;
	void LoadINI();
public:
	void Init();
	inline bool IsEnabled() { return m_Enabled; };
	inline UINT GetBlueHPMPAddon() { return m_BlueHPMP; };
	inline UINT GetRedHPMPAddon() { return m_RedHPMP; };
	void LoadChampionData();
	ChampionNpcInfo *GetChampionData(UINT npcClassID);
	bool IsChampionNPC(UINT npcClassID);
	int GetExp(int baseExp, UINT nNPCclassID, int nTeam);
	int GetSP(int baseSP, UINT nNPCclassID, int nTeam);
};

extern CChampionNpc g_ChampionNpc;