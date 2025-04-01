#pragma once

struct HappyHoursPeriod
{
	UINT startHour;
	UINT endHour;
	UINT startHour2;
	UINT endHour2;
};

class CHappyHours
{
	BOOL m_Enabled;
	BOOL g_HappyHourSecondTimeEnabled;
	int nExpRateBonus;
	int nSPRateBonus;
	int nAdenaRateBonus;
	int nDropRateBonus;
	int nSpoilRateBonus;
	wstring registrationBeforeStart;
	wstring registrationOnStart;
	wstring registrationEnd;
	//CSLock m_Lock;

public:
	CHappyHours();
	~CHappyHours();
	void Initialize();
	bool GetStatus();
	int GetSP(int baseSP);
	int GetExp(int baseExp);
	double GetSpoilRate(CCreature *pCreature);
	double GetAdenaRate(CCreature *pCreature);
	double GetDropRate(CCreature *pCreature);

};

extern CHappyHours g_HappyHours;