#pragma once

//begin	skill_name=[s_triple_slash11]	skill_id=1	soulshot_bonus=1.33	shield_block=0	magic_shield_block=0	cancel_resistance=0	end

class CSkillInfoEx
{
public:
	string name;
	int id;
	int level;
	double soulshotBonus;
	double damageBonus;
	bool avoidShieldBlock;
	bool magicShieldBlock;
	bool directToHp;
	bool geoDataTest;
	int staticReuseTime;
	int staticReuseTimeWarrior;
	int staticReuseTimeMago;
	CSkillInfoEx() : id(0), level(0), geoDataTest(0), soulshotBonus(0), damageBonus(0), avoidShieldBlock(false), magicShieldBlock(false), directToHp(false), staticReuseTime(0), staticReuseTimeWarrior(0), staticReuseTimeMago(0) { }
};

struct SkillNameE
{
	wstring skillname;
	wstring skilldesc;
	wstring skillenchant1;
	wstring skillenchant2;
};

struct SkillGrp
{
	wstring skillicon;
	//Mby Add on future?
};

class CSkillDBEx
{
	void ReadData();
	void ReadData2();
	void LoadSkillNameData();
	void LoadSkillGrpData();
	map<int, map<int, wstring>> mData2; //<SkillID, <Level, Name>>
	map<CSkillKey, CSkillInfoEx*> mData;
	map<CSkillKey, SkillNameE> m_SkillNameE;
	map<CSkillKey, SkillGrp> m_SkillGrp;

public:
	~CSkillDBEx();
	void Initialize();
	int GetMaxSkillLevel(int SkillID);
	int GetMaxNotEnchantedSkillLevel(int SkillID);
	CSkillInfoEx *GetSkillInfoEx(int nSkillID, int nLevel);
	wstring GetSkillName(int nSkillID, int nSkillLev);
	wstring GetSkillDesc(int nSkillID, int nSkillLev);
	wstring GetSkillEnch1(int nSkillID, int nSkillLev);
	wstring GetSkillEnch2(int nSkillID, int nSkillLev);
	wstring GetSkillIcon(int nSkillID, int nSkillLev);
};

extern CSkillDBEx g_SkillDBEx;