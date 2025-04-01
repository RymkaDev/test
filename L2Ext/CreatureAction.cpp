#include "StdAfx.h"
#include "CreatureAction.h"
#include "HerbSystem.h"
#include "VIPSystem.h"
#include "Augmentation.h"
#include "HerbSystem.h"
#include "TerritoryData.h"
#include "Geo.h"
#include "DnN.h"
#include "TvT.h"
#include "AIO.h"
#include "InfinityShot.h"
#include "Exploits.h"
#include "DuelSystem.h"
#include "ObjectDB.h"
#include "ArmorPenalty.h"
#include "SkillOperateCondition.h"
#include "PetAction.h"
#include "Rebirth.h"
#include "DoorData.h"
#include "JailSystem.h"
#include "PlayerAction.h"
#include "FactionSystem.h"
#include "FactionCounter.h"
#include "DB.h"
#include "Hair2Slot.h"
#include "LureProtection.h"
#include "RatesDinamicos.h"

extern BOOL g_BlockSummonExp;
extern BOOL g_SpiritShotExtension;
extern BOOL g_NewShotSystem;
extern INT32 g_MaxPartyLevelRange;
extern BOOL g_IsDistributingExpSp[32];
extern CCreature* g_DistributingCreature[32];
extern double g_PartyExpRate;
extern double g_PetExpRate;


extern BOOL g_FrenzyDamagePlayerMultipler;

extern double g_FrenzyDamagePlayerMultipler_none;
extern double g_FrenzyDamagePlayerMultipler_sword;
extern double g_FrenzyDamagePlayerMultipler_blunt;
extern double g_FrenzyDamagePlayerMultipler_dagger;
extern double g_FrenzyDamagePlayerMultipler_pole;
extern double g_FrenzyDamagePlayerMultipler_fist;
extern double g_FrenzyDamagePlayerMultipler_bow;
extern double g_FrenzyDamagePlayerMultipler_etc;
extern double g_FrenzyDamagePlayerMultipler_dual;
extern double g_FrenzyDamagePlayerMultipler_dualfist;
extern double g_FrenzyDamagePlayerMultipler_fishing_rod;

extern double g_FrenzyDamagePlayerMultipler_noneTwo;
extern double g_FrenzyDamagePlayerMultipler_swordTwo;
extern double g_FrenzyDamagePlayerMultipler_bluntTwo;
extern double g_FrenzyDamagePlayerMultipler_daggerTwo;
extern double g_FrenzyDamagePlayerMultipler_poleTwo;
extern double g_FrenzyDamagePlayerMultipler_fistTwo;
extern double g_FrenzyDamagePlayerMultipler_bowTwo;
extern double g_FrenzyDamagePlayerMultipler_etcTwo;
extern double g_FrenzyDamagePlayerMultipler_dualTwo;
extern double g_FrenzyDamagePlayerMultipler_dualfistTwo;
extern double g_FrenzyDamagePlayerMultipler_fishing_rodTwo;



extern double g_MagoVsMago;
extern double g_MagoVsWarrior;
extern double g_WarriorVsMago;
extern double g_WarriorVsWarrior;


//none=0; sword= 1; blunt= 2; dagger= 3; pole= 4; fist= 5; bow= 6; etc= 7; dual=8; dualfist=9; fishing_rod=10;


vector<INT32> g_BlockBuffException;
vector<INT32> g_BlockDebuffException;

vector<INT32> g_BlockBuffExceptionWarrior;
vector<INT32> g_BlockBuffExceptionMage;

vector<INT32> g_AntiBuffException;

vector<INT32> g_HealResistNpc;

BOOL g_ToggleSkillSystem = FALSE;
BOOL g_TeamAbnormal = FALSE;
BOOL g_ReplaceHostileAbnormal = TRUE;
BOOL g_CelestialDisAggro = FALSE;


BOOL g_DoorInActionTarget[16] = { 0 };
CCreature * g_SkillOnTickCaster[16] = { 0 };
const CSkillInfo * g_SkillOnTickSkillInfo[16] = { 0 };

BOOL g_AttackOnTickAttaker[16] = { 0 };

CCreature* g_Harvester[26];

double g_FrenzyDamageMultipler = 1.0;

BOOL g_FrenzyDamageRaidBoss = FALSE;
BOOL g_FrenzyDamageZZoldagu = FALSE;
double g_FrenzyTopDamage = 1.0;
vector <int> g_FrenzyDamageNpcs;
vector<int> g_BossIgnoreSkills;
BOOL g_BossPvPFlag = 0;
vector<INT32> g_BossPvPFlagException;

bool CWorld_PickItem(CWorld* pWorld, CItem* pItem, CCreature *pCreature)
{
	if(pItem->IsValidItem() && pCreature->ValidCreature())
	{
		if(g_HerbSystem.HandleHerb(pCreature, pItem))
		{
			return true;
		}
	}

	typedef bool (*f)(CWorld*, CItem*, CCreature*);
	return f(0x8BEAC0L)(pWorld, pItem, pCreature);
}


void CreatureAction::LoadINI()
{
	
	const TCHAR* sectionName = _T("SkillFactory");
	TCHAR temp[0x4000];
	memset(temp, 0, sizeof(temp));
	g_BlockBuffException.clear();
	if(GetPrivateProfileString(sectionName, _T("BlockBuffException"), 0, temp, 0x8000, g_ConfigFile))
	{
		wstringstream skillStream(temp);
		wstring skillName;
		while(skillStream >> skillName)
		{
			INT32 skillId = 0, level = 0;
			g_SkillDB.GetSkillIdLevelByName((PWCHAR)skillName.c_str(), &skillId, &level);
			if(skillId > 0)
			{
				g_BlockBuffException.push_back(skillId);
			}			
		}
	}


	g_BlockBuffException.clear();
	if(GetPrivateProfileString(sectionName, _T("BlockBuffExceptionWarrior"), 0, temp, 0x8000, g_ConfigFile))
	{
		wstringstream skillStream(temp);
		wstring skillName;
		while(skillStream >> skillName)
		{
			INT32 skillId = 0, level = 0;
			g_SkillDB.GetSkillIdLevelByName((PWCHAR)skillName.c_str(), &skillId, &level);
			if(skillId > 0)
			{
				g_BlockBuffExceptionWarrior.push_back(skillId);
			}			
		}
	}

	g_BlockBuffException.clear();
	if(GetPrivateProfileString(sectionName, _T("BlockBuffExceptionMage"), 0, temp, 0x8000, g_ConfigFile))
	{
		wstringstream skillStream(temp);
		wstring skillName;
		while(skillStream >> skillName)
		{
			INT32 skillId = 0, level = 0;
			g_SkillDB.GetSkillIdLevelByName((PWCHAR)skillName.c_str(), &skillId, &level);
			if(skillId > 0)
			{
				g_BlockBuffExceptionMage.push_back(skillId);
			}			
		}
	}

	g_AntiBuffException.clear();
	if(GetPrivateProfileString(sectionName, _T("AntiBuffException"), 0, temp, 0x8000, g_ConfigFile))
	{
		wstringstream skillStream(temp);
		wstring skillName;
		while(skillStream >> skillName)
		{
			INT32 skillId = 0, level = 0;
			g_SkillDB.GetSkillIdLevelByName((PWCHAR)skillName.c_str(), &skillId, &level);
			if(skillId > 0)
			{
				g_AntiBuffException.push_back(skillId);
			}			
		}
	}

	g_ToggleSkillSystem = GetPrivateProfileInt(_T("L2Server"), _T("ToggleSkillSystem"), 0, g_ConfigFile);



	g_BossIgnoreSkills.clear();
	if(GetPrivateProfileString(_T("NpcMod"), _T("BossIgnoreSkillList"), 0, temp, 0x8000, g_ConfigFile))
	{
		wstringstream skillStream(temp);
		wstring skillName;
		while(skillStream >> skillName)
		{
			INT32 skillId = 0, level = 0;
			g_SkillDB.GetSkillIdLevelByName((PWCHAR)skillName.c_str(), &skillId, &level);
			if(skillId > 0)
			{
				g_BossIgnoreSkills.push_back(skillId);
			}			
		}
	}


	g_BossPvPFlag = GetPrivateProfileInt(_T("NpcMod"), _T("BossPvPFlag"), 0, g_ConfigFile);


	memset(temp, 0, sizeof(temp));
	g_BossPvPFlagException.clear();
	if(GetPrivateProfileString(_T("NpcMod"), _T("BossPvPFlagException"), 0, temp, 0x8000, g_ConfigFile))
	{
		wstringstream npcStream(temp);
		wstring npcName;
		while(npcStream >> npcName)
		{
			INT32 npcId = g_ObjectDB.GetClassIdFromName(npcName.c_str());
						//INT32 npcId = 0;
			if(npcId > 0)
			{
				g_BossPvPFlagException.push_back(npcId);
			}			
		}
	}


	g_BlockDebuffException.clear();
	if(GetPrivateProfileString(sectionName, _T("BlockDebuffException"), 0, temp, 0x8000, g_ConfigFile))
	{
		wstringstream skillStream(temp);
		wstring skillName;
		while(skillStream >> skillName)
		{
			INT32 skillId = 0, level = 0;
			g_SkillDB.GetSkillIdLevelByName((PWCHAR)skillName.c_str(), &skillId, &level);
			if(skillId > 0)
			{
				g_BlockDebuffException.push_back(skillId);
			}			
		}
	}


	UINT permissionTime = GetPrivateProfileInt(_T("NpcMod"), _T("FirstItemDropPermissionTime"), 5, g_ConfigFile);
	permissionTime *= 1000;
	g_HookManager.WriteMemoryDWORD(0x4354F1, permissionTime);
	g_HookManager.WriteMemoryDWORD(0x6C5021, permissionTime);		//bool __stdcall CNPC::Die(CNPC *this, CCreature *pEnemy)
	permissionTime = GetPrivateProfileInt(_T("NpcMod"), _T("SecondItemDropPermissionTime"), 10, g_ConfigFile);
	permissionTime *= 1000;
	g_HookManager.WriteMemoryDWORD(0x62D227, permissionTime);

	g_TeamAbnormal = GetPrivateProfileInt(sectionName, _T("TeamAbnormal"), 0, g_ConfigFile);
	g_ReplaceHostileAbnormal = GetPrivateProfileInt(sectionName, _T("ReplaceHostileAbnormal"), TRUE, g_ConfigFile);
	g_CelestialDisAggro = GetPrivateProfileInt(sectionName, _T("CelestialDisAggro"), TRUE, g_ConfigFile);
	


	g_FrenzyDamageMultipler = GetPrivateProfileDouble(_T("NpcMod"), _T("FrenzyDamageMultipler"), 1.0, g_ConfigFile);
	g_FrenzyDamageRaidBoss = GetPrivateProfileInt(_T("NpcMod"), _T("FrenzyDamageRaidBoss"), FALSE, g_ConfigFile);
	g_FrenzyDamageZZoldagu = GetPrivateProfileInt(_T("NpcMod"), _T("FrenzyDamageZZoldagu"), FALSE, g_ConfigFile);

	g_FrenzyTopDamage = GetPrivateProfileDouble(_T("NpcMod"), _T("FrenzyTopDamage"), 1.0, g_ConfigFile);



	g_FrenzyDamageNpcs.clear();
	if(GetPrivateProfileString(_T("NpcMod"), _T("FrenzyDamageNpcList"), 0, temp, 0x8000, g_ConfigFile))
	{
		wstringstream npcStream(temp);
		wstring npcName;
		while(npcStream >> npcName)
		{
			INT32 npcId = g_ObjectDB.GetClassIdFromName(npcName.c_str());
			if(npcId > 0)
			{
				g_FrenzyDamageNpcs.push_back(npcId);
			}			
		}
	}

	g_HealResistNpc.clear();
	if(GetPrivateProfileString(_T("NpcMod"), _T("HealResistNpcList"), 0, temp, 0x8000, g_ConfigFile))
	{
		wstringstream npcStream(temp);
		wstring npcName;
		while(npcStream >> npcName)
		{
			INT32 npcId = g_ObjectDB.GetClassIdFromName(npcName.c_str());
			if(npcId > 0)
			{
				g_HealResistNpc.push_back(npcId);
			}			
		}
	}


	g_Log.Add(CLog::Blue, "[%s] Loaded [L2Server]->ToggleSkillSystem.", __FUNCTION__);

	g_Log.Add(CLog::Blue, "[%s] Loaded [SkillFactory]->TeamAbnormal.", __FUNCTION__);
	g_Log.Add(CLog::Blue, "[%s] Loaded [SkillFactory]->ReplaceHostileAbnormal.", __FUNCTION__);
	g_Log.Add(CLog::Blue, "[%s] Loaded [SkillFactory]->CelestialDisAggro.", __FUNCTION__);
	g_Log.Add(CLog::Blue, "[%s] Loaded [%d] [SkillFactory]->BlockBuffException.", __FUNCTION__, g_BlockBuffException.size());
	g_Log.Add(CLog::Blue, "[%s] Loaded [%d] [SkillFactory]->AntiBuffException.", __FUNCTION__, g_AntiBuffException.size());
	g_Log.Add(CLog::Blue, "[%s] Loaded [%d] [SkillFactory]->BlockDebuffException.", __FUNCTION__, g_BlockDebuffException.size());

	g_Log.Add(CLog::Blue, "[%s] Loaded [NpcMod]->BossPvPFlag.", __FUNCTION__);
	g_Log.Add(CLog::Blue, "[%s] Loaded [NpcMod]->FrenzyDamageMultipler.", __FUNCTION__);
	g_Log.Add(CLog::Blue, "[%s] Loaded [NpcMod]->FrenzyDamageRaidBoss.", __FUNCTION__);
	g_Log.Add(CLog::Blue, "[%s] Loaded [NpcMod]->FrenzyDamageZZoldagu.", __FUNCTION__);
	g_Log.Add(CLog::Blue, "[%s] Loaded [NpcMod]->FrenzyTopDamage.", __FUNCTION__);
	g_Log.Add(CLog::Blue, "[%s] Loaded [%d] [NpcMod]->FrenzyDamageNpcList.", __FUNCTION__, g_FrenzyDamageNpcs.size());
	g_Log.Add(CLog::Blue, "[%s] Loaded [%d] [NpcMod]->HealResistNpcList.", __FUNCTION__, g_HealResistNpc.size());
	g_Log.Add(CLog::Blue, "[%s] Loaded [%d] [NpcMod]->BossIgnoreSkillList.", __FUNCTION__, g_BossIgnoreSkills.size());
	g_Log.Add(CLog::Blue, "[%s] Loaded [%d] [NpcMod]->BossPvPFlagException.", __FUNCTION__, g_BossPvPFlagException.size());
}



void CreatureAction::Initialize()
{
	for(int n=0;n<26;n++)
	{
		g_Harvester[n] = 0;
	}
	g_HookManager.WriteCall( 0x8C18A1, CWorld_PickItem, 0);
	g_HookManager.WriteCall( 0x8C19D9, CWorld_PickItem, 0);
	g_HookManager.WriteCall( 0x8C1A58, CWorld_PickItem, 0);

	g_HookManager.WriteCall( 0x575EE9, OnInitializeSkillMod, 0);
	g_HookManager.WriteCall( 0x518B58, OnInitializeSkillMod, 0);
	g_HookManager.WriteCall( 0x518246, OnInitializeSkillMod, 0);
	g_HookManager.WriteCall( 0x4FFB5B, OnInitializeSkillMod, 0);
	g_HookManager.WriteCall( 0x851D23, OnInitializeSkillMod, 0);
	g_HookManager.WriteCall( 0x42571B, OnInfectedSkillBy, 0);
	g_HookManager.WriteCall( 0x4257C6, OnInfectedSkillBy, 0);
	g_HookManager.WriteCall( 0x798D52, OnInfectedSkillBy, 0);
	g_HookManager.WriteCall( 0x798E9C, OnInfectedSkillBy, 0);
	g_HookManager.WriteCall( 0x7992CF, OnInfectedSkillBy, 0);
	g_HookManager.WriteCall( 0x799444, OnInfectedSkillBy, 0);
	g_HookManager.WriteCall( 0x7995CF, OnInfectedSkillBy, 0);
	g_HookManager.WriteCall( 0x7996E2, OnInfectedSkillBy, 0);
	g_HookManager.WriteMemoryDWORD(0x989570, (DWORD)OnGotDamageBy);
	g_HookManager.WriteMemoryDWORD(0x9B0EB0, (DWORD)OnGotDamageBy);
	g_HookManager.WriteMemoryDWORD(0xA1B1B0, (DWORD)OnGotDamageBy);
	g_HookManager.WriteMemoryDWORD(0xA28FD0, (DWORD)OnGotDamageBy);
	g_HookManager.WriteMemoryDWORD(0xA4AD00, (DWORD)OnGotDamageBy);
	g_HookManager.WriteMemoryDWORD(0xA4B670, (DWORD)OnGotDamageBy);
	g_HookManager.WriteMemoryDWORD(0xA877B0, (DWORD)OnGotDamageBy);
	g_HookManager.WriteMemoryDWORD(0xAA0FC0, (DWORD)OnGotDamageBy);

	g_HookManager.WriteMemoryDWORD( 0x989578, (DWORD)OnAttackedBy);
	g_HookManager.WriteMemoryDWORD( 0x9B0EB8, (DWORD)OnAttackedBy);
	g_HookManager.WriteMemoryDWORD( 0xA1B1B8, (DWORD)OnAttackedBy);
	g_HookManager.WriteMemoryDWORD( 0xA28FD8, (DWORD)OnAttackedBy);
	g_HookManager.WriteMemoryDWORD( 0xA4AD08, (DWORD)OnAttackedBy);
	g_HookManager.WriteMemoryDWORD( 0xA4B678, (DWORD)OnAttackedBy);
	g_HookManager.WriteMemoryDWORD( 0xA877B8, (DWORD)OnAttackedBy);
	g_HookManager.WriteMemoryDWORD( 0xAA0FC8, (DWORD)OnAttackedBy);

	g_HookManager.WriteCall( 0x46B0B3, OnActivateSkill, 0);
	g_HookManager.WriteCall( 0x696BCD, OnActivateSkill, 0);
	g_HookManager.WriteCall( 0x696C6F, OnActivateSkill, 0);
	g_HookManager.WriteCall( 0x4EC9DA, OnActivateSkill, 0);
	g_HookManager.WriteCall( 0x4FA1A4, OnActivateSkill, 0);
	g_HookManager.WriteCall( 0x5B05F1, OnActivateSkill, 0);
	g_HookManager.WriteCall( 0x5B06F2, OnActivateSkill, 0);
	g_HookManager.WriteCall( 0x7073C2, OnActivateSkill, 0);
	g_HookManager.WriteCall( 0x6B873E, OnActivateSkill, 0);
	g_HookManager.WriteCall( 0x6B89C2, OnActivateSkill, 0);
	g_HookManager.WriteCall( 0x6B8DF9, OnActivateSkill, 0);
	g_HookManager.WriteCall( 0x802677, OnActivateSkill, 0);
	g_HookManager.WriteCall( 0x5177E1, OnValidateAttachedSkills, 0);
	g_HookManager.WriteCall( 0x519DEC, OnValidateSetItem, 0);
	g_HookManager.WriteCall( 0x6C5F0E, OnTimerExpired, 0);
	g_HookManager.WriteCall( 0x845146, OnTimerExpired, 0);
	g_HookManager.WriteMemoryDWORD(0x9B0930, (DWORD)OnTimerExpired);
	g_HookManager.WriteCall( 0x6A2F0F, OnBroadcastMagicSkillLanuched, 0);
	g_HookManager.WriteCall( 0x6986CD, OnAttackCheckItemSkill, 0);
	g_HookManager.WriteCall( 0x698703, OnAttackCheckItemSkill, 0);
	g_HookManager.WriteCall( 0x6987B3, OnAttackCheckItemSkill, 0);
	g_HookManager.WriteCall( 0x69888E, OnAttackCheckItemSkill, 0);
	g_HookManager.WriteCall( 0x6CAE5E, OnCreatureConstruction, 0);
 	g_HookManager.WriteCall( 0x84ABF4, OnCreatureConstruction, 0);
	g_HookManager.WriteCall( 0x6BED7B, OnCreatureConstructionOther, 0);
	g_HookManager.WriteCall( 0x4D7473, OnCreatureDestruction, 0);
	g_HookManager.WriteCall( 0x6BECA5, OnCreatureDestruction, 0);
	g_HookManager.WriteCall( 0x6BB38D, OnCreatureDestruction, 0);
	g_HookManager.WriteCall( 0x6CAFFD, OnCreatureDestruction, 0);
	g_HookManager.WriteCall( 0x84C270, OnCreatureDestruction, 0);
	g_HookManager.WriteCall( 0x84CBB0, OnCreatureDestruction, 0);
	g_HookManager.WriteCall( 0x6BF0A0, OnCreatureDestruction, 0);
	g_HookManager.WriteCall( 0x6BED0D, OnCreatureDestruction, 0);
	g_HookManager.WriteJump( 0x84CB95, OnCreatureDestruction, 0);
	g_HookManager.WriteJump( 0x6BB36C, OnCreatureDestruction, 0);
	g_HookManager.WriteCall( 0x6A485D, OnDoNothing, 0);
	g_HookManager.WriteCall( 0x517F6B, OnValidateBaseData, 0);
	//i_backstab::instant
	g_HookManager.WriteCall( 0x7AF269, OnIsShieldDefend, 0);
	//i_energy_attack::instant
	g_HookManager.WriteCall( 0x7AD4DE, OnIsShieldDefend, 0);
	//i_fatal_blow::instant
	g_HookManager.WriteCall( 0x7A7B72, OnIsShieldDefend, 0);
	//i_p_attack::instant
	g_HookManager.WriteCall( 0x7A6811, OnIsShieldDefend, 0);
	//i_p_attack_overhit::instant
	g_HookManager.WriteCall( 0x7A7003, OnIsShieldDefend, 0);
	//i_physical_attack_hp_link::instant
	g_HookManager.WriteCall( 0x7B4131, OnIsShieldDefend, 0);
	g_HookManager.WriteCall(0x6B55E4, OnGetSkillUsedTime, 0);
	g_HookManager.WriteCall(0x6B338C, OnGetSkillUsedTime, 0);
	g_HookManager.WriteCall(0x8733FC, OnGetSkillUsedTime, 0);
	g_HookManager.WriteCall(0x873076, OnGetSkillUsedTime, 0);
	g_HookManager.WriteCall(0x870E05, OnGetSkillUsedTime, 0);
	g_HookManager.WriteCall(0x870A7D, OnGetSkillUsedTime, 0);
	g_HookManager.WriteCall(0x874E88, OnGetSkillUsedTime, 0);
	g_HookManager.WriteCall(0x87551E, OnGetSkillUsedTime, 0);
	g_HookManager.WriteCall(0x84DE4A, OnGetSkillUsedTime, 0);
	g_HookManager.WriteCall(0x837DCD, OnGetSkillUsedTime, 0);
	g_HookManager.WriteCall(0x82D0B8, OnGetSkillUsedTime, 0);
	g_HookManager.WriteCall(0x845BB5, OnGetSkillUsedTime, 0);
	g_HookManager.WriteCall(0x575F7B, OnSetSkillUsableTime, 0);
	g_HookManager.WriteCall(0x46A846, OnSetSkillUsableTime, 0);
	g_HookManager.WriteCall(0x495375, OnSetSkillUsableTime, 0);
	g_HookManager.WriteCall(0x495436, OnSetSkillUsableTime, 0);
	g_HookManager.WriteCall(0x46A5B8, OnSetSkillUsableTime, 0);
	g_HookManager.WriteCall(0x46A3E0, OnSetSkillUsableTime, 0);
	g_HookManager.WriteCall(0x5715D8, OnSetSkillUsableTime, 0);
	//casting a skill
	g_HookManager.WriteCall(0x6B5FFE, OnSetSkillUsableTime2, 0);
	g_HookManager.WriteCall(0x6B363F, OnSetSkillUsableTime2, 0);
	g_HookManager.WriteCall(0x4F9FC8, OnSetItemUsableTime, 0);
	g_HookManager.WriteCall(0x4F9EF4, OnGetItemUsedTime, 0);
	g_HookManager.WriteCall(0x6B3E5E, IsValidTarget, 0);
	//only timer
	g_HookManager.WriteCall(0x50F3E3, OnDeleteAbnormalStatus, 0);
	
	//UpdateSP from  CContributeData::Distribute
	g_HookManager.WriteCall(0x6F74B4, OnUpdateSP, 0);
	g_HookManager.WriteCall(0x6F8A60, OnUpdateSP, 0);	//Summon ?
	g_HookManager.WriteCall(0x6F8E6F, OnUpdateSP, 0);
	g_HookManager.WriteCall(0x6F7380, OnUpdateSP, 0);
	g_HookManager.WriteCall(0x6F73F6, OnUpdateSP, 0);	//Pet ?

	g_HookManager.WriteCall(0x7FF523, CreatureAction::ExpInc, 0);		//In User::ExpInc
	g_HookManager.WriteMemoryDWORD(0x9892E8, (DWORD)CreatureAction::ExpInc);	//CBoss
	g_HookManager.WriteMemoryDWORD(0x9B0C28, (DWORD)CreatureAction::ExpInc);	//CCreature
	g_HookManager.WriteMemoryDWORD(0xA1AF28, (DWORD)CreatureAction::ExpInc);	//CMerchant
	g_HookManager.WriteMemoryDWORD(0xA28D48, (DWORD)CreatureAction::ExpInc);	//CNpc
	g_HookManager.WriteMemoryDWORD(0xA4AA78, (DWORD)CreatureAction::ExpInc);	//CSummon
	g_HookManager.WriteMemoryDWORD(0xA4B3E8, (DWORD)CreatureAction::ExpInc);	//CPet
	g_HookManager.WriteMemoryDWORD(0xAA0D38, (DWORD)CreatureAction::ExpInc);	//CZZoldagu

	g_HookManager.WriteCall(0x80E7F8, CreatureAction::UseItem, 0);

	g_HookManager.WriteCall(0x4A7D6C, CreatureAction::OnDeleteItemInInventory, 0);
	g_HookManager.WriteCall(0x50E01C, CreatureAction::OnDeleteItemInInventory, 0);
	g_HookManager.WriteCall(0x6354F5, CreatureAction::OnDeleteItemInInventory, 0);
	g_HookManager.WriteCall(0x63557F, CreatureAction::OnDeleteItemInInventory, 0);
	g_HookManager.WriteCall(0x6B5CD7, CreatureAction::OnDeleteItemInInventory, 0);
	g_HookManager.WriteCall(0x6B5DEB, CreatureAction::OnDeleteItemInInventory, 0);
	g_HookManager.WriteCall(0x6BC7CB, CreatureAction::OnDeleteItemInInventory, 0);
	g_HookManager.WriteCall(0x6D984C, CreatureAction::OnDeleteItemInInventory, 0);
	g_HookManager.WriteCall(0x79F7E0, CreatureAction::OnDeleteItemInInventory, 0);
	g_HookManager.WriteCall(0x80AB8D, CreatureAction::OnDeleteItemInInventory, 0);
	g_HookManager.WriteCall(0x84E328, CreatureAction::OnDeleteItemInInventory, 0);
	g_HookManager.WriteCall(0x866449, CreatureAction::OnDeleteItemInInventory, 0);

	g_HookManager.WriteMemoryDWORD(0xAD8980, (DWORD)CreatureAction::OnIHarvestingEffect);

	g_HookManager.WriteCall(0x6B089D, CreatureAction::ActionBroadcastSkillCancelled, 0);
	g_HookManager.WriteCall(0x6B0A21, CreatureAction::ActionBroadcastSkillCancelled, 0);
	g_HookManager.WriteCall(0x6B0E09, CreatureAction::ActionBroadcastSkillCancelled, 0);
	g_HookManager.WriteCall(0x6B1A23, CreatureAction::ActionBroadcastSkillCancelled, 0);
	g_HookManager.WriteCall(0x6B752E, CreatureAction::ActionBroadcastSkillCancelled, 0);
	g_HookManager.WriteCall(0x6B76AC, CreatureAction::ActionBroadcastSkillCancelled, 0);

//	g_HookManager.WriteCall(0x6B801C, CreatureAction::ActionBroadcastSkillLanuched, 0);	//multiple target
//	g_HookManager.WriteCall(0x6B805E, CreatureAction::ActionBroadcastSkillLanuchedEx, 0);	//solo

	g_HookManager.WriteCall(0x6985D8, CreatureAction::TurnOffSoulshot);
	g_HookManager.WriteCall(0x6B8C17, CreatureAction::TurnOffSoulshot);
	g_HookManager.WriteCall(0x707A28, CreatureAction::TurnOffSoulshot);
	g_HookManager.WriteCall(0x707A78, CreatureAction::TurnOffSoulshot);
	g_HookManager.WriteCall(0x7A69DF, CreatureAction::TurnOffSoulshot);
	g_HookManager.WriteCall(0x7A71D3, CreatureAction::TurnOffSoulshot);
	g_HookManager.WriteCall(0x7A7C88, CreatureAction::TurnOffSoulshot);
	g_HookManager.WriteCall(0x7AD671, CreatureAction::TurnOffSoulshot);
	g_HookManager.WriteCall(0x7AF519, CreatureAction::TurnOffSoulshot);
	g_HookManager.WriteCall(0x7B42FF, CreatureAction::TurnOffSoulshot);
	g_HookManager.WriteCall(0x826288, CreatureAction::TurnOffSoulshot);
	g_HookManager.WriteCall(0x826C65, CreatureAction::TurnOffSoulshot);

	g_HookManager.WriteCall(0x696BEB, CreatureAction::TurnOffSpiritshot);
	g_HookManager.WriteCall(0x696C8D, CreatureAction::TurnOffSpiritshot);
	g_HookManager.WriteCall(0x6B8C3A, CreatureAction::TurnOffSpiritshot);
	g_HookManager.WriteCall(0x707A31, CreatureAction::TurnOffSpiritshot);
	g_HookManager.WriteCall(0x707A89, CreatureAction::TurnOffSpiritshot);
	g_HookManager.WriteCall(0x8262DC, CreatureAction::TurnOffSpiritshot);
	g_HookManager.WriteCall(0x826CB8, CreatureAction::TurnOffSpiritshot);

	g_HookManager.WriteMemoryDWORD(0x989590, reinterpret_cast<UINT>(CreatureAction::SkillAction));
	g_HookManager.WriteMemoryDWORD(0x9B0ED0, reinterpret_cast<UINT>(CreatureAction::SkillAction));
	g_HookManager.WriteMemoryDWORD(0xA1B1D0, reinterpret_cast<UINT>(CreatureAction::SkillAction));
	g_HookManager.WriteMemoryDWORD(0xA28FF0, reinterpret_cast<UINT>(CreatureAction::SkillAction));
	g_HookManager.WriteMemoryDWORD(0xA4AD20, reinterpret_cast<UINT>(CreatureAction::SkillAction));
	g_HookManager.WriteMemoryDWORD(0xA4B690, reinterpret_cast<UINT>(CreatureAction::SkillAction));
	g_HookManager.WriteMemoryDWORD(0xA877D0, reinterpret_cast<UINT>(CreatureAction::SkillAction));
	g_HookManager.WriteMemoryDWORD(0xAA0FE0, reinterpret_cast<UINT>(CreatureAction::SkillAction));

	g_HookManager.WriteCall(0x6A1517, CreatureAction::CheckAttackValidity);
	
	g_HookManager.WriteMemoryDWORD(0xA22150, reinterpret_cast<UINT>(CreatureAction::AttackActionOnStart));
	g_HookManager.WriteMemoryDWORD(0xA25900, reinterpret_cast<UINT>(CreatureAction::SkillActionOnStart));
	g_HookManager.WriteMemoryDWORD(0xA25908, reinterpret_cast<UINT>(CreatureAction::SkillActionOnTick));
//	g_HookManager.WriteMemoryDWORD(0xA220F0, reinterpret_cast<UINT>(CreatureAction::MoveActionOnStart));
//	g_HookManager.WriteMemoryDWORD(0xA22390, reinterpret_cast<UINT>(CreatureAction::MoveActionExOnStart));

	//CCreature::GatherNeighborCreatureByPoint
	g_HookManager.WriteCall(0x5072F7, CreatureAction::GatherIsActive, 4);
	//CCreature::GatherNeighborPledge
	g_HookManager.WriteCall(0x50952D, CreatureAction::GatherIsNotActive, 4);
	g_HookManager.WriteCall(0x509546, CreatureAction::GatherIsActive, 4);
	//CCreature::GatherNeighborCreature
	g_HookManager.WriteCall(0x508054, CreatureAction::GatherIsActive, 4);
	//CCreature::GatherNeighborCreatureEx
	g_HookManager.WriteCall(0x50CE63, CreatureAction::GatherIsActive, 4);
	//CCreature::GatherNeighborParty
	g_HookManager.WriteCall(0x508901, CreatureAction::GatherIsActive, 4);
	//GatherNeighborCreatureSquare
	g_HookManager.WriteCall(0x50BF3C, CreatureAction::GatherIsActive, 4);
}

bool CreatureAction::GatherIsNotActive(CCreature *pCreature)
{
	UINT64 addr = (*(PUINT64)pCreature);
	addr += 0x250;
	addr = (*(PUINT64)addr);

	typedef bool (*f)(CCreature*);
	bool ret = f((PVOID)addr)(pCreature);

	if(!ret)
	{
		UINT threadIndex = GetThreadIndex();
		if(threadIndex < 16)
		{
			const CSkillInfo *pSI = g_SkillOnTickSkillInfo[threadIndex];
			if(pSI)
			{
				if(pSI->nGeodataCheck)
				{
					if(CCreature *pCaster = g_SkillOnTickCaster[threadIndex]->SafeCastCreature())
					{
						if(!CGeo::GetInstance()->CanSee(&pCaster->pSD->Pos, &pCreature->pSD->Pos))
						{
						//	g_Log.Add(LogBlue, "[%s] Cannot see creature[%S] - caster[%S]", __FUNCTION__, pCreature->pSD->wName, pCaster->pSD->wName);
							ret = true;
						}
					}
				}else if(User *pUser = pCreature->SafeCastUser())
				{
					if(CCreature *pCaster = g_SkillOnTickCaster[threadIndex]->SafeCastCreature())
					{
						/*
						UINT territoryId = pUser->pSD->pExData->territoryData.territoryId[SKILL_GEODATA_CHECK_ZONE];
						if(territoryId > 0)
						{
							if(CSkillGeodataCheckTerritory *pTerritory = g_TerritoryChecker.GetTerritory(territoryId)->SafeCastSkillGeodataCheck())
							{
								if(pTerritory->IsAffected(pSI->nSkillID))
								{
									if(!CGeo::GetInstance()->CanSee(&pCaster->pSD->Pos, &pCreature->pSD->Pos))
									{
									//	g_Log.Add(LogBlue, "[%s] Cannot see creature[%S] - caster[%S]", __FUNCTION__, pCreature->pSD->wName, pCaster->pSD->wName);
										ret = true;
									}
								}
							}
						}*/
					}
				}
			}
		}
	}

	return ret;
}


//TENGO ERRORES CON LA POLE Y g_AttackOnTickAttaker
/* bool CreatureAction::GatherIsActive(CCreature *pCreature)
{
	UINT64 addr = (*(PUINT64)pCreature);
	addr += 0x250;
	addr = (*(PUINT64)addr);

//	g_Log.Add(LogBlue, "[%s] test[%d]", __FUNCTION__, 1);

	typedef bool (*f)(CCreature*);
	bool ret = f((PVOID)addr)(pCreature);

	if(ret)
	{
//		g_Log.Add(LogBlue, "[%s] test[%d]", __FUNCTION__, 2);
		UINT threadIndex = GetThreadIndex();
		if(threadIndex < 16)
		{
			if(g_AttackOnTickAttaker[threadIndex] && pCreature->SafeCastUser())
			{
				//g_Log.Add(CLog::Error, "[%s] pCreature->SafeCastUser()[%S] !", __FUNCTION__, pCreature->SafeCastUser()->pSD->wszName);
		//		if(!pCreature->SafeCastUser()->pSD->nPvPAttackTimeStamp)
		//		{
					ret = false;
					//g_AttackOnTickAttaker[threadIndex] = 0;
					//g_Log.Add(CLog::Error, "[%s] test[%d]", __FUNCTION__, 3);
		//		}
			}

//			g_Log.Add(LogBlue, "[%s] test[%d]", __FUNCTION__, 3);
			const CSkillInfo *pSI = g_SkillOnTickSkillInfo[threadIndex];
			if(pSI)
			{
				bool bMassSweep = false;
				if(pSI->nSkillID == 444)
					bMassSweep = true;

				if(pCreature->ValidCreature() && pCreature->IsMob())
					if(bMassSweep)
						ret = false;

//				g_Log.Add(LogBlue, "[%s] test[%d]", __FUNCTION__, 4);
				if(pSI->nGeodataCheck)
				{
//					g_Log.Add(LogBlue, "[%s] test[%d]", __FUNCTION__, 5);
					if(CCreature *pCaster = g_SkillOnTickCaster[threadIndex]->SafeCastCreature())
					{
//						g_Log.Add(LogBlue, "[%s] test[%d]", __FUNCTION__, 6);
//						g_Log.Add(LogBlue, "[%s] caster[%S] target[%S]", __FUNCTION__, pCaster->pSD->wName, pCreature->pSD->wName);
						if(!CGeo::GetInstance()->CanSee(&pCaster->pSD->Pos, &pCreature->pSD->Pos))
						{
						//	g_Log.Add(LogBlue, "[%s] Cannot see creature[%S] - caster[%S]", __FUNCTION__, pCreature->pSD->wName, pCaster->pSD->wName);
							ret = false;
						}

						
					}
				}else if(User *pUser = pCreature->SafeCastUser())
				{
					if(CCreature *pCaster = g_SkillOnTickCaster[threadIndex]->SafeCastCreature())
					{

					}
				}
			}
		}
	}
	else
	{
		UINT threadIndex = GetThreadIndex();
		if(threadIndex < 16)
		{
			const CSkillInfo *pSI = g_SkillOnTickSkillInfo[threadIndex];
			if(pSI)
			{
				bool bMassSweep = false;
				if(pSI->nSkillID == 444)
				{
					if(pCreature->ValidCreature() && pCreature->IsMob())
						ret = true;
				}
			}
		}
	}

	return ret;
}*/



bool CreatureAction::GatherIsActive(CCreature *pCreature)
{
	UINT64 addr = (*(PUINT64)pCreature);
	addr += 0x250;
	addr = (*(PUINT64)addr);

//	g_Log.Add(LogBlue, "[%s] test[%d]", __FUNCTION__, 1);

	typedef bool (*f)(CCreature*);
	bool ret = f((PVOID)addr)(pCreature);

	if(ret)
	{
//		g_Log.Add(LogBlue, "[%s] test[%d]", __FUNCTION__, 2);
		UINT threadIndex = GetThreadIndex();
		if(threadIndex < 16)
		{
//			g_Log.Add(LogBlue, "[%s] test[%d]", __FUNCTION__, 3);
			const CSkillInfo *pSI = g_SkillOnTickSkillInfo[threadIndex];
			if(pSI)
			{
//				g_Log.Add(LogBlue, "[%s] test[%d]", __FUNCTION__, 4);
				if(pSI->nGeodataCheck)
				{
//					g_Log.Add(LogBlue, "[%s] test[%d]", __FUNCTION__, 5);
					if(CCreature *pCaster = g_SkillOnTickCaster[threadIndex]->SafeCastCreature())
					{
//						g_Log.Add(LogBlue, "[%s] test[%d]", __FUNCTION__, 6);
//						g_Log.Add(LogBlue, "[%s] caster[%S] target[%S]", __FUNCTION__, pCaster->pSD->wName, pCreature->pSD->wName);
						if(!CGeo::GetInstance()->CanSee(&pCaster->pSD->Pos, &pCreature->pSD->Pos))
						{
						//	g_Log.Add(LogBlue, "[%s] Cannot see creature[%S] - caster[%S]", __FUNCTION__, pCreature->pSD->wName, pCaster->pSD->wName);
							ret = false;
						}
					}
				}else if(User *pUser = pCreature->SafeCastUser())
				{
					if(CCreature *pCaster = g_SkillOnTickCaster[threadIndex]->SafeCastCreature())
					{
						/*
						UINT territoryId = pUser->pSD->pExData->territoryData.territoryId[SKILL_GEODATA_CHECK_ZONE];
						if(territoryId > 0)
						{
							if(CSkillGeodataCheckTerritory *pTerritory = g_TerritoryChecker.GetTerritory(territoryId)->SafeCastSkillGeodataCheck())
							{
								if(pTerritory->IsAffected(pSI->nSkillID))
								{
									if(!CGeo::GetInstance()->CanSee(&pCaster->pSD->Pos, &pCreature->pSD->Pos))
									{
									//	g_Log.Add(LogBlue, "[%s] Cannot see creature[%S] - caster[%S]", __FUNCTION__, pCreature->pSD->wName, pCaster->pSD->wName);
										ret = false;
									}
								}
							}
						}*/
					}
				}
			}
		}
	}

	return ret;
}



bool CreatureAction::SkillActionOnTick(CSkillAction *pAction)
{
	CTL;

	UINT threadIndex = GetThreadIndex();
	if(threadIndex < 16)
	{
		if(CObject *pTO = pAction->GetTarget())
		{
			if(pTO->IsValid(VT_CDOOR))
			{
				g_DoorInActionTarget[threadIndex] = TRUE;
			}
		}
		if(CCreature *pCaster = pAction->GetCaster()->SafeCastCreature())
		{
			g_SkillOnTickCaster[threadIndex] = pCaster;
			g_SkillOnTickSkillInfo[threadIndex] = pAction->GetSkillInfo();
		}
	}

/*	if(User *pUser = pAction->GetCaster()->SafeCastUser())
	{
		g_Log.Add(CLog::Blue, "[%s] User[%S] tick[%d] state[%d]", __FUNCTION__, pUser->pSD->wszName, GetTickCount(), pAction->GetState());
	} */
	bool ret = false;
	typedef bool (*f)(CSkillAction*);
	ret = f(0x6B70F0L)(pAction);

	if(threadIndex < 16)
	{
		g_DoorInActionTarget[threadIndex] = FALSE;
		g_SkillOnTickCaster[threadIndex] = 0;
		g_SkillOnTickSkillInfo[threadIndex] = 0;
	}

	return ret;
}

bool CreatureAction::SkillActionOnStart(CSkillAction *pAction)
{
	CTL;

	UINT threadIndex = GetThreadIndex();
	if(threadIndex < 16)
	{
		if(CObject *pTO = pAction->GetTarget())
		{
			if(pTO->IsValid(VT_CDOOR))
			{
				g_DoorInActionTarget[threadIndex] = TRUE;
			}
		}
		if(CCreature *pCaster = pAction->GetCaster()->SafeCastCreature())
		{
			g_SkillOnTickCaster[threadIndex] = pCaster;
			g_SkillOnTickSkillInfo[threadIndex] = pAction->GetSkillInfo();
		}
	}
	
	typedef bool (*f)(CSkillAction*);
	bool ret = f(0x6B28F0L)(pAction);

	if(threadIndex < 16)
	{
		g_DoorInActionTarget[threadIndex] = FALSE;
		g_SkillOnTickCaster[threadIndex] = 0;
		g_SkillOnTickSkillInfo[threadIndex] = 0;
	}

	return ret;
}

bool CreatureAction::MoveActionExOnStart(CMoveActionEx *pAction)
{
	CTL;

	bool ret = false;

	if(g_DoorData.IsEnabled())
	{
		if(CCreature *pCreature = pAction->GetCreature()->SafeCastCreature())
		{
			if(CCreature *pTarget = pAction->GetTarget()->SafeCastCreature())
			{
				if(!g_DoorData.CanSee(pCreature->pSD->Pos, pTarget->pSD->Pos))
				{
					if(User *pUser = pCreature->SafeCastUser())
					{
						pUser->ActionFailed();
			//			g_Log.Add(CLog::Blue, "[%s] moving creature[%S] to [%f][%f][%f] blocked!", __FUNCTION__, pCreature->pSD->wszName, pTarget->pSD->Pos.x, pTarget->pSD->Pos.y, pTarget->pSD->Pos.z);
					}
				
					return false;
				}
			}
		}
	}

	typedef bool (*f)(CMoveActionEx*);
	ret = f(0x6AC0A0L)(pAction);


	return ret;
}

bool CreatureAction::MoveActionOnStart(CMoveAction *pAction)
{
	CTL;

	bool ret = false;

	if(g_DoorData.IsEnabled())
	{
		if(CCreature *pCreature = pAction->GetCreature()->SafeCastCreature())
		{
			if(!g_DoorData.CanSee(pCreature->pSD->Pos, pAction->GetDestination()))
			{
				if(User *pUser = pCreature->SafeCastUser())
				{
					pUser->ActionFailed();
			//		g_Log.Add(CLog::Blue, "[%s] moving creature[%S] to [%f][%f][%f] blocked!", __FUNCTION__, pCreature->pSD->wszName, pAction->GetDestination().x, pAction->GetDestination().y, pAction->GetDestination().z);
				}
			
				return false;
			}
		}
	}

	typedef bool (*f)(CMoveAction*);
	ret = f(0x6AC4E0L)(pAction);


	return ret;
}

bool CreatureAction::AttackActionOnStart(CAttackAction *pAction)
{
	CTL;

	UINT threadIndex = GetThreadIndex();
	if(threadIndex < 16)
	{
		if(pAction->GetWeaponType() != WeaponBow && g_DoorData.IsEnabled() && g_DoorData.IsAffectCloseCombat())
		{
			if(CCreature *pCreature = pAction->GetAttacker()->SafeCastCreature())
			{
				if(CObject *pTO = pAction->GetTarget())
				{
					if(pTO->IsValid(VT_CDOOR))
					{
						g_DoorInActionTarget[threadIndex] = TRUE;
					}else if(CCreature *pTarget = pTO->SafeCastCreature())
					{
						if(!g_DoorData.CanSee(pCreature->pSD->Pos, pTarget->pSD->Pos))
						{
							pAction->SetTarget(0);
							if(User *pUser = pCreature->SafeCastUser())
							{
								//cannot see target
								pUser->pSocket->SendSystemMessage(181);
							}
						}
					}
				}
			}
		}


			//g_Log.Add(CLog::Error, "[%s]111111111111", __FUNCTION__);
			if(CCreature *pCreature = pAction->GetAttacker()->SafeCastCreature())
			{
				//g_Log.Add(CLog::Error, "[%s]22222222222222", __FUNCTION__);
				if(User *pAttacker = pCreature->SafeCastUser())
				{

					//g_Log.Add(CLog::Error, "[%s] User *pAttacker = pCreature->SafeCastUser()[%S] !", __FUNCTION__, pAttacker->pSD->wszName);
					//g_Log.Add(CLog::Error, "[%s]0000000000 [%d]", __FUNCTION__, pAction->GetWeaponType());
					if(pAttacker->pSD->nWeaponType == WeaponPole) //POLE 4
					{
						//g_Log.Add(CLog::Error, "[%s]33333333333333", __FUNCTION__);
						if(!pAction->GetTarget()->SafeCastUser())
						{
							g_AttackOnTickAttaker[threadIndex] = true;
							//g_Log.Add(CLog::Error, "[%s] User[%S] !", __FUNCTION__, pUser->pSD->wszName);
							//g_Log.Add(CLog::Error, "[%s] TARGET NO USER USER[%d]", __FUNCTION__, 1);
						}
						else
						{
					//		g_Log.Add(CLog::Error, "[%s] pAction->GetTarget()->SafeCastUser()[%S] !", __FUNCTION__, pAction->GetTarget()->SafeCastUser()->pSD->wszName);
							//g_Log.Add(CLog::Error, "[%s] TARGET USER[%d]", __FUNCTION__, 1);
							g_AttackOnTickAttaker[threadIndex] = false;
						}
					}
					else
					{
						g_AttackOnTickAttaker[threadIndex] = false;
					}
				}
				else
				{
					g_AttackOnTickAttaker[threadIndex] = false;
				}
			}
			else
			{
				g_AttackOnTickAttaker[threadIndex] = false;
			}
	}

	typedef bool (*f)(CAttackAction*);
	bool ret = f(0x6A0ED0L)(pAction);

	if(threadIndex < 16)
	{
		g_DoorInActionTarget[threadIndex] = FALSE;
	}

	return ret;
}


void CreatureAction::SkillAction(CCreature *pCreature, int skillId, bool force, bool inPlace, CItem *pItem)
{
	guard;

	if(skillId > 0)
	{
		int skillLevel = pCreature->GetAcquiredSkillLevel(skillId);
		if(skillLevel > 0)
		{
			if(CSkillInfo *pSI = g_SkillDB.GetSkillInfo(skillId, skillLevel))
			{
				if(pSI->operateType == OperateToggle && g_ToggleSkillSystem)
				{
					pCreature->ToggleSkillAction(skillId, skillLevel);
					unguard;
					return;
				}


				if (g_TvT.FortressGetSkill() == skillId)
				{
					int targetNpc = g_TvT.FortressGetNpcObject();

					if(targetNpc > 0)
					{
						if(targetNpc == pCreature->targetId)
						{
							force = true;
						}
						else
						{
							unguard;
							return;
						}
					}
					else
					{
						unguard;
						return;
					}
				}

				if(pSI->nEffectPoint < 0)
				{
					if(pCreature->targetId > 0)
					{
						if(User *pTarget = User::GetUserBySID(&pCreature->targetId))
						{
							if(pTarget->pED->antiPkLevelRange > 0 && pTarget->pSD->nKarma == 0 && pTarget->pSD->bGuilty == false)
							{
								User *pCaster = 0;
								if(pCreature->pSD->nIsPC)
								{
									pCaster = pCreature->SafeCastUser();
								}else if(pCreature->IsSummon() || pCreature->IsPet())
								{
									pCaster = pCreature->CastSummon()->GetMaster();
								}
								if(pCaster->ValidUser())
								{
									if( (pTarget->pSD->nLevel + pTarget->pED->antiPkLevelRange) < pCaster->pSD->nLevel )
									{
										//1996	1	a,The attack has been blocked.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
										CSystemMessage msg(1996);
										pCaster->SendSystemMessage(&msg);
										unguard;
										return;
									}
								}
							}
						}
					}
				}
			}
		}
	}



	typedef void(*f)(CCreature*, int, bool, bool, CItem*);
	f(0x4F1070L)(pCreature, skillId, force, inPlace, pItem);

	unguard;
}

void CreatureAction::TurnOffSpiritshot(CCreature *pCreature)
{
	guard;

	typedef void(*f)(CCreature*);
	f(0x4E7420L)(pCreature);

	if(g_InfinityShot.IsEnabled())
	{
		if(User *pUser = pCreature->SafeCastUser())
		{
			if(CSharedItemData *pWD = pUser->GetEquipedWeapon())
			{
				if(CItemInfo *pWI = pWD->GetItemInfo())
				{
					if(pUser->pED->autoInfinitySpiritshot[pWI->nCrystalType])
					{
						if(CItem *pShot = pUser->inventory.GetFirstItemByClassID(pUser->pED->autoInfinitySpiritshot[pWI->nCrystalType]))
						{
							g_InfinityShot.TurnOn(pUser, pShot);
						}else
						{
							g_InfinityShot.AutoOff(pUser, pUser->pED->autoInfinitySpiritshot[pWI->nCrystalType]);
						}
					}
				}
			}
		}
	}

	if( g_SpiritShotExtension )
	{
		if(User *pUser = pCreature->SafeCastUser())
		{
			if(CSharedItemData *pWD = pUser->GetEquipedWeapon())
			{
				if(CItemInfo *pWI = pWD->GetItemInfo())
				{
					if(pUser->pED->autoInfinitySpiritshot_2[pWI->nCrystalType])
					{
						if(CItem *pShot = pUser->inventory.GetFirstItemByClassID(pUser->pED->autoInfinitySpiritshot_2[pWI->nCrystalType]))
						{
							g_InfinityShot.TurnOn(pUser, pShot);
						}else
						{
							g_InfinityShot.AutoOff_Normal(pUser, pUser->pED->autoInfinitySpiritshot_2[pWI->nCrystalType]);
						}
					}
				}
			}
		}
	}

	unguard;
}

void CreatureAction::TurnOffSoulshot(CCreature *pCreature)
{
	guard;

	typedef void(*f)(CCreature*);
	f(0x4E6F30L)(pCreature);

	if(g_InfinityShot.IsEnabled())
	{
		if(User *pUser = pCreature->SafeCastUser())
		{
			if(CSharedItemData *pWD = pUser->GetEquipedWeapon())
			{
				if(CItemInfo *pWI = pWD->GetItemInfo())
				{
					if(pUser->pED->autoInfinitySoulshot[pWI->nCrystalType])
					{
						if(CItem *pShot = pUser->inventory.GetFirstItemByClassID(pUser->pED->autoInfinitySoulshot[pWI->nCrystalType]))
						{
							g_InfinityShot.TurnOn(pUser, pShot);
						}else
						{
							g_InfinityShot.AutoOff(pUser, pUser->pED->autoInfinitySoulshot[pWI->nCrystalType]);
						}
					}
				}
			}
		}
	}

	if( g_SpiritShotExtension )
	{
		if(User *pUser = pCreature->SafeCastUser())
		{
			if(CSharedItemData *pWD = pUser->GetEquipedWeapon())
			{
				if(CItemInfo *pWI = pWD->GetItemInfo())
				{
					if(pUser->pED->autoInfinitySoulshot_2[pWI->nCrystalType])
					{
						if(CItem *pShot = pUser->inventory.GetFirstItemByClassID(pUser->pED->autoInfinitySoulshot_2[pWI->nCrystalType]))
						{
							g_InfinityShot.TurnOn(pUser, pShot);
						}else
						{
							g_InfinityShot.AutoOff_Normal(pUser, pUser->pED->autoInfinitySoulshot_2[pWI->nCrystalType]);
						}
					}
				}
			}
		}
	}

	unguard;
}

void CreatureAction::OnIHarvestingEffect(LPVOID lpEffect, CCreature *pCaster, CCreature *pTarget, CSkillInfo *pSI, CSkillAction *pAction, double distance)
{
	guard;
	
	UINT threadIndex = GetThreadIndex();
	if(threadIndex < 26)
	{
		g_Harvester[threadIndex] = pCaster;
	}

	typedef void(*f)(LPVOID, CCreature*, CCreature*, CSkillInfo*, CSkillAction*, double );
	f(0x7D3860L)(lpEffect, pCaster, pTarget, pSI, pAction, distance);

	if(threadIndex < 26)
	{
		g_Harvester[threadIndex] = 0;
	}

	unguard;
}

bool CreatureAction::OnDeleteItemInInventory(CCreature *pCreature, INT32 itemId, INT32 count)
{
	guard;

	if(User *pUser = pCreature->GetUser())
	{
		if(pUser->IsNowTrade())
		{
			pUser->TradeCancel();
		}
	}

	typedef bool (*f)(CCreature*, INT32, INT32);
	bool ret = f(0x4EF8C0L)(pCreature, itemId, count);

	unguard;

	return ret;
}

void CreatureAction::OnActivateSkill(CSkillInfo *pSI, CCreature *pCreature, CCreature *pTarget, double dUnkn, INT64 nUnkn)
{
	typedef void (*_as)(CSkillInfo*, CObject*, CObject*, double, INT64);
	_as as = (_as) 0x00799000;

	if(pTarget->ValidCreature() && pCreature->ValidCreature())
	{
		if(pTarget->inPeaceZone && pCreature->pSD->nIsPC && pSI->nEffectPoint < 0)
		{
			if(pSI->AffectScope == CSkillInfo::AS_POINT_BLANK)
			{
				return;
			}
		}

		if(pTarget->IsBoss() || pTarget->IsZZoldagu())
		{
			SkillPchId sp(pSI->nSkillID, pSI->nLevel);
			for(UINT n=0;n<g_BossIgnoreSkills.size();n++)
			{
		//		g_Log.Add(CLog::Blue, "[%s] [%d] vs [%d]", __FUNCTION__, g_BossIgnoreSkills[n] , sp.skillId);
				if(g_BossIgnoreSkills[n] == sp.skillId)
				{
					return;
				}
			}
		}

		if(pTarget->IsSummon())
		{
			if(pCreature->nObjectID == pTarget->pSD->nMasterID)
			{
				if(pSI->operateType == OperateA2)
				{
					if(pSI->nDebuff == 1)
					{
						return; //cant debuff own summon
					}
				}
			}
		}

		if(g_TeamAbnormal && pSI->nEffectPoint < 0)
		{
			if(pCreature->IsSameAbnormalTeam(pTarget))
			{
				return;
			}
		}

		//Instat cast type check
		if(pSI->nInstantCastTime > 0)
		{
		//	g_Log.Add(CLog::Blue, "[%s] Instat Cast Type skill_id[%d] level[%d]", __FUNCTION__, pSI->nSkillID, pSI->nLevel);
			return;
		}

		CSkillInfoEx *pSDEx = g_SkillDBEx.GetSkillInfoEx(pSI->nSkillID, pSI->nLevel);
		if(pSDEx)
		{
			//Geodata Check
			if(pSI->nAffectRange > 0 && pSDEx->geoDataTest)
			{
				FVector Pos1;
				FVector Pos2;
				pCreature->GetPos(&Pos1);
				pTarget->GetPos(&Pos2);
				if(!CGeo::GetInstance()->CanSee(&Pos1, &Pos2))
				{
				//	g_Log.Add(CLog::Blue, "[%s] Cannot See Target[%S] Caster[%S]", __FUNCTION__, pTarget->pSD->wszName, pCreature->pSD->wszName);
					return;
				}
			}
		}
				
		if(pTarget->pSD->nIsPC && pTarget->pSD->pExData->SkillMod.nAvoidMeleeSkill && !pCreature->IsBoss() && !pCreature->IsZZoldagu())
		{
			//Check if it's melee skill and physical
			if(pSI->IsMeleeAtk())
				if(CSkillFx::PerformAvoidAttack(pTarget->GetUser(), pCreature))
					return;
		}
		if(pTarget->pSD->nCursedOwner && pCreature!=pTarget)
		{
			if(pSI->nEffectPoint > 0)
				return;
		}

		//TODO FACTION BLOCK MELEE ATTACK SKILLS & OL BUFFS[OK]
		if(pCreature->ValidUser() && pTarget->ValidUser())
		{
			if( (pTarget->pSD->pExData->territoryData.territoryId[FACTION_ZONE] != 0) && (pTarget->pSD->pExData->territoryData.territoryId[FACTION_ZONE] != 0) )
			{
				if(User *pUser = pCreature->GetUser())
				{
					if(User *pUserT = pTarget->GetUser())
					{
						if( pUser->pED->nFactionID == pUserT->pED->nFactionID )
						{
							if(pSI->IsMeleeAtk()) //Not working.. ?
							{
								pUser->SendSystemMessage(L"You cannot hit someone from same team!");
								return;	
							}

							//Extra Fix For Some Skills by Archers and etc...
							if(g_FactionSystem.SkillExist(pSI->nSkillID))
							{
								pUser->SendSystemMessage(L"You cannot hit someone from same team!");
								return;	
							}
						}
					}
				}
			}
		}

		if(pTarget->pSD->pExData->territoryData.territoryId[FACTION_ZONE])
		{
			if(pSI->AffectScope == CSkillInfo::AS_PLEDGE)
			{
				if(pTarget != pCreature)
					return;
			}
		}

		if(pTarget->pSD->pExData->territoryData.territoryId[EVENT_PVP_ZONE])
		{
			if(pSI->AffectScope == CSkillInfo::AS_PLEDGE)
			{
				if(pTarget != pCreature)
					return;
			}
		}



		if(pTarget->pSD->DuelInfo.DuelID != pCreature->pSD->DuelInfo.DuelID)
		{
			//interrupt duel
			if(pTarget->pSD->DuelInfo.DuelID)
			{
				g_DuelSystem.Interrupt(pTarget->pSD->DuelInfo.DuelID);
			}
			if(pCreature->pSD->DuelInfo.DuelID)
			{
				g_DuelSystem.Interrupt(pCreature->pSD->DuelInfo.DuelID);
			}
			return;
		}

		if(pTarget->pSD->pExData->territoryData.territoryId[NO_OL_BUFFS_ZONE])
		{
			if(pSI->AffectScope == CSkillInfo::AS_PLEDGE)
			{
				if(pTarget!=pCreature)
					return;
			}
		}

		//Fusion Attack Skills
		UINT nMasterID = pCreature->pSD->nMasterID;
		if(nMasterID && (pSI->nSkillID >= 5130 && pSI->nSkillID <= 5133))
		{
			User *pUser = User::GetUserBySID(&nMasterID);
			if(pUser->ValidUser())
			{
				switch(pSI->nSkillID)
				{
				case 5130:	//Volcano
				case 5131:	//Tsunami
				case 5132:	//Cyclone
				case 5133:	//Gehenna
					{
						if(pUser!=pTarget && !pUser->IsMyParty(pTarget))
						{
							as(pSI, pUser, pTarget, dUnkn, nUnkn);
						}
						pUser->TurnOffSpiritshot();
						return;
						break;
					}
				};
			}
		}
		
		pCreature->pSD->pExData->CastedSkill.skill_id = pSI->nSkillID;
		pCreature->pSD->pExData->CastedSkill.level = pSI->nLevel;
		if(pCreature->pSD->dSoulshotPower > 0)
			pCreature->pSD->pExData->SoulshotActivated = true;
	}
	
	as(pSI, pCreature, pTarget, dUnkn, nUnkn);

	if(User *pUser = pCreature->SafeCastUser())
	{
		if(pUser->pED->aioId)
		{
			if(g_AIOSystem.IsPartyBuff(pUser->pED->aioId, pSI->nSkillID, pSI->nLevel))
			{
				if(CParty *pParty = pUser->GetParty())
				{
					UserVector members;
					pParty->GetAllMembersEx(members);
					for(UINT n=0;n<members.size();n++)
					{
						if(User *pMember = members[n]->SafeCastUser())
						{
							if(pMember->nObjectID != pTarget->nObjectID)
							{
								if(pUser->IsInRange(pMember, 1500) && pMember->pSD->nAlive)
								{
									as(pSI, pCreature, pMember, dUnkn, nUnkn);
								}
							}
						}
					}
				}
			}
		}
	}

	if(pCreature->ValidCreature())
	{
		pCreature->pSD->pExData->CastedSkill.skill_id = 0;
		pCreature->pSD->pExData->CastedSkill.level = 0;
		pCreature->pSD->pExData->SoulshotActivated = 0;

		
		if(!pCreature->IsBoss() && !pCreature->IsZZoldagu() && !pTarget->IsBoss() && !pTarget->IsZZoldagu())
		{
			if(User *pUser = pTarget->SafeCastUser())
			{
				if(pTarget->pSD->pExData->SkillMod.nReflectMeleeSkillDmg)
				{
					//Check if it's melee skill and physical
					if(pSI->IsMeleeAtk())
					{
						CSkillFx::PerformCounterAttack(pUser, pCreature, pSI);
					}
				}
			}

			if(pSI->nIsMagic == 1 && pSI->nEffectPoint < 0 && pCreature->pSD->nIsPC)
			{
				if(User *pUser = pCreature->SafeCastUser())
				{
					pUser->TiggerAutoCastSkill(AutoCastSkill::OnMagicalAttack, pTarget);
				}
			}
		}
	}
}

bool CreatureAction::UseItem(CCreature *pCreature, CItem *pItem, BOOL force)
{
	guard;

	INT32 itemId = 0;
	if(g_InfinityShot.IsEnabled())
	{
		if(pItem->IsValidItem())
		{
			itemId = pItem->pSID->nItemID;
			if(User *pUser = pCreature->SafeCastUser())
			{
				if(pItem->pII->etcType == EtcItemInfinitySoulshot || pItem->pII->etcType == EtcItemInfinitySpiritshot || pItem->pII->etcType == EtcItemInfinityBlessedSpiritshot)
				{
					bool ret = g_InfinityShot.Activate(pUser, pItem);
					unguard;
					return ret;
				}
			}
		}
	}

//			if(User *pUser = pCreature->SafeCastUser())
//			{
//				if(itemId >= 23020 && itemId <= 23034)
//				{
	//				g_DB.WithdrawPet(pUser,pItem);
	//				unguard;
	//				return false;
//				}
//			}


	if(g_NewShotSystem) //until check will be made
	{
		if(pItem->IsValidItem())
		{
			itemId = pItem->pSID->nItemID;
			if(User *pUser = pCreature->SafeCastUser())
			{
				//soulshot
				if( (itemId > 1462 && itemId < 1468) || itemId == 5789 || itemId == 1835 )
				{
					if(pUser->pSD->dSoulshotPower == 0.0)
					{
						if(CSharedItemData *pWD = pUser->GetEquipedWeapon())
						{
							//grade check
							if(CItemInfo *pWI = pWD->GetItemInfo())
							{
								if(pItem->pII->nCrystalType == pWI->nCrystalType)
								{
									if(pUser->inventory.HaveItemByClassID(itemId, pWI->soulshotCount))
									{
										if(CSkillInfo *pInfo = g_SkillDB.GetSkillInfo(pItem->pII->itemSkillId, pItem->pII->itemSkillLevel))
										{
											pUser->soulShotInUse = true;
											pUser->soulshotUseTick = GetTickCount();
											pInfo->ActivateSkill(pUser, pUser);
											CHAR buff[512];
											FVector pos = pUser->pSD->Pos;
											int len = Assemble(buff, 512, "cddddddddddd", 0x48, pUser->nObjectID, pUser->nObjectID, pItem->pII->itemSkillId, pItem->pII->itemSkillLevel, 0, 0, (int)pos.x, (int)pos.y, (int)pos.z, 0, 0);
											L2Server::BroadcastToNeighborDist(pUser->nObjectID, &pos, 8000, len, buff);
											//46	1	a,You use $s1.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
											CSystemMessage msg(46);
											msg.AddItem(pItem->pSID->nItemID);
											pUser->SendSystemMessage(&msg);

											//pUser->DeleteItemInInventory(pItem->pSID->nItemID, pWI->soulshotCount);
											g_DB.RequestDestroyItem(pItem, pWI->soulshotCount, pUser);
											//g_DB.RequestUseItem(pItem, pUser, pWI->soulshotCount);

											//g_Log.Add(CLog::Blue, "[%s] Soulshot Used!!", __FUNCTION__);

											unguard;
											return true;
										}
									}
								}else
								{
									//337	1	a,The soulshot you are attempting to use does not match the grade of your equipped weapon.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
									CSystemMessage msg(337);
									pUser->SendSystemMessage(&msg);
								}
							}else
							{
								g_Log.Add(CLog::Error, "[%s] cannot find item info for index[%d]!", __FUNCTION__, pWD->nItemIndex);
								unguard;
								return false;
							}
						}else
						{
							//337	1	a,The soulshot you are attempting to use does not match the grade of your equipped weapon.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
							CSystemMessage msg(337);
							pUser->SendSystemMessage(&msg);
							unguard;
							return false;
						}
					}
					unguard;
					return false;
				}
				//spiritshot / blessed spiritshot
				if( (itemId > 2508 && itemId < 2515) || itemId == 5790 || (itemId > 3946 && itemId < 3953) )
				{
					if(pUser->pSD->dSpiritShotPower == 0.0)
					{
						if(CSharedItemData *pWD = pUser->GetEquipedWeapon())
						{
							//grade check
							if(CItemInfo *pWI = pWD->GetItemInfo())
							{
								if(pItem->pII->nCrystalType == pWI->nCrystalType)
								{
									if(pUser->inventory.HaveItemByClassID(itemId, pWI->spiritshotCount))
									{
										if(CSkillInfo *pInfo = g_SkillDB.GetSkillInfo(pItem->pII->itemSkillId, pItem->pII->itemSkillLevel))
										{
											pUser->spiritShotInUse = true;
											pInfo->ActivateSkill(pUser, pUser);
											CHAR buff[512];
											FVector pos = pUser->pSD->Pos;
											int len = Assemble(buff, 512, "cddddddddddd", 0x48, pUser->nObjectID, pUser->nObjectID, pItem->pII->itemSkillId, pItem->pII->itemSkillLevel, 0, 0, (int)pos.x, (int)pos.y, (int)pos.z, 0, 0);
											L2Server::BroadcastToNeighborDist(pUser->nObjectID, &pos, 8000, len, buff);
											//46	1	a,You use $s1.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
											CSystemMessage msg(46);
											msg.AddItem(pItem->pSID->nItemID);
											pUser->SendSystemMessage(&msg);

											//pUser->DeleteItemInInventory(pItem->pSID->nItemID, 1);
											g_DB.RequestDestroyItem(pItem, pWI->spiritshotCount, pUser);
											//g_DB.RequestUseItem(pItem, pUser, pWI->spiritshotCount);

											//g_Log.Add(CLog::Blue, "[%s] Spiritshot Used!!", __FUNCTION__);

											unguard;
											return true;
										}
									}
								}else
								{
									//337	1	a,The soulshot you are attempting to use does not match the grade of your equipped weapon.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
									CSystemMessage msg(337);
									pUser->SendSystemMessage(&msg);
								}
							}else
							{
								g_Log.Add(CLog::Error, "[%s] cannot find item info for index[%d]!", __FUNCTION__, pWD->nItemIndex);
							}
						}else
						{
							//337	1	a,The soulshot you are attempting to use does not match the grade of your equipped weapon.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
							CSystemMessage msg(337);
							pUser->SendSystemMessage(&msg);
						}
					}
					unguard;
					return false;
				}
			}
		}
	}

	int result = Hair2Slot::CCreature::UseItem(pCreature, pItem, force);
	//int result = -1;
	if(result == -1) {
		typedef bool (*f)(CCreature*, CItem*, BOOL);
		result = f(0x4F9C40L)(pCreature, pItem, force);
	}

	if(result)
	{
		if(g_SpiritShotExtension)
		{
			try
			{
				if(User *pUser = pCreature->GetUser())
				{
					itemId = pItem->pSID->nItemID; //fix vang mistake
					//spiritshot
					if( (itemId > 2508 && itemId < 2515) || itemId == 5790 || (itemId > 3946 && itemId < 3953) )
					{
						if(pUser->spiritShotInUse)
						{
							//activate skill effect
							if(pItem->pII->itemSkillId)
							{
								if(CSkillInfo *pInfo = g_SkillDB.GetSkillInfo(pItem->pII->itemSkillId, pItem->pII->itemSkillLevel))
								{
									pInfo->ActivateSkill(pCreature, pCreature);
									pUser->spiritShotInUse = 1;
								}			
							}
						}
					}
				}
			}catch(...)
			{
				EXCEPTION_LOG;
			}
		}
		unguard;
		return true;
	}
	unguard;
	return false;
}

int CreatureAction::ExpInc(CCreature *pCreature, int exp, int affectKarma)
{
	if(pCreature->IsSummon() && g_BlockSummonExp)
	{
		return pCreature->pSD->nExp;
	}

	if(pCreature->IsPet())
	{
		if(pCreature->pSD->nAlive == 0 && exp > 0)
		{
			if(pCreature->pSD->nRessurectExp == 0)
			{
				return pCreature->pSD->nExp;
			}
		}
		if(User *pMaster = pCreature->CastPet()->GetMaster())
		{
			if(pMaster->pSD->pExData->SkillMod.stopExp || pMaster->pSD->pExData->stopIncExp)
			{
				return pCreature->pSD->nExp;
			}

			double fExp = static_cast<double>(exp) * g_PetExpRate;
			exp = static_cast<int>(fExp);
			if(exp > 0)
			{
				CSystemMessage msg(1014);	//1014	1	a,Your pet gained $s1 experience points.\0	3	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,damage\0
				msg.AddNumber(exp);
				pMaster->SendSystemMessage(&msg);
			}
		}
	}
	else if(User *pUser = pCreature->SafeCastUser())
	{
		double fExp = static_cast<double>(exp) * g_RatesDinamicos.GetExpRate();
		exp = static_cast<int>(fExp);
	}

	typedef int(*f)(CCreature*, int, int);
	return f(0x4D8B30L)(pCreature, exp, affectKarma);
}

bool CreatureAction::OnValidateSetItem(CCreature *pCreature, int nSlotType)
{
	bool bRet = pCreature->ValidateSetItem(nSlotType);
	if(pCreature->ValidUser())
	{
		User *pUser = pCreature->GetUser();
		g_EnchantedSet.Validate(pUser);
		if(g_ArmorPenalty.IsEnabled())
		{
			//pCreature->pSD->pExData->ArmorPenalty = false;
			g_ArmorPenalty.Validate(pUser);
		}
	}
	return bRet;
}

bool CreatureAction::OnValidateBaseData(CCreature *pCreature)
{
	typedef bool (*_vbd)(CCreature*);
	_vbd vbd = (_vbd) 0x004DACC0;

	bool bRet = vbd(pCreature);

	if(User *pUser = pCreature->SafeCastUser())
	{
		g_Augmentation.ValidateBaseStat(pUser);
		if(g_RebirthSystem.Enabled())
		{
			RebirthUser& ru = pUser->pED->rebirthUser;

			if(ru.rebirthCount > 0)
			{
				pUser->pSD->nSTR += ru.bonusStr;
				pUser->pSD->nINT += ru.bonusInt;
				pUser->pSD->nCON += ru.bonusCon;
				pUser->pSD->nMEN += ru.bonusMen;
				pUser->pSD->nWIT += ru.bonusWit;
				pUser->pSD->nDEX += ru.bonusDex;
			}
		}
	}
	return bRet;
}

void CreatureAction::OnValidateAttachedSkills(CCreature *pCreature)
{
	if(User *pUser = pCreature->SafeCastUser())
	{
		g_EnchantedSet.Validate(pUser);
		if(g_ArmorPenalty.IsEnabled())
		{
			g_ArmorPenalty.Validate(pUser);
		}
		g_Augmentation.ValidateAugmentation(pCreature);

		if(g_RebirthSystem.Enabled())
		{
			RebirthUser& ru = pUser->pED->rebirthUser;

			if(ru.rebirthCount > 0)
			{
				pUser->pSD->nSTR += ru.bonusStr;
				pUser->pSD->nINT += ru.bonusInt;
				pUser->pSD->nCON += ru.bonusCon;
				pUser->pSD->nMEN += ru.bonusMen;
				pUser->pSD->nWIT += ru.bonusWit;
				pUser->pSD->nDEX += ru.bonusDex;
			}
		}
	}
	pCreature->ValidateSkillList();
}

int CreatureAction::OnUpdateSP(CCreature* pCreature, int incSp)
{
	typedef int (*f)(CCreature*, int);
	/* Do whatever you'd like with SP here*/

	if(User *pUser = pCreature->GetUser())
	{
		if(pUser->pSD->vipLevel)
		{
			incSp = g_VIPSystem.GetSP(incSp, pUser->pSD->vipLevel);
		}

		UINT currentThreadIdx = GetThreadIndex();
		if(currentThreadIdx < 32)
		{
			if(g_IsDistributingExpSp[currentThreadIdx])
			{
				if(pUser->CanGetPartyBonus(g_DistributingCreature[currentThreadIdx]))
				{
					double modSp = static_cast<double>(incSp);
					modSp *= g_PartyExpRate;
					incSp = static_cast<INT32>(modSp);
				}
			}
		}
		
		//sp overflow fix
		if(incSp == -2147483648)
		{
			INT64 sp = pUser->pSD->nSp;
			sp *= 5;
			sp /= 100;
			incSp = sp;
		}
		INT64 sp = pUser->pSD->nSp;
		sp += incSp;
		if( sp >= INT_MAX)
		{
			return pUser->pSD->nSp;
		}

		double modSp = static_cast<double>(incSp);
		modSp *= pUser->pSD->pExData->SkillMod.bonusSp;
		modSp *= g_DnNSystem.GetRate(DnN::RateSp);
		incSp = static_cast<INT32>(modSp);
	}

//	g_Log.Add(CLog::Blue, "[%s] Creature[%S] CreatureSP[%d] newSP[%d]", __FUNCTION__, pCreature->pSD->wszName, pCreature->pSD->nSp, SP);
	/* End Here */
	return f(0x4D8C20L)(pCreature, incSp);
}


void CreatureAction::OnTimerExpired(CCreature *pCreature, int nTimerID)
{
	typedef void (*f)(CCreature*, int);
//g_Log.Add(CLog::Blue, "111111111111111111");

//			if(pCreature->pSD->nNpcClassID >= 1033910 && pCreature->pSD->nNpcClassID <= 1033928)
//			{
//				g_Log.Add(CLog::Blue, "222222222222222222 nMakerParam2[%d]", pCreature->pSD->nMakerParam2);

//				if(pCreature->pSD->nMakerParam2 < 65456)
//				{
//g_Log.Add(CLog::Blue, "3333333333333333");
//					pCreature->AddTimer(50,65456);
//					pCreature->pSD->nMakerParam2 = 65456;
//				}
//				if(nTimerID == 65456)
//				{
//					pCreature->AddTimer(50,65456);
//		//				pCreature->AddTimer(300,65456);
//						g_Log.Add(CLog::Blue, "444444444444444444444");
//
//					User *pMaster = pCreature->CastSummon()->GetMaster();
//					if(pMaster->ValidUser())
//					{
//					
//						bool pasar =false;
//						double x1 = pCreature->pSD->Pos.x;
//						double y1 = pCreature->pSD->Pos.y;
//						double x2 = pMaster->pSD->Pos.x;
//						double y2 = pMaster->pSD->Pos.y;
//						int dist = (int)sqrt(pow((x2-x1), 2) + pow((y2-y1), 2));
//						if(dist > 30)
//							pasar= true;

//						if (pCreature->pSD->m_MovingStatus && !pMaster->pSD->m_MovingStatus || pCreature->pSD->m_MovingStatus && pasar)
//						{
//							pCreature->pCreatureController->AsyncMoveToTarget(pMaster->CastCreature(),1);
//							g_Log.Add(CLog::Blue, "111111111111111");
//						}
//
//					}
//					return;
//				}
//			}


	if(nTimerID == 0)
	{
		try
		{
			if(pCreature->ValidCreature())
			{
				if(pCreature->ValidUser() || pCreature->IsSummon() || pCreature->IsPet())
				{
					//check for herb system
					pCreature->pSD->pExData->HerbAbnormalMgr.TimerExpired(pCreature);

					TerritoryData& td = pCreature->pSD->pExData->territoryData;
					td.clear();
					g_TerritoryChecker.GetTerritories(pCreature, td);

					//DISPEL_ALL_ZONE
					if(td.territoryId[DISPEL_ALL_ZONE] != 0)
					{
						CDispelAllTerritory* pT =  g_TerritoryChecker.GetTerritory(td.territoryId[DISPEL_ALL_ZONE])->SafeCastDispelAll();
						if(pT)
						{
							if(pCreature->pSD->pExData->dispelAllZoneDone == FALSE || pT->IsOnEnterOnly() == FALSE)
							{
								pCreature->pSD->pExData->dispelAllZoneDone = TRUE;
								pCreature->DispelAllByGM();
							}
						}
					}else
					{
						if(pCreature->pSD->pExData->dispelAllZoneDone)
						{
							pCreature->pSD->pExData->dispelAllZoneDone = FALSE;
						}
					}

					//Faction Areas
					if(User *pUser = pCreature->GetUser())
					{
						//Check For Users without faction id
						if(pUser->pED->nFactionID == 0)
						{
							if(CFactionZoneTerritory *pT = g_TerritoryChecker.GetTerritory(td.territoryId[FACTION_ZONE])->SafeCastFactionZone())
							{
								pUser->SendSystemMessage(L"You cannot be here without having a Faction Team!");

								IVector kickOut = pT->GetKickOutPos();
								PlayerAction::OnTeleportToLocation(pUser, kickOut.x, kickOut.y, kickOut.z, 0);
							}
						}

						if(pUser->pED->nInFactionPvpZone > 0 )
						{
							if(td.territoryId[FACTION_ZONE] == 0)
							{
								//Left

								int nFactionOldID = pUser->pED->nFactionID;

								if( nFactionOldID == 1 )
								{
									g_FactionCounter.DecreaseRedTeam();
								}
								else if( nFactionOldID == 2 )
								{
									g_FactionCounter.DecreaseGreenTeam();
								}
								else
								{
									//Nothing?
								}

								pUser->pED->nInFactionPvpZone = 0;
								pUser->pED->nFactionID = 0;

								//Delete Nobless Skill
								if(pUser->HaveSkill(13254, 1))
								{
									pUser->DeleteSkill(13254);
									pUser->ValidateParameters();
								}
								pUser->SetUserInfoChanged();
								pUser->SetCharInfoChanged();
						}
						}else
						{
							if(td.territoryId[FACTION_ZONE] != 0)
							{
								//Enter
								pUser->pED->nInFactionPvpZone = td.territoryId[FACTION_ZONE];

								pUser->SetGuilty(false);

								//Give Nobless Skill
								pUser->AcquireSkill(13254, 1);
								pUser->ValidateParameters();

								pUser->SetUserInfoChanged();
								pUser->SetCharInfoChanged();
							}
						}
					}

					//PVP_ZONE
					//if(td.territoryId[PVP_ZONE_STEAL] == 0)
					//{
						if(pCreature->pSD->nInCustomPvpZone > 0)
						{
							if(td.territoryId[PVP_ZONE] == 0)
							{
								pCreature->pSD->nInCustomPvpZone = 0;
								if(User *pUser = pCreature->GetUser())
								{
									pUser->SetPvPFlag();
									pUser->pSD->bGuilty = true;
									pUser->SetUserInfoChanged();
									pUser->SetCharInfoChanged();
									//2557	1	a,You have left the PvP Zone.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
									//pUser->pSocket->SendSystemMessage(2557);
									CSystemMessage msg(2914);
									msg.AddText(L"You have left a PvP Zone.");
									pUser->SendSystemMessage(&msg);

								}
							}
						}else
						{
							if(td.territoryId[PVP_ZONE] != 0)
							{
								pCreature->pSD->nInCustomPvpZone = td.territoryId[PVP_ZONE];
								if(User *pUser = pCreature->GetUser())
								{
									pUser->SetPvPFlag();
									pUser->pSD->bGuilty = true;
									pUser->SetUserInfoChanged();
									pUser->SetCharInfoChanged();
									
									//2556	1	a,You have entered a PvP Zone.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
									//pUser->pSocket->SendSystemMessage(2556);
									CSystemMessage msg(2914);
									msg.AddText(L"You have entered a PvP Zone.");
									pUser->SendSystemMessage(&msg);
								}
							}
						}
					//}


					//ZONE_ANTI_REJUNTE
					if(User *pUser = pCreature->GetUser())
					{
						if(pUser->pED->nInCustomAntiRejunteZone)
						{
							if(td.territoryId[ZONE_ANTI_REJUNTE] == 0)
							{
								pUser->pED->nInCustomAntiRejunteZone = 0;
								g_TerritoryChecker.DelUserPvPZone(pUser);
							}
							else
							{
								g_TerritoryChecker.AutoAttackPvPZone(pUser);
							}
						}
						else
						{
							if(td.territoryId[ZONE_ANTI_REJUNTE] != 0)
							{
								pUser->pED->nInCustomAntiRejunteZone = td.territoryId[ZONE_ANTI_REJUNTE];
								g_TerritoryChecker.AddUserPvPZone(pUser);
							}
						}
					}



					//PVP_ZONE_STEAL
					//if(td.territoryId[PVP_ZONE] == 0)
					//{
						if(pCreature->GetUser() && pCreature->GetUser()->pED->nInPvpZoneSteal == true )
						{
							if(td.territoryId[PVP_ZONE_STEAL] == 0)
							{
								if(User *pUser = pCreature->GetUser())
								{
									pUser->pED->nInPvpZoneSteal = false;

//									pUser->SetPvPFlag();
//									pUser->SetUserInfoChanged();
//									pUser->SetCharInfoChanged();
									//2557	1	a,You have left the PvP Zone.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
									//pUser->pSocket->SendSystemMessage(2557);

									CSystemMessage msg(2920);
									msg.AddText(L"You have left a Steal Zone.");
									pUser->SendSystemMessage(&msg);

								}
							}

						}else
						{
							if(td.territoryId[PVP_ZONE_STEAL] != 0)
							{
								if(User *pUser = pCreature->GetUser())
								{
									pUser->pED->nInPvpZoneSteal = true;
//									pUser->SetUserInfoChanged();
//									pUser->SetCharInfoChanged();
									//2556	1	a,You have entered a PvP Zone.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
									//pUser->pSocket->SendSystemMessage(2556);

									CSystemMessage msg(2920);
									msg.AddText(L"You have entered a Steal Zone.");
									pUser->SendSystemMessage(&msg);


								}
							}
						}
					//}


					//DAILY PVP
					if(User *pUser = pCreature->GetUser())
					{
						if(pUser->pED->nInCustomDailyPvPZone)
						{
							if(td.territoryId[DAILY_PVP] == 0)
							{
								pUser->pED->nInCustomDailyPvPZone = 0;
								//2633	1	You have left a DailyPvP Zone.	0	79	9B	B0	FF			0	0	0	0	0		none
								pUser->pSocket->SendSystemMessage(2633);
							}
						}
						else
						{
							if(td.territoryId[DAILY_PVP] != 0)
							{
								pUser->pED->nInCustomDailyPvPZone = td.territoryId[DAILY_PVP];
								//2632	1	You have entered a DailyPvP zone.	0	79	9B	B0	FF			0	0	0	0	0		none
								pUser->pSocket->SendSystemMessage(2632);
							}
						}
					}

					//NO PK ZONE
					if(User *pUser = pCreature->GetUser())
					{
						if(pUser->pED->nInCustomNoPKZone)
						{
							if(td.territoryId[NOPKZONE] == 0)
							{
								pUser->pED->nInCustomNoPKZone = 0;
								CSystemMessage msg(2907);
								msg.AddText(L"Has salido de la Zona Anti-PK.");
								pUser->SendSystemMessage(&msg);
							}
						}
						else
						{
							if(td.territoryId[NOPKZONE] != 0)
							{
								pUser->pED->nInCustomNoPKZone = td.territoryId[NOPKZONE];
								//2632	1	You have entered a DailyPvP zone.	0	79	9B	B0	FF			0	0	0	0	0		none
								//pUser->pSocket->SendSystemMessage(2632);
								if(pUser->pED->nInCustomNoPKZoneTime > time(0))
								{  
									PlayerAction::OnTeleportToLocation(pUser, 82793, 148425, -3464, false);
								}
								CSystemMessage msg(2907);
								msg.AddText(L"Entraste a una Zona Anti-PK. Si haces un PK aqui, no podras volver a entrar por un tiempo.");
								pUser->SendSystemMessage(&msg);

							}
						}
					}

					//EVENT_PENALTY_CLAN_ZONE
					if(User *pUser = pCreature->GetUser())
					{
						if(pUser->pED->nInCustomEventClanZone)
						{
							if(td.territoryId[EVENT_PENALTY_CLAN_ZONE] == 0)
							{
								pUser->pED->nInCustomEventClanZone = 0;

								CPledge *pPledge = pUser->GetPledge();
								if(pPledge && pPledge->pSD)
								{
									g_TerritoryChecker.updateClanUserCount(pPledge->pSD->nDBID, -1);

									wstring value = pUser->pED->original_wTitle;
									const WCHAR * value2 = value.c_str();
									wcscpy(pUser->wTitle, value2);
									pUser->SetUserInfoChanged();
									pUser->SetCharInfoChanged();

									CSystemMessage msg(2907);
									msg.AddText(L"Has salido de la Zona de Evento.");
									pUser->SendSystemMessage(&msg);
								}
							}
							else
							{
								g_TerritoryChecker.setClanUserCountTittle(pUser);
							}
						}
						else
						{
							if(td.territoryId[EVENT_PENALTY_CLAN_ZONE] != 0)
							{
								pUser->pED->nInCustomEventClanZone = td.territoryId[EVENT_PENALTY_CLAN_ZONE];

								wcscpy(pUser->pED->original_wTitle, pUser->wTitle);

								CPledge *pPledge = pUser->GetPledge();
								if(pPledge && pPledge->pSD)
								{
									if(pUser->pSD->nAlive)
										g_TerritoryChecker.updateClanUserCount(pPledge->pSD->nDBID, 1);
									
								}

								CSystemMessage msg(2907);
								msg.AddText(L"Entraste a la zona de evento. Si tu clan es mayoria, al momento de morir tendran penalizacion de 1 minuto para darse Ressurection o volver a esta Zona.");
								pUser->SendSystemMessage(&msg);
							}
						}
					}


					//BUFF ZONE
					if(User *pUser = pCreature->GetUser())
					{
						if(pUser->pED->nInCustomBuffZone)
						{
							if(td.territoryId[BUFF_ZONE] == 0)
							{
								pUser->pED->nInCustomBuffZone = 0;
								CSystemMessage msg(2901);
								msg.AddText(L"You have left an Offline Buff Zone.");
								pUser->SendSystemMessage(&msg);
							}
						}
						else
						{
							if(td.territoryId[BUFF_ZONE] != 0)
							{
								pUser->pED->nInCustomBuffZone = td.territoryId[BUFF_ZONE];
								CSystemMessage msg(2901);
								msg.AddText(L"You have enter an Offline Buff Zone.");
								pUser->SendSystemMessage(&msg);
							}
						}
					}

					//Show HP Info Area
					if(User *pUser = pCreature->GetUser())
					{
						if(pUser->pED->nInCustomShowHPZone)
						{
							//Left
							if(td.territoryId[SHOW_HP_TITLE] == 0)
							{
								pUser->pED->nInCustomShowHPZone = 0;
								pUser->SendUserInfo(false);
								pUser->SendCharInfo(false);
							}
						}

						if(td.territoryId[SHOW_HP_TITLE] != 0)
						{
							pUser->pED->nInCustomShowHPZone = td.territoryId[SHOW_HP_TITLE];
							pUser->SendUserInfo(false);
							pUser->SendCharInfo(false);
						}
					}

					//SSQ Zone fix
					if(pCreature->pSD->nInSSQ_ZONE)
					{
						if(td.territoryId[SSQ_ZONE] == 0)
						{
							pCreature->pSD->nInSSQ_ZONE = 0;
						}
					}else
					{
						if(td.territoryId[SSQ_ZONE] != 0)
						{
							pCreature->pSD->nInSSQ_ZONE = 1;
						}
					}
					//dispel skill zone
					if(td.territoryId[DISPEL_SKILL_ZONE] != 0)
					{
						if(CDispelSkillTerritory* pTerritory = g_TerritoryChecker.GetTerritory(td.territoryId[DISPEL_SKILL_ZONE])->SafeCastDispelSkill())
						{
							pTerritory->Validate(pCreature);
						}
					}

					//dispel skill zone
					if(td.territoryId[JAIL_ZONE] != 0)
					{
						if(User *pUser = pCreature->GetUser())
						{
							if( pUser->pED->jailtimeout == 0 )
							{
								PlayerAction::OnTeleportToLocation(pUser, g_Jail.JKickPosX(), g_Jail.JKickPosY(), g_Jail.JKickPosZ(), false);
							}
						}
					}

					//despawn summon zone
					if(pCreature->IsSummon() || pCreature->IsPet())
					{
						if(User *pMaster = pCreature->CastSummon()->GetMaster())
						{
							if(pMaster->pSD->DuelInfo.DuelID)
							{
								pCreature->pSD->DuelInfo.DuelID = pMaster->pSD->DuelInfo.DuelID;
							}else if(pCreature->pSD->DuelInfo.DuelID)
							{
								pCreature->pSD->DuelInfo.DuelID = 0;
							}
						}

						if(td.territoryId[DESPAWN_SUMMON_ZONE] != 0)
						{
							if(CDespawnSummonTerritory* pTerritory = g_TerritoryChecker.GetTerritory(td.territoryId[DESPAWN_SUMMON_ZONE])->SafeCastDespawnSummon())
							{
								if(pTerritory->IsBlocked(pCreature->pSD->nNpcClassID))
								{
									CSummon *pSummon = pCreature->CastSummon();
									if(User *pMaster = pSummon->GetMaster())
									{
										pMaster->SendSystemMessage(L"You cannot use this servitor here!");
										if(pCreature->IsPet())
										{
											PetAction::DespawnPet(pMaster, false);
										}else
										{
											pMaster->DespawnSummon();
										}
									}
								}
							}

						}
					}
				}
			}
		}catch(...)
		{
			g_Log.Add(CLog::Error, "[%s] Exception 1!", __FUNCTION__);
		}
	}

	f(0x0050D680L)(pCreature, nTimerID);
	
	if(nTimerID == 0)
	{
		try
		{
			if(pCreature->ValidCreature() && nTimerID == 0)
			{

				pCreature->pSD->pExData->TimerHandler.TimerExpired(pCreature);

				if(CAntiExploit::ValidateStats(pCreature))
				{
					pCreature->ValidateBaseData();
					try
					{
						g_Log.Add(CLog::Error, "[%s] Invalid Stats Creature[%S]", __FUNCTION__, pCreature->pSD->wszName);
						g_Log.Add(CLog::Error, "Default: STR[%d] DEX[%d] CON[%d] INT[%d] WIT[%d] MEN[%d]",  pCreature->pSD->nDefaultSTR, pCreature->pSD->nDefaultDEX, pCreature->pSD->nDefaultCON, pCreature->pSD->nDefaultINT, pCreature->pSD->nDefaultWIT, pCreature->pSD->nDefaultMEN);
						g_Log.Add(CLog::Error, "Henna: STR[%d] DEX[%d] CON[%d] INT[%d] WIT[%d] MEN[%d]",  pCreature->hennaSTR, pCreature->hennaDEX, pCreature->hennaCON, pCreature->hennaINT, pCreature->hennaWIT, pCreature->hennaMEN);
					}catch(...)
					{
						g_Log.Add(CLog::Error, "[%s] Exception!", __FUNCTION__);
					}
							
					if(pCreature->ValidUser())
					{
						pCreature->ValidateParameters();
						if(CAntiExploit::ValidateStats(pCreature))
						{
							g_Log.Add(CLog::Error, "[%s] Invalid Stats stage 2 Creature[%S]", __FUNCTION__, pCreature->pSD->wszName);
							g_Log.Add(CLog::Error, "Default: STR[%d] DEX[%d] CON[%d] INT[%d] WIT[%d] MEN[%d]", pCreature->pSD->nDefaultSTR, pCreature->pSD->nDefaultDEX, pCreature->pSD->nDefaultCON, pCreature->pSD->nDefaultINT, pCreature->pSD->nDefaultWIT, pCreature->pSD->nDefaultMEN);
							g_Log.Add(CLog::Error, "Henna: STR[%d] DEX[%d] CON[%d] INT[%d] WIT[%d] MEN[%d]",  pCreature->hennaSTR, pCreature->hennaDEX, pCreature->hennaCON, pCreature->hennaINT, pCreature->hennaWIT, pCreature->hennaMEN);
							if(pCreature->ValidUser())
							{
								pCreature->GetUser()->GetSocket()->Close(L"CAntiExploit::ValidateStats");
							}
						}
					}
				}
			}
		}catch(...)
		{
			g_Log.Add(CLog::Error, "[%s] Exception 2!", __FUNCTION__);
		}
	}
}


void CreatureAction::OnSetSkillUsableTime(CCreature *pCreature, int nSkillID, int nLevel, DWORD *stamp, DWORD Reuse)
{
	pCreature->SetSkillUsableTime(nSkillID, nLevel, stamp, Reuse);
}
//casting a skill
void CreatureAction::OnSetSkillUsableTime2(CCreature *pCreature, int nSkillID, int nLevel, DWORD *stamp, DWORD Reuse)
{
	/* Static reuse feature start */
	CSkillInfoEx *pInfo = g_SkillDBEx.GetSkillInfoEx(nSkillID, nLevel);
	if(pInfo)
	{
		if(pInfo->staticReuseTime > 0)
		{
		//	g_Log.Add(CLog::Blue, "[%s] Reuse[%d] Static[%d]", __FUNCTION__, Reuse, pInfo->staticReuseTime);
			Reuse = pInfo->staticReuseTime;
		}
		else
		{
			if(pInfo->staticReuseTimeWarrior > 0 && pInfo->staticReuseTimeMago > 0)
			{
				if(User *pUser = pCreature->SafeCastUser())
				{
					if(CCategoryDataDB::IsInCategory(pUser->pSD->nClass, CCategoryDataDB::MAGE_GROUP))
					{
						Reuse = pInfo->staticReuseTimeMago;
					}else
					{
						Reuse = pInfo->staticReuseTimeWarrior;
					}
				}
			}
		}


	}
	/* Static reuse feature end */

	if(User *pUser = pCreature->SafeCastUser())
	{
		if(g_Config.IsSet(CConfig::SKILL_REUSE_MANAGER))
		{		
			g_SkillReuseManager.SetReuse(pUser, nSkillID, nLevel, Reuse);
		}
	}
	pCreature->SetSkillUsableTime(nSkillID, nLevel, stamp, Reuse);
}

void CreatureAction::OnSetItemUsableTime(CCreature *pCreature, int ItemClassID, DWORD *stamp, DWORD Reuse)
{
	guard;
	if(User *pUser = pCreature->SafeCastUser())
	{
		bool canUse = true;
		if(Reuse > 1500)
		{
			if(CItem *pItem = g_ObjectDB.GetTemplateObject(ItemClassID)->SafeCastItem())
			{
				int skillId = pItem->pII->itemSkillId;
				int skillLevel = pItem->pII->itemSkillLevel;
				if(skillId > 0 && skillLevel > 0)
				{
					if(CSkillInfo *pSI = g_SkillDB.GetSkillInfo(skillId, skillLevel))
					{
						if(pSI->targetType == CSkillInfo::TargetSelf && pSI->vOperateCondition.size() > 0)
						{
							for(UINT n=0;n<pSI->vOperateCondition.size();n++)
							{
								CSkillOperateCondition* pCond = pSI->vOperateCondition[n];
								if(pCond)
								{
									if(pCond->CanUse(pCreature, pCreature) == false)
									{
										canUse = false;
										unguard;
										return;
									}
								}
							}
						}
					}
				}
			}
		}
		if(g_Config.IsSet(CConfig::ITEM_REUSE_MANAGER))
		{
			g_ItemReuseManager.SetReuse(pUser, ItemClassID, Reuse);
			DWORD nReuse = Reuse / 1000;
			if(nReuse > 1)
			{
				CItemDataEx *pData = g_ItemDBEx.GetItemDataEx(ItemClassID);
				if(pData && pData->GetReuseGroup() > 0)
				{
					pUser->pSocket->Send("chdddd", 0xFE, 0x49, ItemClassID, pData->GetReuseGroup(), nReuse, nReuse);
				}
			}
		}
	}
	pCreature->SetItemUsableTime(ItemClassID, stamp, Reuse);
	unguard;
}


void CreatureAction::OnAttackCheckItemSkill(CAttackAction *pAction, AttackTargetDataType *pTargetData)
{
	try
	{
		CCreature *pCreature = pAction->GetAttacker()->SafeCastCreature();
		CCreature *pTarget = pAction->GetTarget()->SafeCastCreature();
		if(pCreature && pTarget)
		{
			if(pCreature->pSD->nWeaponId)
			{
				if(!pCreature->IsInRange(pTarget, pCreature->pSD->nWeaponRange))
				{
				//	g_Log.Add(CLog::Blue, "[%s] Target is out of range Attacker[%S] Target[%S] maxRange[%d]", __FUNCTION__, pCreature->pSD->wszName, pTarget->pSD->wszName, pCreature->pSD->nWeaponRange);
					return;
				}
			}

			if(User *pUser = pCreature->SafeCastUser())
			{
				if(pTarget->ValidCreature() && !pTarget->IsZZoldagu() && !pTarget->IsBoss())
				{
					pUser->TiggerAutoCastSkill(AutoCastSkill::OnPhysicalAttack, pTarget);
					if(pTargetData->bCritical)
					{
						pUser->TiggerAutoCastSkill(AutoCastSkill::OnCriticalAttack, pTarget);
					}
				}
			}
		}
	}
	catch(...)
	{
	}

	
	typedef void (*f)(CAttackAction*, AttackTargetDataType*);
	f(0x00696A00L)(pAction, pTargetData);
}

void CreatureAction::ActionBroadcastSkillCancelled(CCreatureController *pCC, CSkillAction *pAction)
{
	guard;

	typedef void (*f)(CCreatureController*, CSkillAction*);
	f(0x69DF00L)(pCC, pAction);

	unguard;
}

void CreatureAction::ActionBroadcastSkillLanuched(CCreatureController *pCC, int skillId, int level, LPVOID pContainer)
{
	guard;



	typedef void(*f)(CCreatureController*, int, int, LPVOID);
	f(0x6A2C70L)(pCC, skillId, level, pContainer);

	unguard;
}

void CreatureAction::ActionBroadcastSkillLanuchedEx(CCreatureController *pCC, int skillId, int level, UINT targetId)
{
	guard;

	typedef void(*f)(CCreatureController*, int, int, UINT);
	f(0x69E1B0L)(pCC, skillId, level, targetId);

	unguard;
}

bool CreatureAction::IsValidTarget(CSkillInfo *pSI, CCreature *pSkillUser, CObject *pTarget, bool bForce)
{
	typedef bool (*_f)(CSkillInfo*, CCreature*, CObject*, bool);
	_f f = (_f) 0x00799920;

//	g_Log.Add(CLog::Blue, "[%s] Called [%d]", __FUNCTION__, pSI->nSkillID);
	return f(pSI, pSkillUser, pTarget, bForce);
}

bool CreatureAction::OnIsShieldDefend(CCreature *pCreature, CCreature *pAttacker, double CriticalBonus)
{
	typedef bool (*_ISD)(CCreature*, CCreature*, double);
	_ISD isd = (_ISD) 0x004DFD80;

	if(pCreature->ValidCreature() && pAttacker->ValidCreature())
	{
		if(pAttacker->pSD->pExData->CastedSkill.skill_id)
		{
			CSkillInfoEx *pData = g_SkillDBEx.GetSkillInfoEx(pAttacker->pSD->pExData->CastedSkill.skill_id, pAttacker->pSD->pExData->CastedSkill.level);
			if(pData)
			{
				if(pData->avoidShieldBlock)
					return false;
			}
		}
	}
	return isd(pCreature, pAttacker, CriticalBonus);
}

void CreatureAction::OnInitializeSkillMod(CCreature *pCreature)
{
	guard;

	if(pCreature->ValidCreature())
	{
		typedef void(*f)(CCreature*);
		f(0x004DDC70L)(pCreature);

		pCreature->pSD->pExData->SummonBetrayData.Betraying = false;
		pCreature->pSD->pExData->SkillMod.Clear();
		if(pCreature->pSD->nIsPC)
		{
			if(User *pUser = pCreature->SafeCastUser())
			{
				pUser->pED->itemBonus.Clear();
				pUser->pED->lock.Enter();
				pUser->pED->skillDmgMultiplers.clear();
				pUser->pED->autoCastSkills.clear();
				pUser->pED->lock.Leave();
				g_Augmentation.SetAugmentationSkillMod(pCreature, pCreature->pSD->nAugmentationID);
				if(pUser->pED->preserveAbnormalTerritory)
				{
					pUser->preserveAbnormals = true;
				}
			}
		}
	}else
	{
		typedef void(*f)(CCreature*);
		f(0x004DDC70L)(pCreature);
	}

	unguard;
}

bool CreatureAction::OnInfectedSkillBy(CCreature *pCreature, CCreature *pSource, CSkillInfo *pInfo)
{
	if(pCreature->ValidCreature() && pInfo)
	{
		if(pCreature->IsNPC() && pSource->ValidUser())
		{
			if(User *pUser = pSource->GetUser())
			{
				g_TvT.FortressCastCrystal(pUser, pCreature->nObjectID, pInfo->nSkillID);
			}
		}

		if(pCreature->ValidUser() && pSource->ValidUser())
		{
			if(User *pUser = pCreature->GetUser())
			{
				if(User *pTarget = pSource->GetUser())
				{
					if((pUser->pED->inZoneCustomEventPvp && !pTarget->pED->inZoneCustomEventPvp) || (!pUser->pED->inZoneCustomEventPvp && pTarget->pED->inZoneCustomEventPvp))
					{
						return false;
					}
				}
			}
		}

		if(pInfo->nDebuff == 1 && pCreature->isBlockDebuff)
		{
			//check for block debuff
			bool exception = false;
			for(UINT n=0;n<g_BlockDebuffException.size();n++)
			{
				if(pInfo->nSkillID == g_BlockDebuffException[n])
				{
					exception = true;
					break;
				}
			}
			if(!exception)
			{
				return false;
			}
		}else if(pInfo->nDebuff == 0 && pCreature->isBlockBuff)
		{
			//check for block buff
			bool exception = false;
			for(UINT n=0;n<g_BlockBuffException.size();n++)
			{
				if(pInfo->nSkillID == g_BlockBuffException[n])
				{
					exception = true;
					break;
				}
			}
			if(!exception)
			{
				return false;
			}
		}

		if(pCreature->ValidUser() || pCreature->IsSummon())
		{

			if(pCreature->pSD->pExData->SkillMod.nAntiBuff == 4 && pSource /* && pSource!=pCreature*/)
			{
				if(User *pUser = pCreature->GetUser())
				{
					if(User *pUserSource = pSource->GetUser())
					{
						if(CParty *pParty = pUser->GetParty())
						{
							if(CParty *pParty2 = pUserSource->GetParty())
							{
								if(pParty == pParty2)
								{
									bool affected = true;
									for(UINT n=0;n<g_AntiBuffException.size();n++)
									{
										if(pInfo->nSkillID == g_AntiBuffException[n])
										{
											affected = false;
											break;
										}
									}

									if(CCategoryDataDB::IsInCategory(pCreature->pSD->nClass, CCategoryDataDB::MAGE_GROUP))
									{
										for(UINT n=0;n<g_BlockBuffExceptionMage.size();n++)
										{
											if(pInfo->nSkillID == g_BlockBuffExceptionMage[n])
											{
												affected = false;
												break;
											}
										}
									}
									else
									{
										for(UINT n=0;n<g_BlockBuffExceptionWarrior.size();n++)
										{
											if(pInfo->nSkillID == g_BlockBuffExceptionWarrior[n])
											{
												affected = false;
												break;
											}
										}
									}

									if(affected)
										return false;
								}
							}
						}

						if(CPledge *pPledge = pUser->GetPledge())
						{
							if(CPledge *pPledge2 = pUserSource->GetPledge())
							{
								if(pPledge == pPledge2)
								{
									bool affected = true;
									for(UINT n=0;n<g_AntiBuffException.size();n++)
									{
										if(pInfo->nSkillID == g_AntiBuffException[n])
										{
											affected = false;
											break;
										}
									}



									if(CCategoryDataDB::IsInCategory(pCreature->pSD->nClass, CCategoryDataDB::MAGE_GROUP))
									{
										for(UINT n=0;n<g_BlockBuffExceptionMage.size();n++)
										{
											if(pInfo->nSkillID == g_BlockBuffExceptionMage[n])
											{
												affected = false;
												break;
											}
										}
									}
									else
									{
										for(UINT n=0;n<g_BlockBuffExceptionWarrior.size();n++)
										{
											if(pInfo->nSkillID == g_BlockBuffExceptionWarrior[n])
											{
												affected = false;
												break;
											}
										}
									}


									if(affected)
										return false;
								}
							}
						}

						if(CPledge *pPledge = pUser->GetPledge())
						{
							if(CPledge *pPledge2 = pUserSource->GetPledge())
							{
								if(pPledge->GetAllianceID() == pPledge2->GetAllianceID() && (pPledge->GetAllianceID() != 0))
								{
									bool affected = true;
									for(UINT n=0;n<g_AntiBuffException.size();n++)
									{
										if(pInfo->nSkillID == g_AntiBuffException[n])
										{
											affected = false;
											break;
										}
									}


									if(CCategoryDataDB::IsInCategory(pCreature->pSD->nClass, CCategoryDataDB::MAGE_GROUP))
									{
										for(UINT n=0;n<g_BlockBuffExceptionMage.size();n++)
										{
											if(pInfo->nSkillID == g_BlockBuffExceptionMage[n])
											{
												affected = false;
												break;
											}
										}
									}
									else
									{
										for(UINT n=0;n<g_BlockBuffExceptionWarrior.size();n++)
										{
											if(pInfo->nSkillID == g_BlockBuffExceptionWarrior[n])
											{
												affected = false;
												break;
											}
										}
									}

									if(affected)
										return false;
								}
							}
						}


					}
				}
			}


			if(pInfo->nDebuff == CSkillInfo::BUFF)
			{
				//Herb System Start
				if(g_HerbSystem.IsHerbSkill(pInfo->nSkillID))
				{
					g_HerbSystem.StoreBuff(pCreature, pInfo);
				}
				
				//Cursed weapon system
				if(pCreature->pSD->nCursedOwner && pCreature!=pSource)
				{
					if(pInfo->nDebuff == 0 && pInfo->nEffectPoint > 0)
					{
						return false;
					}
				}

				//AntiBuff effect
				if(pInfo->nEffectPoint > 0)
				{
					bool affected = true;
					for(UINT n=0;n<g_AntiBuffException.size();n++)
					{
						if(pInfo->nSkillID == g_AntiBuffException[n])
						{
							affected = false;
							break;
						}
					}
					if(affected)
					{
						if(pCreature->pSD->pExData->SkillMod.nAntiBuff == 2 && pSource)
						{
							return false;
						}else if(pCreature->pSD->pExData->SkillMod.nAntiBuff == 1 && pSource && pSource!=pCreature)
						{
							return false;
						}else if(pCreature->pSD->pExData->SkillMod.nAntiBuff == 3 && pSource && pSource!=pCreature)
						{
							bool blocked = true;
							if(User *pUser = pCreature->GetUser())
							{
								if(User *pUserSource = pSource->GetUser())
								{
									if(CParty *pParty = pUser->GetParty())
									{
										UserVector vMembers;
										pParty->GetAllMembersEx(vMembers, true);
										for(INT32 n=0;n<vMembers.size();n++)
										{
											if(User *pMember = vMembers[n]->GetUser())
											{
												if(pMember == pUserSource)
													blocked = false;
											}
										}
									}
								}
							}
							if(blocked)
								return false;
						}
					}
				}
			}
		}
	}

	//Replace hostile abnormal - c5+ you cant stun already stunned player or force to sleep already sleeping player
	if(!g_ReplaceHostileAbnormal && pInfo && pSource)
	{
		if(pInfo->nAbnormalType != 181 && pInfo->nEffectPoint < 0 && pInfo->nDebuff == 1 && pInfo->nAbnormalType >= 0 && pSource->pSD->nIsPC)
		{
			int currentLevel = pCreature->HasAbnormal(pInfo->nAbnormalType);
			if(currentLevel > 0 && pInfo->nAbnormalLevel <= currentLevel)
			{
				if(User *pUser = pSource->SafeCastUser())
				{
					//139	1	a,$s1 has resisted your $s2.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
					CSystemMessage msg(139);
					if(pCreature->pSD->nIsPC)
					{
						msg.AddText(pCreature->pSD->wszName);
					}else
					{
						msg.AddNpc(pCreature->pSD->nNpcClassID);
					}
					msg.AddSkill(pInfo->nSkillID, pInfo->nLevel);
					pUser->SendSystemMessage(&msg);
				}
				return false;
			}
		}
	}
	
	typedef bool (*f)(CCreature*, CCreature*, CSkillInfo*);
	if( f(0x504FD0L)(pCreature, pSource, pInfo) ) //CCreature::InfectedSkillBy
	{
		if(pInfo && pSource)
		{
			if(pInfo->nSkillID == 4515 && pInfo->nLevel == 1) //raid boss curse
			{
				if(pCreature->IsSummon())
				{
					CSummon *pSummon = pCreature->CastSummon();
					if(pSummon)
					{
						if(User *pUser = pSummon->GetMaster())
						{
							if(pUser->ValidUser())
							{
								pInfo->ActivateSkill(pSource, pUser);
							}
						}
					}
				}
			}
		}

		//Support for i_dispel_npc_buff
		if(g_Config.L2ServerConfig.IsPlayerBuffAsSelfBuff() )
		{
			if( pSource->ValidUser() && pCreature->ValidUser() && !pCreature->pSD->buffedByBuffer && pInfo )
			{
				if( pInfo->nDebuff == 0 && pInfo->nEffectPoint > 0 )
				{
					int SkillID = pInfo->nSkillID;
					int SkillLevel = pInfo->nLevel;

					pCreature->abnormalStatusLock.Lock(__FILEW__, __LINE__);
					for(AbnormalDataVector::iterator Iter = pCreature->vAbnormalStatus.begin(); Iter != pCreature->vAbnormalStatus.end(); Iter++)
					{
						if( Iter->pSI )
						{
							if( Iter->pSI->nSkillID == SkillID && Iter->pSI->nLevel == SkillLevel )
							{
								Iter->selfBuff |= 1;	//set selfbuff flag
								break;
							}
						}
					}
					pCreature->abnormalStatusLock.Unlock();

				}
			}
		}

		//Buff Time feature
		if( pCreature->ValidUser() || pCreature->IsSummon() )
		{
			//herb part
			if( g_HerbSystem.IsHerbSkill(pInfo->nSkillID) && g_HerbSystem.IsAffectSummon())
			{
				bool divTime = false;
				if(pCreature->IsSummon())
				{
					divTime = true;
				}else if(User *pUser = pCreature->GetUser())
				{
					if(CSummon* pSummon = pUser->GetSummon())
					{
						divTime = true;
					}
				}
				if(divTime)
				{
					pCreature->abnormalStatusLock.Lock(__FILEW__, __LINE__);
					for(AbnormalDataVector::iterator Iter = pCreature->vAbnormalStatus.begin(); Iter != pCreature->vAbnormalStatus.end(); Iter++)
					{
						if( Iter->pSI )
						{
							if( Iter->pSI->nSkillID == pInfo->nSkillID && Iter->pSI->nLevel == pInfo->nLevel )
							{
								Iter->expireTime = Iter->expireTime - (pInfo->nAbnormalTime / 2);
								break;
							}
						}
					}
					pCreature->abnormalStatusLock.Unlock();
					if( User *pUser = pCreature->GetUser() )
					{
						pUser->SendAbnormalStatusInfo();
					}
				}
			}

			//AIO part
			if(User *pUser = pSource->GetUser())
			{
				if(pUser->pED->aioId)
				{
					INT32 abnormalTime = pInfo->nAbnormalTime;
					INT32 customAbnormalTime = g_AIOSystem.GetAbnormalTime(pUser, pInfo->nSkillID, pInfo->nLevel);
					if(customAbnormalTime > 0)
					{
						pCreature->abnormalStatusLock.Lock(__FILEW__, __LINE__);
						for(AbnormalDataVector::iterator Iter = pCreature->vAbnormalStatus.begin(); Iter != pCreature->vAbnormalStatus.end(); Iter++)
						{
							if( Iter->pSI )
							{
								if( Iter->pSI->nSkillID == pInfo->nSkillID && Iter->pSI->nLevel == pInfo->nLevel )
								{
									Iter->expireTime = time(0) + customAbnormalTime - Iter->pSI->nAbnormalTime;
									break;
								}
							}
						}
						pCreature->abnormalStatusLock.Unlock();
						if( User *pUser = pCreature->GetUser() )
						{
							pUser->SendAbnormalStatusInfo();
						}
					}
				}
			}
		}
		return true;
	}
	
	return false;
}


bool CreatureAction::CheckAttackValidity(CAttackAction *pAction, CCreature *pActor, CObject *pTarget)
{
	guard;

	if(pActor->pSD->nNpcClassID >= 1033910 && pActor->pSD->nNpcClassID <= 1033928)
	{
		unguard;
		return false;
	}

	if(User *pAttacker = pActor->SafeCastUser())
	{
		if(User *pUser = pTarget->SafeCastUser())
		{
			if(pUser->pED->antiPkLevelRange > 0 && pUser->pSD->nKarma == 0 && pUser->pSD->bGuilty == false)
			{
				if( (pUser->pSD->nLevel + pUser->pED->antiPkLevelRange) < pAttacker->pSD->nLevel)
				{
					//1996	1	a,The attack has been blocked.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
					CSystemMessage msg(1996);
					pAttacker->SendSystemMessage(&msg);
					unguard;
					return false;
				}
			}
		}
	}else if(CSummon *pSummon = pActor->SafeCastSummon())
	{
		if(User *pMaster = pSummon->GetMaster())
		{
			if(User *pUser = pTarget->SafeCastUser())
			{
				if(pUser->pED->antiPkLevelRange > 0 && pUser->pSD->nKarma == 0 && pUser->pSD->bGuilty == false)
				{
					if( (pUser->pSD->nLevel + pUser->pED->antiPkLevelRange) < pMaster->pSD->nLevel)
					{
						//1996	1	a,The attack has been blocked.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
						CSystemMessage msg(1996);
						pMaster->SendSystemMessage(&msg);
						unguard;
						return false;
					}
				}
			}
		}
	}

	typedef bool (*f)(CAttackAction*, CCreature*, CObject*);
	bool ret = f(0x695530L)(pAction, pActor, pTarget);

	unguard;
	return ret;
}

double CreatureAction::OnGotDamageBy(CCreature *pCreature, CCreature *pAttacker, double Damage, int nDmgType, bool DmgFlag)
{
	guard;


	typedef double (*gdb)(CCreature*, CCreature*, double, int, bool);
	gdb _gdb = (gdb) 0x00513970;

	if(pCreature->ValidCreature() && pAttacker->ValidCreature())
	{
		if(g_BossPvPFlag)
		{
			if(pCreature->IsBoss())
			{
				bool affected = true;
				for(UINT n=0;n<g_BossPvPFlagException.size();n++)
				{
					if(g_BossPvPFlagException[n] == pCreature->pSD->nNpcClassID)
					{
						affected = false;
						break;
					}
				}
				if(affected)
				{
					if(User *pUser = pAttacker->SafeCastUser())
					{
						pUser->SetPvPFlag();
						pUser->SetUserInfoChanged();
						pUser->SetCharInfoChanged();
					}else if(pAttacker->IsSummon() || pAttacker->IsPet())
					{
						if(User *pUser = pAttacker->CastSummon()->GetMaster())
						{
							pUser->SetPvPFlag();
							pUser->SetUserInfoChanged();
							pUser->SetCharInfoChanged();
						}
					}
				}
			}



			//Destroy The Base Event
			if(User *pEn = pAttacker->SafeCastUser())
			{
				if(g_TvT.IsNpcDestroyTheBaseTeam(pEn, pCreature->nObjectID))
				{
					Damage = 0;
				}
			}
		}

		if(Damage > 0 && pCreature->pSD->nIsPC)
		{
			if(pCreature->HasAbnormal(163))
			{
				pCreature->DispelByAbnormal(163, true); //at_meditation
			}
		}

		if(pAttacker->pSD->pExData->CastedSkill.skill_id)
		{
			if(pAttacker->pSD->nIsPC)
			{
				if(User *pUser = pAttacker->SafeCastUser())
				{
					Damage *= pUser->GetSkillDmgMultipler(pUser->pSD->pExData->CastedSkill.skill_id, pUser->pSD->pExData->CastedSkill.level);
				}
			}

			CExData *pExData = pAttacker->pSD->pExData;
			CSkillInfoEx *pData = g_SkillDBEx.GetSkillInfoEx(pExData->CastedSkill.skill_id, pExData->CastedSkill.level);
			if(pData)
			{
				if(pData->soulshotBonus > 0 && pExData->SoulshotActivated)
				{
					Damage = Damage * pData->soulshotBonus;
				}
				if(pData->magicShieldBlock)
				{
					Damage = CMagicalShieldDefense::Calculate(pCreature, pAttacker, Damage);
				}
				if(pData->directToHp)
				{
					pExData->AttackDirectToHp = true;
				}
				if(pData->damageBonus != 0)
				{
					Damage = Damage * pData->damageBonus;
				}
			}
		}
		if(pAttacker->IsSummon() || pAttacker->IsPet())
		{
			User *pMaster = pAttacker->CastSummon()->GetMaster();
			if(pMaster->ValidUser())
			{
				//1026	1	a,The summoned monster gave damage of $s1.\0	3	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,damage\0
				CSystemMessage msg(1026);
				msg.AddNumber(static_cast<int>(Damage));
				pMaster->pSocket->SendSystemMessage(&msg);
			}
		}
		if(pCreature->IsSummon() || pCreature->IsPet())
		{
			User *pMaster = pCreature->CastSummon()->GetMaster();
			if(pMaster->ValidUser())
			{
				//1027	1	a,The summoned monster received damage of $s2 caused by $s1.\0	3	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,damage\0
				CSystemMessage msg(1027);
				if(pAttacker->pSD->nIsPC)
				{
					msg.AddText(pAttacker->pSD->wszName);
				}else
				{
					msg.AddNpc(pAttacker->pSD->nNpcClassID);
				}
				msg.AddNumber(static_cast<int>(Damage));
				pMaster->pSocket->SendSystemMessage(&msg);
			}
		}

		//Frenzy damage multipler
		if(g_FrenzyDamageMultipler != 1.0)
		{
			if(pAttacker->pSD->nIsPC == 1 && pCreature->pSD->nIsPC == 0)
			{
				if(pAttacker->HasAbnormal(62))	//ab_pinch
				{
					if((g_FrenzyDamageRaidBoss && pCreature->IsBoss()) || (g_FrenzyDamageZZoldagu && pCreature->IsZZoldagu()))
					{
						Damage *= g_FrenzyDamageMultipler;
					}else
					{
						for(UINT n=0;n < g_FrenzyDamageNpcs.size();n++)
						{
							//g_Log.Add(CLog::Error, "[%d][%d]", g_FrenzyDamageNpcs[n],pCreature->pSD->nNpcClassID);
							if(g_FrenzyDamageNpcs[n] == pCreature->pSD->nNpcClassID)
							{
								Damage *= g_FrenzyDamageMultipler;
								break;
							}
						}
					}

					if(User *pUser = pCreature->SafeCastUser())
					{
						if( g_FrenzyTopDamage > 1.0 )
						{
							Damage = g_FrenzyTopDamage;
						}
					}
				}
			}
		}



		if(pAttacker->ValidUser())
		{
			if (g_FrenzyDamagePlayerMultipler)
			{
				if(pAttacker->pSD->pExData->SkillMod.nFrenzyActivo)
				{
					if(pAttacker->pSD->nIsPC == 1 && pCreature->pSD->nIsPC == 1)
					{

						int nWeaponType = pAttacker->pSD->nWeaponType;

						int wpntype = 0;

						if(User *pUser = pAttacker->GetUser())
							wpntype = pUser->pED->WeapontTypeHand;


//						g_Log.Add(CLog::Error, "[%d][%d]", wpntype, nWeaponType);
						//	SlotRightHand = 128,
						//	SlotRightLeftHand = 16384,
						//	SlotLeftRightHand = 16384,


						if((wpntype == SlotRightLeftHand))
						{
							//none=0; sword= 1; blunt= 2; dagger= 3; pole= 4; fist= 5; bow= 6; etc= 7; dual=8; dualfist=9; fishing_rod=10;
							if(nWeaponType == 0)
								Damage *= g_FrenzyDamagePlayerMultipler_noneTwo;
							else if(nWeaponType == 1)
								Damage *= g_FrenzyDamagePlayerMultipler_swordTwo;
							else if(nWeaponType == 2)
								Damage *= g_FrenzyDamagePlayerMultipler_bluntTwo;
							else if(nWeaponType == 3)
								Damage *= g_FrenzyDamagePlayerMultipler_daggerTwo;
							else if(nWeaponType == 4)
								Damage *= g_FrenzyDamagePlayerMultipler_poleTwo;
							else if(nWeaponType == 5)
								Damage *= g_FrenzyDamagePlayerMultipler_fistTwo;
							else if(nWeaponType == 6)
								Damage *= g_FrenzyDamagePlayerMultipler_bowTwo;
							else if(nWeaponType == 7)
								Damage *= g_FrenzyDamagePlayerMultipler_etcTwo;
							else if(nWeaponType == 8)
								Damage *= g_FrenzyDamagePlayerMultipler_dualTwo;
							else if(nWeaponType == 9)
								Damage *= g_FrenzyDamagePlayerMultipler_dualfistTwo;
							else if(nWeaponType == 10)
								Damage *= g_FrenzyDamagePlayerMultipler_fishing_rodTwo;
						}
						else
						{
							//none=0; sword= 1; blunt= 2; dagger= 3; pole= 4; fist= 5; bow= 6; etc= 7; dual=8; dualfist=9; fishing_rod=10;
							if(nWeaponType == 0)
								Damage *= g_FrenzyDamagePlayerMultipler_none;
							else if(nWeaponType == 1)
								Damage *= g_FrenzyDamagePlayerMultipler_sword;
							else if(nWeaponType == 2)
								Damage *= g_FrenzyDamagePlayerMultipler_blunt;
							else if(nWeaponType == 3)
								Damage *= g_FrenzyDamagePlayerMultipler_dagger;
							else if(nWeaponType == 4)
								Damage *= g_FrenzyDamagePlayerMultipler_pole;
							else if(nWeaponType == 5)
								Damage *= g_FrenzyDamagePlayerMultipler_fist;
							else if(nWeaponType == 6)
								Damage *= g_FrenzyDamagePlayerMultipler_bow;
							else if(nWeaponType == 7)
								Damage *= g_FrenzyDamagePlayerMultipler_etc;
							else if(nWeaponType == 8)
								Damage *= g_FrenzyDamagePlayerMultipler_dual;
							else if(nWeaponType == 9)
								Damage *= g_FrenzyDamagePlayerMultipler_dualfist;
							else if(nWeaponType == 10)
								Damage *= g_FrenzyDamagePlayerMultipler_fishing_rod;
						}
					}
				}
			}
		}

	}
	
	if(User *pUser = pCreature->SafeCastUser())
	{
		if(g_Config.IsSet(CConfig::SIEGE_REPORT) && g_Config.SiegeReportInfo.IsReportDamage())
		{
			if(pUser->pSD->nPledgeID)
			{
				FVector Pos = pUser->pSD->Pos;
				int Killer = 0;
				int PledgeK = 0;
				int Owned = pUser->nDBID;
				int PledgeO = pUser->pSD->nPledgeID;
				
				if(pAttacker->ValidUser())
				{
					Killer = pAttacker->nDBID;
					PledgeK = pAttacker->pSD->nPledgeID;
				}
				else if(pAttacker->IsSummon())
				{
					User *pMaster = pAttacker->CastSummon()->GetMaster();
					if(pMaster->ValidUser())
					{
						Killer = pMaster->nDBID;
						PledgeK = pMaster->pSD->nPledgeID;
					}
				}
				if(Killer && PledgeO)
				{
					CSiegeStat::GetInstance().ReportDamage(pUser->pSD->Pos, Killer, PledgeK, Owned, PledgeO, Damage);
				}
			}
		}
		//TvT event
		if(pUser->pED->tvtUser.status == TvT::UserFighting)
		{
			if(User *pEn = pAttacker->SafeCastUser())
			{
				if(pEn->pED->tvtUser.status == TvT::UserFighting && pEn->pED->tvtUser.team == pUser->pED->tvtUser.team)
				{
					if(pEn->pED->tvtUser.friendlyFire == FALSE)
					{
						Damage = 0;
					}
				}
			}
		}
	}

	//Team abnormal feature
	if(g_TeamAbnormal)
	{
		if(pCreature->IsSameAbnormalTeam(pAttacker))
		{
			Damage = 0;
		}
	}

	if(pCreature->pSD->DuelInfo.DuelID || pAttacker->pSD->DuelInfo.DuelID)
	{
		if(pCreature->pSD->DuelInfo.DuelID != pAttacker->pSD->DuelInfo.DuelID)
		{
			Damage = 0;
		}
		g_DuelSystem.Damaged(pCreature, pAttacker);
	}


	if(pCreature->ValidCreature() && pAttacker->ValidCreature())
	{
		if(pCreature->IsBoss() || pCreature->IsZZoldagu())
		{
			if(User *pEn = pAttacker->SafeCastUser())
			{
				if(g_LureProtection.HandlePlayer(pCreature,pEn))
					Damage = 0;
			}
		}
	}


	if(User *pAttackerUser = pAttacker->SafeCastUser())
	{
		if(User *pUser = pCreature->SafeCastUser())
		{
			if(pAttackerUser->pED->EsMago && pAttackerUser->pED->EsMago)
			{
				Damage *= g_MagoVsMago;
			}
			else if(pAttackerUser->pED->EsMago && !pAttackerUser->pED->EsMago)
			{
				Damage *= g_MagoVsWarrior;
			}
			else if(!pAttackerUser->pED->EsMago && pAttackerUser->pED->EsMago)
			{
				Damage *= g_WarriorVsMago;
			}
			else if(!pAttackerUser->pED->EsMago && !pAttackerUser->pED->EsMago)
			{
				Damage *= g_WarriorVsWarrior;
			}

		}
	}



	
	if(User *pEn = pAttacker->SafeCastUser())
	{
		if(pEn->pED->inZoneCustomEventPvp)
		{
				pEn->pED->EventPvpDanio += Damage;

				if(pEn->pED->EventPvpDanio > 2000000000)
					pEn->pED->EventPvpDanio = 0;
		}
		else
			pEn->pED->EventPvpDanio = 0;


		if(CPledge *pPledge = pEn->GetPledge())
		{
			if(pEn->pED->nInCustomAntiRejunteZone)
			{
				if(User *pUser = pCreature->SafeCastUser())
				{
					if(CPledge *pPledge1 = pUser->GetPledge())
					{
						pPledge->pSD->pPledgeEx->m_Lock.Enter();
						pPledge->pSD->pPledgeEx->ClansPowerData[pPledge1->pSD->nDBID] += Damage;
						pPledge->pSD->pPledgeEx->m_Lock.Leave();
					}

				}
			}
		}

	}


	


	double dRet = _gdb(pCreature, pAttacker, Damage, nDmgType, DmgFlag);

	if(pCreature->ValidCreature() && pAttacker->ValidCreature())
	{
		if(pAttacker->pSD->pExData->AttackDirectToHp)
		{
			pAttacker->pSD->pExData->AttackDirectToHp = 0;
		}
		if(pCreature->pSD->nIsPC && pCreature->pSD->nAlive)
		{
			if(!pAttacker->IsBoss() && !pAttacker->IsZZoldagu())
			{
				if(User *pUser = pCreature->SafeCastUser())
				{
					pUser->TiggerAutoCastSkill(AutoCastSkill::OnDamaged, pAttacker);
				}
			}
		}
		if(pCreature->pSD->fHP < 0)
			pCreature->pSD->fHP = 0;
	}

	unguard;
	return dRet;
}

DWORD* CreatureAction::OnGetSkillUsedTime(CCreature *pCreature, int SkillID, int Level)
{
	if(User *pUser = pCreature->SafeCastUser())
	{
		if(g_Config.IsSet(CConfig::SKILL_REUSE_MANAGER))
		{
			DWORD *stamp = pUser->GetSkillUsedTime(SkillID, Level);
			if(!stamp)
			{
				DWORD newstamp = g_SkillReuseManager.GetReuse(pUser, SkillID, Level);
				if(newstamp > 0)
				{
					pUser->SetSkillUsableTime(SkillID, Level, NULL, (newstamp - GetTickCount()));
					stamp = pUser->GetSkillUsedTime(SkillID, Level);
				}
			}
			return stamp;
		}
	}

	return pCreature->GetSkillUsedTime(SkillID, Level);
}

DWORD* CreatureAction::OnGetItemUsedTime(CCreature *pCreature, int ItemClassID)
{
	if(User *pUser = pCreature->GetUser())
	{
		if(g_Config.IsSet(CConfig::ITEM_REUSE_MANAGER))
		{
			DWORD *stamp = pUser->GetItemUsedTime(ItemClassID);
			if(!stamp)
			{
				DWORD newstamp = g_ItemReuseManager.GetReuse(pUser, ItemClassID);
				if(newstamp > 0)
				{
					CItem *pItem = g_ObjectDB.GetTemplateObject(ItemClassID)->CastItem();
					if(pItem && pItem->pII->reuseDelay > 0)
					{
						DWORD Reuse = newstamp - GetTickCount();
						DWORD nReuse = Reuse / 1000;
						pUser->SetItemUsableTime(ItemClassID, NULL, Reuse);
						stamp = pUser->GetItemUsedTime(ItemClassID);
						/*
						if(nReuse > 1)
						{
							CItemDataEx *pData = g_ItemDBEx.GetItemDataEx(ItemClassID);
							if(pData)
							{
								pUser->GetSocket()->Send("chdddd", 0xFE, 0x49, ItemClassID, pData->GetReuseGroup(), nReuse, (pItem->pII->reuseDelay / 1000));
							}
						}
						*/
					}
				}
			}
			return stamp;
		}
	}
	return pCreature->GetItemUsedTime(ItemClassID);
}

CCreature *CreatureAction::OnDoNothing(LPUINT pSID)
{
	CCreature *pCreature = CCreature::GetCreatureBySID(pSID);
	if(pCreature->ValidCreature())
	{
		if(pCreature->pSD->nAlive)
		{
			CHAR buff[128];
			int nSize = Assemble(buff, 128, "cd", 0x49, pCreature->nObjectID);
			L2Server::BroadcastToNeighborDist(pCreature->nObjectID, &pCreature->pSD->Pos, 4000, nSize, buff);
		}
	}
	return pCreature;
}

void CreatureAction::OnCreatureDestruction(CCreature *pCreature)
{
	// Functions
	typedef void (__fastcall *_CD) (CCreature *);
	_CD xCreatureDestructor = (_CD)0x004D5150L;
	int nState = 0;
	// Destroy all new objects
	try
	{
		if(pCreature->pSD->pExData)
		{
			nState = 1;
			delete pCreature->pSD->pExData;
			pCreature->pSD->pExData = NULL;
		}
		nState = 2;
	}catch(...)
	{
		g_Log.Add(CLog::Error, "[%s] Exception Detected - nState[%d]", __FUNCTION__, nState);
		pCreature->pSD->pExData = NULL;
	}
	// Calling the Original Function
	xCreatureDestructor(pCreature);
}

void CreatureAction::OnDeleteAbnormalStatus(CreatureSharedData *pSD, int nAbnormalType)
{
	guard;

	pSD->DeleteAbnormalStatus(nAbnormalType);

	CCreature *pCreature = CCreature::GetCreatureBySID(&pSD->nObjectID);
	if(pCreature->ValidCreature())
	{
		if(pCreature->ValidUser() || pCreature->IsSummon())
		{
			g_HerbSystem.RestoreBuff(pCreature, nAbnormalType);
		}
	}

	unguard;
}


CCreature *CreatureAction::OnCreatureConstruction(CCreature *pCreature)
{
	// Functions
	typedef CCreature * (__fastcall *_CC) (CCreature *);
	_CC xCreatureConstructor = (_CC)0x004D6030L;
	// Calling the Original Function
	CCreature *pNewCreature = xCreatureConstructor(pCreature);
	if ( pNewCreature->ValidCreature() )
	{
		try
		{
			//Add new objects here
			pNewCreature->pSD->pExData = new CExData();
		}catch(...)
		{
			g_Log.Add(CLog::Error, "[%s] Exception Detected.", __FUNCTION__);
			pNewCreature->pSD->pExData = NULL;
		}
	}
	return pNewCreature;
}

CCreature *CreatureAction::OnCreatureConstructionOther(CCreature *pCreature, CCreature &pOther)
{
	// Functions
	typedef CCreature * (__fastcall *_CC) (CCreature *, CCreature &);
	_CC xCreatureConstructorOther = (_CC)0x004D74C0L;
	// Calling the Original Function
	CCreature *pNewCreature = xCreatureConstructorOther(pCreature, pOther);
	if ( pNewCreature->ValidCreature() )
	{
		try
		{
			//Add new objects here
			pNewCreature->pSD->pExData = new CExData();
		}catch(...)
		{
			g_Log.Add(CLog::Error, "[%s] Exception Detected.", __FUNCTION__);
			pNewCreature->pSD->pExData = NULL;
		}
	}
	return pNewCreature;
}


void CreatureAction::OnBroadcastMagicSkillLanuched(LPVOID pVoid, UINT nObjectID, int Dist, FVector *Pos, int Dist2, const char *format, ...)
{
	va_list tag;
	va_start(tag, format);
	/*c*/ BYTE opCode = va_arg(tag, BYTE);
	/*d*/ DWORD dCasterID = va_arg(tag, DWORD);
	/*d*/ DWORD dSkillID = va_arg(tag, DWORD);
	/*d*/ DWORD dLevel = va_arg(tag, DWORD);
	/*d*/ DWORD dTargetCnt = va_arg(tag, DWORD);
	/*b*/ DWORD dBuffSize = va_arg(tag, DWORD); PUCHAR cBuff = va_arg(tag, PUCHAR);
	va_end(tag);

	if(dSkillID > 1418 && dSkillID < 1424)
	{
		User *pUser = User::GetUserBySID(&nObjectID);
		if(pUser->ValidUser())
		{
			CPacket pck;
			pck.WriteC(0x49);
			pck.WriteD(dCasterID);
			L2Server::BroadcastToNeighborDist(nObjectID, Pos, Dist2, (int)pck.GetSize(), pck.GetBuff());
			return;
		}
	}
	switch(dSkillID)
	{
	case 5130: { /* Volcano */ dSkillID = 1419;	break; }
	case 5131: { /* Tsunami */ dSkillID = 1421;	break; }
	case 5132: { /* Cyclone */ dSkillID = 1420;	break; }
	case 5133: { /* Gehenna */ dSkillID = 1423; break; }
	case 5145: { /* Day of doom */ dSkillID = 1422; break; }
	}

	CPacket packet;
	packet.WriteC(opCode);
	packet.WriteD(dCasterID);
	packet.WriteD(dSkillID);
	packet.WriteD(dLevel);
	packet.WriteD(dTargetCnt);
	packet.WriteB(dBuffSize, cBuff);
	L2Server::BroadcastToNeighborDist(nObjectID, Pos, Dist2, (int)packet.GetSize(), packet.GetBuff());
}


double CreatureAction::OnAttackedBy(CCreature *pCreature, CCreature *pAttacker, double Damage, int nWeaponId, int nAttackType)
{

	typedef double (*f)(CCreature*, CCreature*, double, int, int);

	if(User *pUser = pCreature->SafeCastUser())
	{
		if(pUser->reflectPhysicalDamage && pUser->pSD->nKarma == 0 && pUser->olympiadUser.IsInside() == false && pUser->pSD->nInBattleField == 0)
		{
			if(User *pEnemy = pAttacker->SafeCastUser())
			{
				//TODO FIX FOR FLAG FACTION
				TerritoryData& td = pUser->pSD->pExData->territoryData;
				TerritoryData& td2 = pEnemy->pSD->pExData->territoryData;
						
				if((td.territoryId[FACTION_ZONE] != 0) && (td2.territoryId[FACTION_ZONE] != 0))
				{
					if( pEnemy->pED->nFactionID != pUser->pED->nFactionID )
					{
						//Nothing
					}
				}
				else
				{
					pEnemy->SetPvPFlag();
					pEnemy->SetRelationChangeRequest(1);
				}

			}else if(pAttacker->IsPet() || pAttacker->IsSummon())
			{
				if(User *pEnemy = pAttacker->CastSummon()->GetMaster())
				{
					//TODO FIX FOR FLAG FACTION
					TerritoryData& td = pUser->pSD->pExData->territoryData;
					TerritoryData& td2 = pEnemy->pSD->pExData->territoryData;
							
					if((td.territoryId[FACTION_ZONE] != 0) && (td2.territoryId[FACTION_ZONE] != 0))
					{
						if( pEnemy->pED->nFactionID != pUser->pED->nFactionID )
						{
							//Nothing
						}
					}
					else
					{
						pEnemy->SetPvPFlag();
						pEnemy->SetRelationChangeRequest(1);
					}
				}
			}
		}
	}

	double dRet = f(0x005178D0L)(pCreature, pAttacker, Damage, nWeaponId, nAttackType);

	if(pCreature->ValidUser() && pAttacker->ValidUser())
	{
		if(pCreature->pSD->nCursedOwner && pAttacker->pSD->nHero == 2)
		{
			if(pCreature->pSD->fCP > 1)
			{
				pCreature->pSD->fCP = 1;
				pCreature->UpdateStatus(CCreature::UPDATE_HP);
			}
		}
		if(pAttacker->pSD->nCursedOwner)
		{
			if(pCreature->pSD->fCP > 1)
			{
				pCreature->pSD->fCP = 1;
				pCreature->UpdateStatus(CCreature::UPDATE_HP);
			}
		}
	}
	return dRet;
}