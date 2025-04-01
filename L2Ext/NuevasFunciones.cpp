#include "StdAfx.h"
#include "ObjectDB.h"
#include "BuildCmdHandler.h"
#include "HTMLCacheManager.h"
#include "PlayerAction.h"
#include "DB.h"
#include "HeroSystem.h"
#include "AccountDB.h"
#include "HtmlCache.h"
#include "VisualArmor.h"
#include "TvT.h"
#include "InstantEffects.h"
#include "ReloadSkillData.h"
#include "Achivments.h"
#include "DropRaidsCustom.h"
#include "DropList.h"
#include "OlympiadField.h"
#include "VIPSystem.h"
#include "Rebirth.h"
#include "CliExt.h"
#include "DailyPvP.h"
#include "TerritoryData.h"
#include "OlympiadSystem.h"
#include "NpcDb.h"
#include "Championship.h"
#include "ItemEnchant.h"

TCHAR g_CustomConfigFile[260];

BOOL g_RecargaEnProceso = false;

BOOL g_RecargaDeSkillsEnProceso = false;

BOOL g_MiAutoSkill = FALSE;
INT32 g_MiAutoSkillMaxLevel = 99;

BOOL g_AnnounceSubClass = FALSE;
tstring g_AnnounceSubClassMsg1;
tstring g_AnnounceSubClassMsg2;
tstring g_AnnounceSubClassMsg3;


INT32 m_TerminarPersonajeRewardId = 0;
INT32 m_TerminarPersonajeRewardAmount = 0;

vector<INT32> m_NoSellItems;

BOOL g_CambiarIDSealStones = FALSE;

wstring g_MensajeEnterWorldServer;

BOOL g_MostrarLevelMobs = FALSE;
BOOL g_MostrarBanderasMobs = FALSE;


BOOL g_Servidor_beta_multisell_free = FALSE;

BOOL g_DespawnSummonEnBattle = FALSE;

vector<INT32> m_BorrarSkillsQueNoSonDeLaSubClass;

vector<INT32> m_NoPrivateBuyItems;

BOOL g_NoDropPlayerOnDie = FALSE;

BOOL g_Config_GM_Login_Undying = FALSE;
BOOL g_Config_GM_Login_UnHide = FALSE;

double g_MagicCriticalMultipler = 4.0;

INT32 auraMsgId = 0;

INT32 g_ChangeColorName_ItemId = 0;
INT32 g_ChangeColorName_ItemCount = 0;
INT32 g_ChangeColorTitle_ItemId = 0;
INT32 g_ChangeColorTitle_ItemCount = 0;
INT32 g_ChangeSkin_ItemId = 0;
INT32 g_ChangeSkin_ItemCount = 0;
INT32 g_ChangeSex_ItemId = 0;
INT32 g_ChangeSex_ItemCount = 0;
INT32 g_ChangeHero_ItemId = 0;
INT32 g_ChangeHero_ItemCount = 0;
INT32 g_ChangeKarma_ItemId = 0;
INT32 g_ChangeKarma_ItemCount = 0;
INT32 g_ChangeSubClass_ItemId = 0;
INT32 g_ChangeSubClass_ItemCount = 0;
INT32 g_ChangeSubClass_PonerLevel = 40;
BOOL g_ChangeSubClass_Anunciar = FALSE;
INT32 g_EntregarItemSiTieneTerceraItemId = 0;
INT32 g_EntregarItemSiTieneTerceraItemCount = 0;


INT32 g_ChangeSubClass_MinLevel = 0;

tstring g_ChangeSubClass_Message;

INT32 g_ChangeLevel_ItemId = 0;
INT32 g_ChangeLevel_ItemCount = 0;

INT32 g_ChangeClan8_ItemId = 0;
INT32 g_ChangeClan8_ItemCount = 0;


INT32 g_NewSubClass_PonerLevel = 40;
INT32 g_NewSubClass_ItemId = 0;
BOOL g_NewSubClass_Enable = FALSE;


extern BOOL g_nosleep;


BOOL g_NoPermitirDosTanques = FALSE;


INT32 g_MaximoDeTercerasLogout = 4;

INT32 g_minLevelTrade = 0;

BOOL CLogFilter = false;
list<wstring> lCLogFilter;
list<string> lCLogFilter_Ansi;

BOOL g_CerrarHallesAlSubastar = FALSE;


BOOL g_LimitedSubClass = 0;
INT32 g_TopeSubClassRace_Human = 3;
INT32 g_TopeSubClassRace_Elf = 3;
INT32 g_TopeSubClassRace_DarkElf = 3;
INT32 g_TopeSubClassRace_Orc = 3;
INT32 g_TopeSubClassRace_Dwarf = 3;

BOOL g_LimitedSubClassRace = false;

BOOL OlympiadInstanceEnable = false;
UINT OlympiadInstanceCount = 0;

extern INT32 g_GlobalChat;
extern INT32 g_GlobalChatTrade;
extern INT32 g_ChatShoutLevel;


double g_EnchantArmorModify = 3.0;
double g_EnchantShieldModify = 3.0;

BOOL m_desactivar_death2 = FALSE;


vector<INT32> g_DispelDebuffException;


INT32 g_MinEnchantLevelAuraHero = 0;
BOOL g_HabilitarChatHero = false;

extern UINT g_HeroVoiceDelay;

BOOL g_RequestSaveAllItemDataExDisable = FALSE;

BOOL g_FrenzyDamagePlayerMultipler = FALSE;

double g_FrenzyDamagePlayerMultipler_none = 1.0;
double g_FrenzyDamagePlayerMultipler_sword = 1.0;
double g_FrenzyDamagePlayerMultipler_blunt = 1.0;
double g_FrenzyDamagePlayerMultipler_dagger = 1.0;
double g_FrenzyDamagePlayerMultipler_pole = 1.0;
double g_FrenzyDamagePlayerMultipler_fist = 1.0;
double g_FrenzyDamagePlayerMultipler_bow = 1.0;
double g_FrenzyDamagePlayerMultipler_etc = 1.0;
double g_FrenzyDamagePlayerMultipler_dual = 1.0;
double g_FrenzyDamagePlayerMultipler_dualfist = 1.0;
double g_FrenzyDamagePlayerMultipler_fishing_rod = 1.0;

double g_FrenzyDamagePlayerMultipler_noneTwo = 1.0;
double g_FrenzyDamagePlayerMultipler_swordTwo = 1.0;
double g_FrenzyDamagePlayerMultipler_bluntTwo = 1.0;
double g_FrenzyDamagePlayerMultipler_daggerTwo = 1.0;
double g_FrenzyDamagePlayerMultipler_poleTwo = 1.0;
double g_FrenzyDamagePlayerMultipler_fistTwo = 1.0;
double g_FrenzyDamagePlayerMultipler_bowTwo = 1.0;
double g_FrenzyDamagePlayerMultipler_etcTwo = 1.0;
double g_FrenzyDamagePlayerMultipler_dualTwo = 1.0;
double g_FrenzyDamagePlayerMultipler_dualfistTwo = 1.0;
double g_FrenzyDamagePlayerMultipler_fishing_rodTwo = 1.0;


double g_MagoVsMago = 1.0;
double g_MagoVsWarrior = 1.0;
double g_WarriorVsMago = 1.0;
double g_WarriorVsWarrior = 1.0;


double g_KarmaRateDownExpInc = 1.0;
double g_KarmaRateDownDie = 1.0;
double g_KarmaRateDownExpInc78 = 1.0;
double g_KarmaRateDownDie78 = 1.0;

BOOL BienvenidoNuevoPersonaje = FALSE;
wstring BienvenidoNuevoPersonajeMsg;

INT32 g_ZonePvPSpawnBossRadio = 0;
BOOL g_ZonePvPSpawnBossBarakiel = false;

BOOL g_ZonePvPAutoAttackRejunte = 0;
INT32 g_ZonePvPAutoAttackRejunteDist = 0;
double g_ZonePvPAutoAttackRejunteDamage = 0;
INT32 g_ZonePvPAutoAttackRejunteTimeProtection = 0;
double g_ZonePvPAutoAttackRejunteMinimo = 0;
double g_ZonePvPAutoAttackRejunteResta = 0;





vector<wstring> Hwids;

wstring g_CrackInterfaceCelestine;


std::set<std::wstring> PalabrasProhibidas;

extern BOOL nBlockChatAll;


extern std::vector<MemoryChangeData> m_MemoryChangeData;


TCHAR   gk_teleport_string_01[260];		//<html><body>&$556;<br><br>														0x6ECD12+3
TCHAR   gk_teleport_string_02[260];		//<a action=\"bypass -h teleport_%d_%d_%d\" msg=\"811;%s\">%s</a><br1>				0x6ECEEA+3
TCHAR   gk_teleport_string_03[260];		//<a action=\"bypass -h teleport_%d_%d_%d\" msg=\"811;%s\">%s - %d %s </a><br1>		0x6ECE4A+3

CIOBuffer *pNulled;

extern std::vector<std::pair<std::wstring, int> > AnnounceRaidBossAnticipado;


double g_DropSpoilEnchantWeapon;
double g_DropSpoilEnchantArmor;


INT32 g_DropSpoilEnchantArmorMaxTimeMinutes = 0;
INT32 g_DropSpoilEnchantWeaponMaxTimeMinutes = 0;
INT32 g_DropSpoilEnchantArmorMaxCount = 0;
INT32 g_DropSpoilEnchantWeaponMaxCount = 0;
INT32 g_DropSpoilEnchantArmorContadorDrop = 0;
INT32 g_DropSpoilEnchantWeaponContadorDrop = 0;






extern BOOL g_menu;
extern BOOL g_offline_shop;
extern BOOL g_vip;
extern BOOL g_vote;
extern BOOL g_exp;
extern BOOL g_autoloot;
extern BOOL g_rune;
extern BOOL g_timeleft;
extern BOOL g_restart;
extern BOOL g_goldbar;
extern BOOL g_varmor;
extern BOOL g_engage;
extern BOOL g_divorce;
extern BOOL g_gotolove;
extern BOOL g_ping;
extern BOOL g_online;
extern BOOL g_jointvt;
extern BOOL g_checkvote;
extern BOOL g_showvote;
extern BOOL g_rebirth;
extern BOOL g_captcha;
extern BOOL g_faction;
extern BOOL g_donate;
extern BOOL g_hero;
extern BOOL g_dressme;
extern BOOL g_sellbuff;
extern BOOL g_achiv;
extern BOOL g_help;
extern BOOL g_pvp;
extern BOOL g_torneo;
extern BOOL g_event;
extern BOOL g_rank;
extern BOOL g_nosleep;

double teleportEpicPer = 1.0;

void NuevasFunciones::Init()
{
	LoadINI();
	//Testear
	g_HookManager.WriteMemoryBYTES(0x6F0A96, "79");		//El normal es 0x32  LO CAMBIE PARA QUE SAQUE MAS RAPIDO LOS NPC AL TIRAR LOS NPC
	g_HookManager.WriteMemoryBYTES(0x6f0aaa, "01");		//El normal es 0x64  100mls  LO CAMBIE PARA QUE SAQUE MAS RAPIDO LOS NPC AL TIRAR LOS NPC

	g_HookManager.WriteCall(0x6E558E, NuevasFunciones::NPCBuySellListAssemble, 0);	//NoSellItems--------[ITEMS]-----
	g_HookManager.WriteCall(0x6E5645, NuevasFunciones::NPCBuySellListAssemble, 0);	//NoSellItems--------[ITEMS]-----
	g_HookManager.WriteCall(0x6E6925, NuevasFunciones::NPCBuySellListAssemble, 0);	//NoSellItems--------[ITEMS]-----
	g_HookManager.WriteCall(0x6E68AF, NuevasFunciones::NPCBuySellListAssemble, 0);	//NoSellItems--------[ITEMS]-----

	g_HookManager.WriteRelativeAddress(0x7A882A, 5, &g_MagicCriticalMultipler, 0);	//CSkillEffect_i_hp_drain::Instant()
	g_HookManager.WriteRelativeAddress(0x7A9071, 5, &g_MagicCriticalMultipler, 0);	//CSkillEffect_i_m_attack::Instant()
	g_HookManager.WriteRelativeAddress(0x7A98DA, 5, &g_MagicCriticalMultipler, 0);	//CSkillEffect_i_m_attack_by_hp::Instant()
	g_HookManager.WriteRelativeAddress(0x7AA14B, 5, &g_MagicCriticalMultipler, 0);	//CSkillEffect_i_m_attack_by_dist::Instant()
	g_HookManager.WriteRelativeAddress(0x7AFED5, 5, &g_MagicCriticalMultipler, 0);	//CSkillEffect_i_death_link::Instant()
	g_HookManager.WriteRelativeAddress(0x7B274E, 5, &g_MagicCriticalMultipler, 0);	//CSkillEffect_i_m_attack_over_hit::Instant()


	g_HookManager.WriteCall(0x512855, NuevasFunciones::IncreaseUserPKCount, 0);	//Hook en IncreaseUserPKCount para interceptar el pk y grabar en achivment


//SPOIL RATE COUNT
	g_HookManager.WriteCall(0x7D3176, AddItemToInventorySpoilCount , 0);	//CSkillEffect_i_sweeper::Instant()
	g_HookManager.WriteCall(0x71C398, AddItemToInventorySpoilCount , 0);	//CParty::SweepItem
	g_HookManager.WriteCall(0x71B1E1, AddItemToInventorySpoilCount , 0);	//CParty::SweepItem
	g_HookManager.WriteCall(0x71B54B, AddItemToInventorySpoilCount , 0);	//CParty::SweepItem
	g_HookManager.WriteCall(0x71BB43, AddItemToInventorySpoilCount , 0);	//CParty::SweepItem
	g_HookManager.WriteCall(0x71BFF4, AddItemToInventorySpoilCount , 0);	//CParty::SweepItem


	g_HookManager.WriteCall(0x6BC7B6, AddItemToInventoryNpcAIDrop , 0);	//CNPC::HandleItemManipulation

	g_HookManager.WriteCall(0x51032D, CSkillInfo__CubicActivate , 0);	//CCreature::TimerExpired


	

	g_HookManager.WriteCall(0x814C2E, NuevasFunciones::RequestSaveCharacterInfoPVPCOUNT, 0);	//Hook en User::IncreaseDuelCount para interceptar el pvp y no sumar si esta en clan hwid etc etc
	g_HookManager.WriteCall(0x814959, NuevasFunciones::RequestSaveCharacterInfoPKCOUNT, 0);		//Hook en User::IncreaseKarma para interceptar el pk y no sumar si esta en clan hwid etc etc


	g_HookManager.WriteCall(0x4043C3, GetUser, 0);	//en L2Server::BroadcastToNeighborDist PARA QUITAR EFECTOS VISUALES SI LA PERSONA QUIERE, HEAL Y SOULSHOT



	//LES TIRA MUCHOS CRITICOS SI NO DESACTIVO LA FUNCION DE COlympiadField__Broadcast con el paquete 
	//COlympiadField::Broadcast(this, "chddb", 0xFEi64, 0x2Ai64, nUserServerId, v11, nBufSize, pBuf);
	//void __stdcall COlympiadField::AsyncUpdateSpelledInfo(COlympiadField *this, int nUserServerId, int nObserverId)
	g_HookManager.NopMemory(0x7028DD, 5);		//.text:00000000007028DD                 call    COlympiadField__Broadcast



	//g_HookManager.WriteMemoryBYTES(0x004A83D1, "90 90 90 90 90 90");	

	g_HookManager.WriteRelativeAddress(0x6ECD12, 3, &gk_teleport_string_01, 0);	
	g_HookManager.WriteRelativeAddress(0x6ECEEA, 3, &gk_teleport_string_02, 0);	
	g_HookManager.WriteRelativeAddress(0x6ECE4A, 3, &gk_teleport_string_03, 0);	
	

	g_HookManager.WriteCall(0x403F16, NuevasFunciones::GetIOBuffer, 0);
	g_HookManager.WriteCall(0x474902, NuevasFunciones::GetIOBuffer, 0);
	g_HookManager.WriteCall(0x475574, NuevasFunciones::GetIOBuffer, 0);
	g_HookManager.WriteCall(0x4B0056, NuevasFunciones::GetIOBuffer, 0);
	g_HookManager.WriteCall(0x4BB890, NuevasFunciones::GetIOBuffer, 0);
	g_HookManager.WriteCall(0x4E8152, NuevasFunciones::GetIOBuffer, 0);
	g_HookManager.WriteCall(0x4E8DE5, NuevasFunciones::GetIOBuffer, 0);
	g_HookManager.WriteCall(0x4E9825, NuevasFunciones::GetIOBuffer, 0);
	g_HookManager.WriteCall(0x54A8D4, NuevasFunciones::GetIOBuffer, 0);
	g_HookManager.WriteCall(0x61E3A5, NuevasFunciones::GetIOBuffer, 0);
	g_HookManager.WriteCall(0x620773, NuevasFunciones::GetIOBuffer, 0);
	g_HookManager.WriteCall(0x64EF8F, NuevasFunciones::GetIOBuffer, 0);
	g_HookManager.WriteCall(0x75E1E8, NuevasFunciones::GetIOBuffer, 0);
	g_HookManager.WriteCall(0x7D4E01, NuevasFunciones::GetIOBuffer, 0);
	g_HookManager.WriteCall(0x7D58A9, NuevasFunciones::GetIOBuffer, 0);
	g_HookManager.WriteCall(0x7D5AAF, NuevasFunciones::GetIOBuffer, 0);
	g_HookManager.WriteCall(0x7D5E00, NuevasFunciones::GetIOBuffer, 0);
	g_HookManager.WriteCall(0x82300F, NuevasFunciones::GetIOBuffer, 0);
	g_HookManager.WriteCall(0x840CE9, NuevasFunciones::GetIOBuffer, 0);
	g_HookManager.WriteJump( 0x61E0D1, HookGetIOBuffer, 14);



	//BYTE movrcxr12[8] = {0x49, 0x8B, 0xCC, 0x90, 0x90, 0x90, 0x90, 0x90};
	//WriteProcessMemory(hL2Server,(LPVOID)0x450A63, &movrcxr12, 8, &bw);
	//ARREGLAR TAMAÑO DEL //ANNOUNCE
	//g_HookManager.WriteMemoryBYTES(0x450416, "49 8B CC 90 90 90 90 90");

}





void NuevasFunciones::VerificarEstructuras()
{

	g_Log.Add(CLog::Error, "Struct User               : size[%p]=[0x2D80] | pUser->nObservationTime  [%p]=[0x2D70] ", sizeof(User), offsetof(User, User::language));
	g_Log.Add(CLog::Error, "Struct CCreature          : size[%p]=[0x1500] | CCreature::_unkn14F8     [%p]=[0x14F8] ", sizeof(CCreature), offsetof(CCreature, CCreature::_unkn14F8));
	g_Log.Add(CLog::Error, "Struct CNPC               : size[%p]=[0x19D8] | CNPC::pND                [%p]=[0x19D0] ", sizeof(CNPC), offsetof(CNPC, CNPC::pND));

	g_Log.Add(CLog::Error, "Struct CreatureSharedData : size[%p]=[0x0C0C] | SharedData::notUserdC08  [%p]=[0x0C08] ", sizeof(CreatureSharedData), offsetof(CreatureSharedData, CreatureSharedData::notUserdC08));

//	g_Log.Add(CLog::Error, "Struct COlympiadUser      : size[%p]=[0x0060] | SharedData::m_pUser      [%p]=[0x0058] ", sizeof(COlympiadUser), offsetof(COlympiadUser, COlympiadUser::m_pUser));

	g_Log.Add(CLog::Error, "Struct CUserSocket        : size[%p]=[0x0480] | CUserSocket::pED         [%p]=[0x0478] ", sizeof(CUserSocket), offsetof(CUserSocket, CUserSocket::pED));

	g_Log.Add(CLog::Error, "Struct CParty             : size[%p]=[0x0080] | CParty::itemRoutingType  [%p]=[0x0078] ", sizeof(CParty), offsetof(CParty, CParty::itemRoutingType));




  //  int charId = 6;
  //  std::wstring newCharName = L"rrrrrrrr2";

  //  NuevasFunciones::setCharacterName(charId, newCharName);


}


void NuevasFunciones::LoadINI()
{
	g_RecargaEnProceso = true;

	GetCurrentDirectory(MAX_PATH, g_CustomConfigFile);

	lstrcat(g_CustomConfigFile, m_ConfigsIlExt);

	lstrcat(g_CustomConfigFile, _T("\\Customs.ini"));


	if(!GetPrivateProfileInt(_T("L2SERVER"), _T("SetThreadAffinityMask"), TRUE, g_CustomConfigFile))
	{
		g_HookManager.NopMemory(0x6257C4, 6);
	}

	teleportEpicPer = GetPrivateProfileDouble(_T("TELEPORT_EPICBOSS"), _T("teleportEpicPer"), 1.0, g_CustomConfigFile);
	//g_Log.Add(CLog::Error, "[%s] teleportEpicPer [%f]", __FUNCTION__, teleportEpicPer);


	GetPrivateProfileStringW(_T("GK_HTML"), _T("HTML_01"),L"",gk_teleport_string_01, 260, g_CustomConfigFile);
	GetPrivateProfileStringW(_T("GK_HTML"), _T("HTML_02"),L"",gk_teleport_string_02, 260, g_CustomConfigFile);
	GetPrivateProfileStringW(_T("GK_HTML"), _T("HTML_03"),L"",gk_teleport_string_03, 260, g_CustomConfigFile);


//	g_HookManager.WriteMemoryDWORD(0x6ECD12+3, (DWORD)&gk_teleport_string_01);
//	g_HookManager.WriteMemoryDWORD(0x6ECEEA+3, (DWORD)&gk_teleport_string_02);
//	g_HookManager.WriteMemoryDWORD(0x6ECE4A+3, (DWORD)&gk_teleport_string_03);



	//std::set<std::wstring> PalabrasProhibidas;
	PalabrasProhibidas.clear();
	TCHAR temp45[0x4000];
	if(GetPrivateProfileString(_T("CHAT"), _T("PalabrasProhibidas"), 0, temp45, 0x8000, g_CustomConfigFile))
	{
		wstring params = Parser::Replace(temp45, L';', L' ');

		tstringstream sstr;
		sstr << params;
		wstring wName;
		while(sstr >> wName)
		{
			PalabrasProhibidas.insert(wName);
		}
	}
	//----------------------------------------





	TCHAR temp[0x4000] = { 0 };
	if(GetPrivateProfileString(_T("SkillFactory"), _T("DispelDebuffExceptionList"), 0, temp, 0x8000, g_ConfigFile))
	{
		wstringstream skillStream(temp);
		wstring skillName;
		while(skillStream >> skillName)
		{

			INT32 skill = 0;


			skill = _wtoi(skillName.c_str());

			if(skill > 0)
			{
				g_DispelDebuffException.push_back(skill);
			}
			else
			{
				INT32 skillId = 0, level = 0;
				g_SkillDB.GetSkillIdLevelByName((PWCHAR)skillName.c_str(), &skillId, &level);
				if(skillId > 0)
				{
					g_DispelDebuffException.push_back(skillId);
				}	
			}
		}
	}




	g_GlobalChat = GetPrivateProfileInt(_T("L2Server"), _T("GlobalChat"), FALSE, g_ConfigFile);
	g_GlobalChatTrade = GetPrivateProfileInt(_T("L2Server"), _T("GlobalChatTrade"), FALSE, g_ConfigFile);
	g_ChatShoutLevel = GetPrivateProfileInt(_T("L2Server"), _T("ChatShoutLevel"), 0, g_ConfigFile);


	//SUBCLASS_LIMIT----------------[SUBCLASS_LIMIT]----
	g_LimitedSubClass = GetPrivateProfileInt(_T("SUBCLASS_LIMIT"), _T("Enabled"), 0, g_CustomConfigFile);
	g_TopeSubClassRace_Human = GetPrivateProfileInt(_T("SUBCLASS_LIMIT"), _T("LimitSubClass_Human"), 3, g_CustomConfigFile);
	g_TopeSubClassRace_Elf = GetPrivateProfileInt(_T("SUBCLASS_LIMIT"), _T("LimitSubClass_Elf"), 3, g_CustomConfigFile);
	g_TopeSubClassRace_DarkElf = GetPrivateProfileInt(_T("SUBCLASS_LIMIT"), _T("LimitSubClass_DarkElf"), 3, g_CustomConfigFile);
	g_TopeSubClassRace_Orc = GetPrivateProfileInt(_T("SUBCLASS_LIMIT"), _T("LimitSubClass_Orc"), 3, g_CustomConfigFile);
	g_TopeSubClassRace_Dwarf = GetPrivateProfileInt(_T("SUBCLASS_LIMIT"), _T("LimitSubClass_Dwarf"), 3, g_CustomConfigFile);

	//AUTOSKILL----------------[AUTOSKILL]----
	g_MiAutoSkill = GetPrivateProfileInt(_T("AUTOSKILL"), _T("AutoLearnSkill"), 0, g_CustomConfigFile);
	g_MiAutoSkillMaxLevel = GetPrivateProfileInt(_T("AUTOSKILL"), _T("AutoLearnSkillMaxLevel"), 99, g_CustomConfigFile);
	//----------------------------------------



	g_ZonePvPSpawnBossRadio = GetPrivateProfileInt(_T("NPC"), _T("ZonePvPSpawnBossRadio"), 0, g_CustomConfigFile);
	g_ZonePvPSpawnBossBarakiel = GetPrivateProfileInt(_T("NPC"), _T("ZonePvPSpawnBossBarakiel"), 0, g_CustomConfigFile);


	


	g_ZonePvPAutoAttackRejunte = GetPrivateProfileInt(_T("ZONE_PVP_ANTI_REJUNTE"), _T("Enable"), 0, g_CustomConfigFile);
	g_ZonePvPAutoAttackRejunteDist = GetPrivateProfileInt(_T("ZONE_PVP_ANTI_REJUNTE"), _T("Distance"), 0, g_CustomConfigFile);
	g_ZonePvPAutoAttackRejunteDamage = GetPrivateProfileDouble(_T("ZONE_PVP_ANTI_REJUNTE"), _T("Damage"), 0, g_CustomConfigFile);
	g_ZonePvPAutoAttackRejunteTimeProtection = GetPrivateProfileInt(_T("ZONE_PVP_ANTI_REJUNTE"), _T("TimeProtection"), 0, g_CustomConfigFile);
	g_ZonePvPAutoAttackRejunteMinimo = GetPrivateProfileDouble(_T("ZONE_PVP_ANTI_REJUNTE"), _T("MinDamageCondition"), 0, g_CustomConfigFile);
	g_ZonePvPAutoAttackRejunteResta = GetPrivateProfileDouble(_T("ZONE_PVP_ANTI_REJUNTE"), _T("Resta"), 0, g_CustomConfigFile);

	g_RequestSaveAllItemDataExDisable = GetPrivateProfileInt(_T("CACHED"), _T("RequestSaveAllItemDataExDisable"), 0, g_CustomConfigFile);


	OlympiadInstanceEnable = GetPrivateProfileInt(_T("OLYMPIAD"), _T("UseInstances"), 0, g_CustomConfigFile);
	int OlympiadLimitArenas = GetPrivateProfileInt(_T("OLYMPIAD"), _T("ArenasCounts"), 22, g_CustomConfigFile);
	g_HookManager.WriteMemoryBYTE2(0x0070ED53+2, OlympiadLimitArenas-1);		//SETEAR LIMITE DE ARENAS DE OLYMPIADA EN SETTING.TXT
	g_HookManager.WriteMemoryBYTE2(0x00703C91+2, OlympiadLimitArenas-1);		//SETEAR LIMITE DE ARENAS DE OLYMPIADA EN SETTING.TXT
	g_HookManager.WriteMemoryBYTE2(0x00703EE8+2, OlympiadLimitArenas-1);		//SETEAR LIMITE DE ARENAS DE OLYMPIADA EN SETTING.TXT
	g_HookManager.WriteMemoryBYTE2(0x007043AE+2, OlympiadLimitArenas-1);		//SETEAR LIMITE DE ARENAS DE OLYMPIADA EN SETTING.TXT
	g_HookManager.WriteMemoryBYTE2(0x008ECFEA+2, OlympiadLimitArenas-1);		//SETEAR LIMITE DE ARENAS DE OLYMPIADA EN SETTING.TXT
	g_HookManager.WriteMemoryBYTE2(0x0095E436+3, OlympiadLimitArenas);			//SETEAR LIMITE DE ARENAS DE OLYMPIADA EN SETTING.TXT
	g_HookManager.WriteMemoryBYTE2(0x006FE248+3, OlympiadLimitArenas);			//SETEAR LIMITE DE ARENAS DE OLYMPIADA EN SETTING.TXT
	g_HookManager.WriteMemoryBYTE2(0x006FE274+3, OlympiadLimitArenas);			//SETEAR LIMITE DE ARENAS DE OLYMPIADA EN SETTING.TXT
	g_HookManager.WriteMemoryBYTE2(0x007040DF+1, OlympiadLimitArenas);			//SETEAR LIMITE DE ARENAS DE OLYMPIADA EN SETTING.TXT
	g_HookManager.WriteMemoryBYTE2(0x007043A5+2, OlympiadLimitArenas);			//SETEAR LIMITE DE ARENAS DE OLYMPIADA EN SETTING.TXT
	g_HookManager.WriteMemoryBYTE2(0x007074B3+4, OlympiadLimitArenas);			//SETEAR LIMITE DE ARENAS DE OLYMPIADA EN SETTING.TXT
	g_HookManager.WriteMemoryBYTE2(0x0070DEF5+3, OlympiadLimitArenas);			//SETEAR LIMITE DE ARENAS DE OLYMPIADA EN SETTING.TXT
	g_HookManager.WriteMemoryBYTE2(0x0070E729+2, OlympiadLimitArenas);			//SETEAR LIMITE DE ARENAS DE OLYMPIADA EN SETTING.TXT
	g_HookManager.WriteMemoryBYTE2(0x0070F55A+3, OlympiadLimitArenas);			//SETEAR LIMITE DE ARENAS DE OLYMPIADA EN SETTING.TXT
	g_HookManager.WriteMemoryBYTE2(0x0070FEA9+3, OlympiadLimitArenas);			//SETEAR LIMITE DE ARENAS DE OLYMPIADA EN SETTING.TXT
	g_HookManager.WriteMemoryBYTE2(0x00705748+2, OlympiadLimitArenas-1);		//SETEAR LIMITE DE ARENAS DE OLYMPIADA EN SETTING.TXT
	g_HookManager.WriteMemoryBYTE2(0x00707D5D+2, OlympiadLimitArenas-1);		//SETEAR LIMITE DE ARENAS DE OLYMPIADA EN SETTING.TXT
	g_HookManager.WriteMemoryBYTE2(0x0070A1D4+2, OlympiadLimitArenas-1);		//SETEAR LIMITE DE ARENAS DE OLYMPIADA EN SETTING.TXT
	g_HookManager.WriteMemoryBYTE2(0x0070F19F+2, OlympiadLimitArenas-1);		//SETEAR LIMITE DE ARENAS DE OLYMPIADA EN SETTING.TXT

	if(GetPrivateProfileInt(_T("OLYMPIAD"), _T("UsarCualquierSubclass"), 0, g_CustomConfigFile))
	{
	//	g_HookManager.WriteMemoryBYTES(0x70CC6C, "EB");
	//	g_HookManager.WriteMemoryBYTES(0x006FE4A1, "90 90 90 90 90 90");
	//	g_HookManager.WriteMemoryBYTES(0x006FE4F9, "90 90 90 90 90 90");
	//	g_HookManager.WriteMemoryBYTES(0x6FE6AF, "EB");
	//	g_HookManager.WriteMemoryBYTES(0x6FE7E9, "EB");
	//	g_HookManager.WriteMemoryBYTES(0x6FE8D7, "EB");
	//	g_HookManager.WriteMemoryBYTES(0x6FEA11, "EB");
		//-------------------------------------------------------------------------------------

		//-------------------
//.text:00000000006FE49A                 cmp     dword ptr [rax+98h], 0
//.text:00000000006FE4A1                 jnz     loc_6FE62A
//		g_HookManager.WriteMemoryBYTES(0x6FE49C, "C0");		//cambio de CreatureSharedData->nSubClassIndex a nClass que es CreatureSharedData->nClass
//		g_HookManager.WriteMemoryBYTES(0x6FE4A0, "57");		//Seteo en (int)87 	para que luego verificque si la clase no es tercera
//		g_HookManager.WriteMemoryBYTES(0x6FE4A2, "8C");		//cambio a condicionde JNZ por (GL)MENOR QUE para comparar si la class es menor que la minima tercera
		//-------------------

		g_HookManager.WriteMemoryBYTES(0x6FE49C, "C0");	
		g_HookManager.WriteMemoryBYTES(0x6FE4A0, "57");	
		g_HookManager.WriteMemoryBYTES(0x6FE4A2, "8C");	
		g_HookManager.WriteMemoryBYTES(0x6FE4F4, "C0");	
		g_HookManager.WriteMemoryBYTES(0x6FE4F8, "57");	
		g_HookManager.WriteMemoryBYTES(0x6FE4FA, "8C");	
		g_HookManager.WriteMemoryBYTES(0x6FE6AA, "C0");	
		g_HookManager.WriteMemoryBYTES(0x6FE6AE, "57 7D");	
		g_HookManager.WriteMemoryBYTES(0x6FE7E4, "C0");	
		g_HookManager.WriteMemoryBYTES(0x6FE7E8, "57 7D");	
		g_HookManager.WriteMemoryBYTES(0x6FE8D2, "C0");	
		g_HookManager.WriteMemoryBYTES(0x6FE8D6, "57 7D");	
		g_HookManager.WriteMemoryBYTES(0x6FEA0C, "C0");	
		g_HookManager.WriteMemoryBYTES(0x6FEA10, "57 7D");	
		g_HookManager.WriteMemoryBYTES(0x70CC67, "C0");	
		g_HookManager.WriteMemoryBYTES(0x70CC6B, "57 7D");	


		//-------------------------------------------------------------------------------------
	}
	else
	{
	//	g_HookManager.WriteMemoryBYTES(0x70CC6C, "74");
	//	g_HookManager.WriteMemoryBYTES(0x006FE4A1, "0F 85 83 01 00 00");
	//	g_HookManager.WriteMemoryBYTES(0x006FE4F9, "0F 85 30 01 00 00");
	//	g_HookManager.WriteMemoryBYTES(0x6FE6AF, "74");
	//	g_HookManager.WriteMemoryBYTES(0x6FE7E9, "74");
	//	g_HookManager.WriteMemoryBYTES(0x6FE8D7, "74");
	//	g_HookManager.WriteMemoryBYTES(0x6FEA11, "74");

		g_HookManager.WriteMemoryBYTES(0x6FE49C, "98");	
		g_HookManager.WriteMemoryBYTES(0x6FE4A0, "00");	
		g_HookManager.WriteMemoryBYTES(0x6FE4A2, "85");	
		g_HookManager.WriteMemoryBYTES(0x6FE4F4, "98");	
		g_HookManager.WriteMemoryBYTES(0x6FE4F8, "00");	
		g_HookManager.WriteMemoryBYTES(0x6FE4FA, "85");	
		g_HookManager.WriteMemoryBYTES(0x6FE6AA, "98");	
		g_HookManager.WriteMemoryBYTES(0x6FE6AE, "00 74");	
		g_HookManager.WriteMemoryBYTES(0x6FE7E4, "98");	
		g_HookManager.WriteMemoryBYTES(0x6FE7E8, "00 74");	
		g_HookManager.WriteMemoryBYTES(0x6FE8D2, "98");	
		g_HookManager.WriteMemoryBYTES(0x6FE8D6, "00 74");	
		g_HookManager.WriteMemoryBYTES(0x6FEA0C, "98");	
		g_HookManager.WriteMemoryBYTES(0x6FEA10, "00 74");	
		g_HookManager.WriteMemoryBYTES(0x70CC67, "98");	
		g_HookManager.WriteMemoryBYTES(0x70CC6B, "00 74");	

	}





	//DitanceToTargetMove----------------[OTROS]----
	INT DitanceToTargetMove = GetPrivateProfileInt(_T("L2Server"), _T("DitanceToTargetMove"), 100, g_CustomConfigFile);
	g_HookManager.WriteMemoryDWORD(0x6AAD40, DitanceToTargetMove);
	g_HookManager.WriteMemoryDWORD(0x6AAD47, DitanceToTargetMove+10);
	//----------------------------------------

	//DitanceToTargetMove----------------[DYES]----
	BOOL g_UsarCualquierDye = GetPrivateProfileInt(_T("DYES"), _T("UsarCualquierDYE"), FALSE, g_CustomConfigFile);
	if (g_UsarCualquierDye)
		g_HookManager.WriteMemoryBYTES(0x5D7090, "B0 01 C3 90 90 90 90");
	else
		g_HookManager.WriteMemoryBYTES(0x5D7090, "48 8B C4 48 83 EC 68");
	//----------------------------------------


	int g_ComprarHallLevel = GetPrivateProfileInt(_T("CLANHALL"), _T("ComprarHallLevel"), 4, g_CustomConfigFile);
	g_HookManager.WriteMemoryBYTE2(0x0043B3A4, g_ComprarHallLevel);		//COMPRAR HALLES A PARTIR DE LEVEL 4

	g_CerrarHallesAlSubastar  = GetPrivateProfileInt(_T("CLANHALL"), _T("CerrarHallesAlSubastar"), 0, g_CustomConfigFile);

	if(g_CerrarHallesAlSubastar)
		g_HookManager.WriteCall(0x41E751, NuevasFunciones::CerrarHallesAutomaticamente , 0);


	int g_MejorarHtmlAuctioner = GetPrivateProfileInt(_T("CLANHALL"), _T("MejorarHtmlAuctioner"), 4, g_CustomConfigFile);
	{
		g_HookManager.WriteMemoryBYTES(0x41A13D, "90 90 90 90 90 90");			//para ver mejor el auctioner
		g_HookManager.WriteMemoryBYTES(0x97be26, "38");							//para ver mejor el auctioner
		g_HookManager.WriteMemoryBYTES(0x97bf1c, "38 00 35");					//para ver mejor el auctioner
		g_HookManager.WriteMemoryBYTES(0x97BDFC, "31");							//para ver mejor el auctioner
	}


	//ANNOUNCE SUBCLASS--------[SUBCLASS]-----

	g_LimitedSubClassRace = GetPrivateProfileInt(_T("SUBCLASS"), _T("LimitedSubClassRace"), 0, g_CustomConfigFile);

	g_AnnounceSubClass = GetPrivateProfileInt(_T("SUBCLASS"), _T("AnnounceSubClass"), 0, g_CustomConfigFile);


	TCHAR temp1[8192];
	if(GetPrivateProfileString(_T("SUBCLASS"), _T("AnnounceSubClassMsg1"), 0, temp1, 8190, g_CustomConfigFile))
	{
		g_AnnounceSubClassMsg1 = temp1;
	}
	TCHAR temp2[8192];
	if(GetPrivateProfileString(_T("SUBCLASS"), _T("AnnounceSubClassMsg2"), 0, temp2, 8190, g_CustomConfigFile))
	{
		g_AnnounceSubClassMsg2 = temp2;
	}
	TCHAR temp3[8192];
	if(GetPrivateProfileString(_T("SUBCLASS"), _T("AnnounceSubClassMsg3"), 0, temp3, 8190, g_CustomConfigFile))
	{
		g_AnnounceSubClassMsg3 = temp3;
	}

	m_TerminarPersonajeRewardId = GetPrivateProfileInt(_T("SUBCLASS"), _T("TerminarPersonajeRewardId"), 0, g_CustomConfigFile);
	m_TerminarPersonajeRewardAmount = GetPrivateProfileInt(_T("SUBCLASS"), _T("TerminarPersonajeRewardAmount"), 0, g_CustomConfigFile);


	//----------------------------------------

	m_desactivar_death2 = GetPrivateProfileInt(_T("SKILLS"), _T("desactivar_death2"), 0, g_CustomConfigFile);



	g_MinEnchantLevelAuraHero = GetPrivateProfileInt(_T("HERO_WEAPONS"), _T("MinEnchantLevelAuraHero"), 0, g_CustomConfigFile);
	g_HabilitarChatHero = GetPrivateProfileInt(_T("HERO_WEAPONS"), _T("HabilitarChatHero"), 0, g_CustomConfigFile);



	g_HeroVoiceDelay = GetPrivateProfileInt(_T("OlympiadSystem"), _T("HeroChatDelay"), 0, g_ConfigFile);


	//NoSellItems--------[ITEMS]-----
	m_NoSellItems.clear();
	TCHAR temp4[0x4000];
	if(GetPrivateProfileString(_T("ITEMS"), _T("NoSellItems"), 0, temp4, 0x8000, g_CustomConfigFile))
	{
		wstring params = Parser::Replace(temp4, L';', L' ');

		tstringstream sstr;
		sstr << params;
		wstring wName;
		while(sstr >> wName)
		{
			m_NoSellItems.push_back(g_ObjectDB.GetClassIdFromName(wName.c_str()));
		}
	}
	//----------------------------------------

	//CambiarIDSealStonesPorAA--------[ITEMS]-----
	g_CambiarIDSealStones = GetPrivateProfileInt(_T("ITEMS"), _T("CambiarIDSealStonesPorAA"), FALSE, g_CustomConfigFile);
	//----------------------------------------

	//MensajeEnterWorldServer--------[L2SERVER]-----
	TCHAR temp5[8192];
	if(GetPrivateProfileString(_T("L2SERVER"), _T("MensajeEnterWorldServer"), 0, temp5, 8190, g_CustomConfigFile))
	{
		g_MensajeEnterWorldServer = temp5;
	}
	//----------------------------------------


	//MensajeEnterWorldServer--------[INTERFACE]-----
	TCHAR temp9[8192];
	if(GetPrivateProfileString(_T("INTERFACE"), _T("MensajeCelestine"), 0, temp9, 8190, g_CustomConfigFile))
	{
		g_CrackInterfaceCelestine = temp9;
	}
	//----------------------------------------



	//MostrarLevelMobs--------[NPC]-----
	g_MostrarLevelMobs  = GetPrivateProfileInt(_T("NPC"), _T("MostrarLevelMobs"), 0, g_CustomConfigFile);
	//----------------------------------------
	
	//MostrarBanderasMobs--------[NPC]-----
	g_MostrarBanderasMobs  = GetPrivateProfileInt(_T("NPC"), _T("MostrarBanderasMobs"), 0, g_CustomConfigFile);
	//----------------------------------------



	g_Servidor_beta_multisell_free  = GetPrivateProfileInt(_T("SERVER_BETA"), _T("MultisellGratis"), 0, g_CustomConfigFile);







	g_DespawnSummonEnBattle = GetPrivateProfileInt(_T("SUMMONS"), _T("DespawnSummonEnBattle"), FALSE, g_CustomConfigFile);


	if (GetPrivateProfileInt(_T("SUMMONS"), _T("SummonPetEnBattle"), FALSE, g_CustomConfigFile))
	{
		g_HookManager.WriteMemoryBYTES(0x007CB16F, "EB");					//SUMONEAR LOS PETS/STRIDER MIENTRAS ESTOY EN COMBATE
	}

	if (GetPrivateProfileInt(_T("SUMMONS"), _T("RideSummonPetEnBattle"), FALSE, g_CustomConfigFile))
	{
		g_HookManager.WriteMemoryBYTES(0x00834BC5, "EB");					//SUBIRSE AL SUMMON ESTANDO EN COMBATE
		g_HookManager.WriteMemoryBYTES(0x00834C74, "EB");					//SUBIRSE AL SUMMON ESTANDO EN COMBATE
	}



	m_BorrarSkillsQueNoSonDeLaSubClass.clear();
	TCHAR temp6[0x4000];
	if(GetPrivateProfileString(_T("SKILLS"), _T("BorrarSkillsQueNoSonDeLaSubClass"), 0, temp6, 0x8000, g_CustomConfigFile))
	{
		wstringstream skillStream(temp6);
		wstring skillName;
		while(skillStream >> skillName)
		{
			INT32 skillId = 0, level = 0;
			g_SkillDB.GetSkillIdLevelByName((PWCHAR)skillName.c_str(), &skillId, &level);
			if(skillId > 0)
			{
				m_BorrarSkillsQueNoSonDeLaSubClass.push_back(skillId);
			}			
		}
	}

	m_NoPrivateBuyItems.clear();
	TCHAR temp7[0x4000];
	if(GetPrivateProfileString(_T("ITEMS"), _T("NoPrivateBuyItems"), 0, temp7, 0x8000, g_CustomConfigFile))
	{
		wstring params = Parser::Replace(temp7, L';', L' ');

		tstringstream sstr;
		sstr << params;
		wstring wName;
		while(sstr >> wName)
		{
			m_NoPrivateBuyItems.push_back(g_ObjectDB.GetClassIdFromName(wName.c_str()));
		}
	}

	g_NoDropPlayerOnDie = GetPrivateProfileInt(_T("ITEMS"), _T("NoDropPlayerOnDie"), FALSE, g_CustomConfigFile);


		int id = 1;
		int memoryaddr = 0x00960C1E;
		BYTE Data[] = { 0x6C, 0x32, 0x45, 0x58, 0x45, 0x54, 0x6F, 0x6F, 0x6C, 0x53, 0x74, 0x72, 0x69, 0x70, 0x4D, 0x65 };
		int cantidad = 16;

	TCHAR sTemp[0x8000];
	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(_T("MENSAGE_BIENVENIDA"), _T("BienvenidoNuevoPersonajeMsg"), 0, sTemp, 8192, g_CustomConfigFile))
	{
		BienvenidoNuevoPersonajeMsg = sTemp;
	}

	BienvenidoNuevoPersonaje = GetPrivateProfileInt(_T("MENSAGE_BIENVENIDA"), _T("Enable"), FALSE, g_CustomConfigFile);

	


	g_Config_GM_Login_Undying = GetPrivateProfileInt(_T("GM_OPTIONS"), _T("EnterWorld_Undying"), 0, g_CustomConfigFile);
	g_Config_GM_Login_UnHide = GetPrivateProfileInt(_T("GM_OPTIONS"), _T("EnterWorld_UnHide"), 0, g_CustomConfigFile);

	if (GetPrivateProfileInt(_T("GM_OPTIONS"), _T("BlockWhispMessagePlayerToGM"), TRUE, g_CustomConfigFile))
		g_HookManager.WriteMemoryBYTES(0x881C07, "05");
	else
		g_HookManager.WriteMemoryBYTES(0x881C07, "00");

	if(GetPrivateProfileInt(_T("GM_OPTIONS"), _T("UseItemsWithHide"), 0, g_CustomConfigFile))
		g_HookManager.WriteMemoryBYTES(0x811F88, "EB");
	else
		g_HookManager.WriteMemoryBYTES(0x811F88, "74");


	g_DropSpoilEnchantWeapon = GetPrivateProfileDouble(_T("SPOIL_ENCHANTS"), _T("DropSpoilEnchantWeapon"), 1.0, g_CustomConfigFile);
	g_DropSpoilEnchantArmor = GetPrivateProfileDouble(_T("SPOIL_ENCHANTS"), _T("DropSpoilEnchantArmor"), 1.0, g_CustomConfigFile);





	g_MagoVsMago = GetPrivateProfileDouble(_T("BALANCED"), _T("MagoVsMago"), 1.0, g_CustomConfigFile);
	g_MagoVsWarrior = GetPrivateProfileDouble(_T("BALANCED"), _T("MagoVsWarrior"), 1.0, g_CustomConfigFile);

	g_WarriorVsMago = GetPrivateProfileDouble(_T("BALANCED"), _T("WarriorVsMago"), 1.0, g_CustomConfigFile);
	g_WarriorVsWarrior = GetPrivateProfileDouble(_T("BALANCED"), _T("WarriorVsWarrior"), 1.0, g_CustomConfigFile);



	g_DropSpoilEnchantArmorMaxTimeMinutes = GetPrivateProfileInt(_T("SPOIL_ENCHANTS"), _T("EnchantArmorMaxTimeMinutes"), 0, g_CustomConfigFile);
	g_DropSpoilEnchantWeaponMaxTimeMinutes = GetPrivateProfileInt(_T("SPOIL_ENCHANTS"), _T("EnchantWeaponMaxTimeMinutes"), 0, g_CustomConfigFile);
	g_DropSpoilEnchantArmorMaxCount = GetPrivateProfileInt(_T("SPOIL_ENCHANTS"), _T("EnchantArmorMaxCount"), 0, g_CustomConfigFile);
	g_DropSpoilEnchantWeaponMaxCount = GetPrivateProfileInt(_T("SPOIL_ENCHANTS"), _T("EnchantWeaponMaxCount"), 0, g_CustomConfigFile);




	g_menu = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("menu"), TRUE, g_ConfigFile);
	g_offline_shop = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("offline_shop"), TRUE, g_ConfigFile);
	g_vip = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("vip"), TRUE, g_ConfigFile);
	g_vote = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("vote"), TRUE, g_ConfigFile);
	g_exp = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("exp"), TRUE, g_ConfigFile);
	g_autoloot = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("autoloot"), TRUE, g_ConfigFile);
	g_rune = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("rune"), TRUE, g_ConfigFile);
	g_timeleft = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("timeleft"), TRUE, g_ConfigFile);
	g_restart = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("restart"), TRUE, g_ConfigFile);
	g_goldbar = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("goldbar"), TRUE, g_ConfigFile);
	g_varmor = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("varmor"), TRUE, g_ConfigFile);
	g_engage = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("engage"), TRUE, g_ConfigFile);
	g_divorce = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("divorce"), TRUE, g_ConfigFile);
	g_gotolove = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("gotolove"), TRUE, g_ConfigFile);
	g_ping = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("ping"), TRUE, g_ConfigFile);
	g_online = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("online"), TRUE, g_ConfigFile);
	g_jointvt = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("jointvt"), TRUE, g_ConfigFile);
	g_checkvote = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("checkvote"), TRUE, g_ConfigFile);
	g_showvote = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("showvote"), TRUE, g_ConfigFile);
	g_rebirth = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("rebirth"), TRUE, g_ConfigFile);
	g_captcha = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("captcha"), TRUE, g_ConfigFile);
	g_faction = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("faction"), TRUE, g_ConfigFile);
	g_donate = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("donate"), TRUE, g_ConfigFile);
	g_hero = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("hero"), TRUE, g_ConfigFile);
	g_dressme = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("dressme"), TRUE, g_ConfigFile);
	g_sellbuff = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("sellbuff"), TRUE, g_ConfigFile);
	g_achiv = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("achiv"), TRUE, g_ConfigFile);
	g_help = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("help"), TRUE, g_ConfigFile);
	g_torneo = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("torneo"), TRUE, g_ConfigFile);
	g_pvp = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("pvp"), TRUE, g_ConfigFile);
	g_event = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("event"), TRUE, g_ConfigFile);
	g_rank = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("rank"), TRUE, g_ConfigFile);
	g_nosleep = GetPrivateProfileInt(_T("COMMAND_PLAYER"), _T("nosleep"), TRUE, g_ConfigFile);






	g_MagicCriticalMultipler = GetPrivateProfileDouble(_T("DANIO_GENERAL"), _T("CriticalSkillDamageBonusPer"), 4.0, g_CustomConfigFile);


	g_FrenzyDamagePlayerMultipler = GetPrivateProfileInt(_T("DANIO_GENERAL"), _T("FrenzyDamagePlayerMultipler"), FALSE, g_CustomConfigFile);

	g_FrenzyDamagePlayerMultipler_none = GetPrivateProfileDouble(_T("DANIO_GENERAL"), _T("FrenzyDamagePlayerMultipler_none"), 1.0, g_CustomConfigFile);
	g_FrenzyDamagePlayerMultipler_sword = GetPrivateProfileDouble(_T("DANIO_GENERAL"), _T("FrenzyDamagePlayerMultipler_sword"), 1.0, g_CustomConfigFile);
	g_FrenzyDamagePlayerMultipler_blunt = GetPrivateProfileDouble(_T("DANIO_GENERAL"), _T("FrenzyDamagePlayerMultipler_blunt"), 1.0, g_CustomConfigFile);
	g_FrenzyDamagePlayerMultipler_dagger = GetPrivateProfileDouble(_T("DANIO_GENERAL"), _T("FrenzyDamagePlayerMultipler_dagger"), 1.0, g_CustomConfigFile);
	g_FrenzyDamagePlayerMultipler_pole = GetPrivateProfileDouble(_T("DANIO_GENERAL"), _T("FrenzyDamagePlayerMultipler_pole"), 1.0, g_CustomConfigFile);
	g_FrenzyDamagePlayerMultipler_fist = GetPrivateProfileDouble(_T("DANIO_GENERAL"), _T("FrenzyDamagePlayerMultipler_fist"), 1.0, g_CustomConfigFile);
	g_FrenzyDamagePlayerMultipler_bow = GetPrivateProfileDouble(_T("DANIO_GENERAL"), _T("FrenzyDamagePlayerMultipler_bow"), 1.0, g_CustomConfigFile);
	g_FrenzyDamagePlayerMultipler_etc = GetPrivateProfileDouble(_T("DANIO_GENERAL"), _T("FrenzyDamagePlayerMultipler_etc"), 1.0, g_CustomConfigFile);
	g_FrenzyDamagePlayerMultipler_dual = GetPrivateProfileDouble(_T("DANIO_GENERAL"), _T("FrenzyDamagePlayerMultipler_dual"), 1.0, g_CustomConfigFile);
	g_FrenzyDamagePlayerMultipler_dualfist = GetPrivateProfileDouble(_T("DANIO_GENERAL"), _T("FrenzyDamagePlayerMultipler_dualfist"), 1.0, g_CustomConfigFile);
	g_FrenzyDamagePlayerMultipler_fishing_rod = GetPrivateProfileDouble(_T("DANIO_GENERAL"), _T("FrenzyDamagePlayerMultipler_fishing_rod"), 1.0, g_CustomConfigFile);

	g_FrenzyDamagePlayerMultipler_noneTwo = GetPrivateProfileDouble(_T("DANIO_GENERAL"), _T("FrenzyDamagePlayerMultipler_noneTwo"), 1.0, g_CustomConfigFile);
	g_FrenzyDamagePlayerMultipler_swordTwo = GetPrivateProfileDouble(_T("DANIO_GENERAL"), _T("FrenzyDamagePlayerMultipler_swordTwo"), 1.0, g_CustomConfigFile);
	g_FrenzyDamagePlayerMultipler_bluntTwo = GetPrivateProfileDouble(_T("DANIO_GENERAL"), _T("FrenzyDamagePlayerMultipler_bluntTwo"), 1.0, g_CustomConfigFile);
	g_FrenzyDamagePlayerMultipler_daggerTwo = GetPrivateProfileDouble(_T("DANIO_GENERAL"), _T("FrenzyDamagePlayerMultipler_daggerTwo"), 1.0, g_CustomConfigFile);
	g_FrenzyDamagePlayerMultipler_poleTwo = GetPrivateProfileDouble(_T("DANIO_GENERAL"), _T("FrenzyDamagePlayerMultipler_poleTwo"), 1.0, g_CustomConfigFile);
	g_FrenzyDamagePlayerMultipler_fistTwo = GetPrivateProfileDouble(_T("DANIO_GENERAL"), _T("FrenzyDamagePlayerMultipler_fistTwo"), 1.0, g_CustomConfigFile);
	g_FrenzyDamagePlayerMultipler_bowTwo = GetPrivateProfileDouble(_T("DANIO_GENERAL"), _T("FrenzyDamagePlayerMultipler_bowTwo"), 1.0, g_CustomConfigFile);
	g_FrenzyDamagePlayerMultipler_etcTwo = GetPrivateProfileDouble(_T("DANIO_GENERAL"), _T("FrenzyDamagePlayerMultipler_etcTwo"), 1.0, g_CustomConfigFile);
	g_FrenzyDamagePlayerMultipler_dualTwo = GetPrivateProfileDouble(_T("DANIO_GENERAL"), _T("FrenzyDamagePlayerMultipler_dualTwo"), 1.0, g_CustomConfigFile);
	g_FrenzyDamagePlayerMultipler_dualfistTwo = GetPrivateProfileDouble(_T("DANIO_GENERAL"), _T("FrenzyDamagePlayerMultipler_dualfistTwo"), 1.0, g_CustomConfigFile);
	g_FrenzyDamagePlayerMultipler_fishing_rodTwo = GetPrivateProfileDouble(_T("DANIO_GENERAL"), _T("FrenzyDamagePlayerMultipler_fishing_rodTwo"), 1.0, g_CustomConfigFile);




	g_KarmaRateDownExpInc = GetPrivateProfileDouble(_T("KARMA"), _T("KarmaRateDownExpInc"), 1.0, g_CustomConfigFile);
	g_KarmaRateDownDie = GetPrivateProfileDouble(_T("KARMA"), _T("KarmaRateDownDie"), 1.0, g_CustomConfigFile);
	g_KarmaRateDownExpInc78 = GetPrivateProfileDouble(_T("KARMA"), _T("KarmaRateDown78ExpInc"), 1.0, g_CustomConfigFile);
	g_KarmaRateDownDie78 = GetPrivateProfileDouble(_T("KARMA"), _T("KarmaRateDown78Die"), 1.0, g_CustomConfigFile);


	auraMsgId = GetPrivateProfileInt(_T("PvPAnnounce"), _T("AuraMessageId"), 0, g_CustomConfigFile);


	if(GetPrivateProfileInt(_T("SSQ"), _T("Disable_SSQSystem_OnCastleSiegeEnd"), 0, g_CustomConfigFile))
	{
		g_HookManager.WriteMemoryBYTES(0x004A69B4,"90 90 90 90 90");
	}


	g_EnchantArmorModify = GetPrivateProfileDouble(_T("ENCHANTS_STATS"), _T("EnchantArmorModify"), 3.0, g_CustomConfigFile);
	g_HookManager.WriteRelativeAddress(0x629B4C, 4, &g_EnchantArmorModify, 0);	
	
	g_EnchantShieldModify = GetPrivateProfileDouble(_T("ENCHANTS_STATS"), _T("EnchantShieldModify"), 3.0, g_CustomConfigFile);
	g_HookManager.WriteRelativeAddress(0x629EED, 4, &g_EnchantShieldModify, 0);	
	




	TCHAR temp8[0x8000];

	GetPrivateProfileString(_T("SERVICES"), _T("ChangeColorName_ItemName"),0,temp8,0x8000, g_CustomConfigFile);
	g_ChangeColorName_ItemId = g_ObjectDB.GetClassIdFromName(temp8);
	g_ChangeColorName_ItemCount = GetPrivateProfileInt(_T("SERVICES"), _T("ChangeColorName_ItemCount"), FALSE, g_CustomConfigFile);


	GetPrivateProfileString(_T("SERVICES"), _T("ChangeColorTitle_ItemName"),0,temp8,0x8000, g_CustomConfigFile);
	g_ChangeColorTitle_ItemId = g_ObjectDB.GetClassIdFromName(temp8);
	g_ChangeColorTitle_ItemCount = GetPrivateProfileInt(_T("SERVICES"), _T("ChangeColorTitle_ItemCount"), FALSE, g_CustomConfigFile);

	GetPrivateProfileString(_T("SERVICES"), _T("ChangeSkin_ItemName"),0,temp8,0x8000, g_CustomConfigFile);
	g_ChangeSkin_ItemId = g_ObjectDB.GetClassIdFromName(temp8);
	g_ChangeSkin_ItemCount = GetPrivateProfileInt(_T("SERVICES"), _T("ChangeSkin_ItemCount"), FALSE, g_CustomConfigFile);


	GetPrivateProfileString(_T("SERVICES"), _T("ChangeSex_ItemName"),0,temp8,0x8000, g_CustomConfigFile);
	g_ChangeSex_ItemId = g_ObjectDB.GetClassIdFromName(temp8);
	g_ChangeSex_ItemCount = GetPrivateProfileInt(_T("SERVICES"), _T("ChangeSex_ItemCount"), FALSE, g_CustomConfigFile);


	GetPrivateProfileString(_T("SERVICES"), _T("ChangeHero_ItemName"),0,temp8,0x8000, g_CustomConfigFile);
	g_ChangeHero_ItemId = g_ObjectDB.GetClassIdFromName(temp8);
	g_ChangeHero_ItemCount = GetPrivateProfileInt(_T("SERVICES"), _T("ChangeHero_ItemCount"), FALSE, g_CustomConfigFile);


	GetPrivateProfileString(_T("SERVICES"), _T("ChangeKarma_ItemName"),0,temp8,0x8000, g_CustomConfigFile);
	g_ChangeKarma_ItemId = g_ObjectDB.GetClassIdFromName(temp8);
	g_ChangeKarma_ItemCount = GetPrivateProfileInt(_T("SERVICES"), _T("ChangeKarma_ItemCount"), FALSE, g_CustomConfigFile);


	GetPrivateProfileString(_T("SERVICES"), _T("ChangeSubClass_ItemName"),0,temp8,0x8000, g_CustomConfigFile);
	g_ChangeSubClass_ItemId = g_ObjectDB.GetClassIdFromName(temp8);
	g_ChangeSubClass_ItemCount = GetPrivateProfileInt(_T("SERVICES"), _T("ChangeSubClass_ItemCount"), FALSE, g_CustomConfigFile);
	g_ChangeSubClass_PonerLevel = GetPrivateProfileInt(_T("SERVICES"), _T("ChangeSubClass_PonerLevel"), 40, g_CustomConfigFile);
	g_ChangeSubClass_MinLevel = GetPrivateProfileInt(_T("SERVICES"), _T("ChangeSubClass_MinLevel"), 1, g_CustomConfigFile);



	


	GetPrivateProfileString(_T("SERVICES"), _T("ChangeLevel_ItemName"),0,temp8,0x8000, g_CustomConfigFile);
	g_ChangeLevel_ItemId = g_ObjectDB.GetClassIdFromName(temp8);
	g_ChangeLevel_ItemCount = GetPrivateProfileInt(_T("SERVICES"), _T("ChangeLevel_ItemCount"), FALSE, g_CustomConfigFile);


	GetPrivateProfileString(_T("SERVICES"), _T("ChangeClan8_ItemName"),0,temp8,0x8000, g_CustomConfigFile);
	g_ChangeClan8_ItemId = g_ObjectDB.GetClassIdFromName(temp8);
	g_ChangeClan8_ItemCount = GetPrivateProfileInt(_T("SERVICES"), _T("ChangeClan8_ItemCount"), FALSE, g_CustomConfigFile);


	

	GetPrivateProfileString(_T("SUBCLASS_NUEVO"), _T("NewSubClass_ItemName"),0,temp8,0x8000, g_CustomConfigFile);
	g_NewSubClass_ItemId = g_ObjectDB.GetClassIdFromName(temp8);
	g_NewSubClass_PonerLevel = GetPrivateProfileInt(_T("SUBCLASS_NUEVO"), _T("NewSubClass_PonerLevel"), 40, g_CustomConfigFile);
	g_NewSubClass_Enable = GetPrivateProfileInt(_T("SUBCLASS_NUEVO"), _T("NewSubClass_Enable"), 0, g_CustomConfigFile);



	
	g_ChangeSubClass_Anunciar = GetPrivateProfileInt(_T("SERVICES"), _T("ChangeSubClass_Anunciar"), FALSE, g_CustomConfigFile);


	g_EntregarItemSiTieneTerceraItemId = GetPrivateProfileInt(_T("SERVICES"), _T("ChangeSubClass_EntregarItemSiTieneTerceraItemId"), 0, g_CustomConfigFile);
	g_EntregarItemSiTieneTerceraItemCount = GetPrivateProfileInt(_T("SERVICES"), _T("ChangeSubClass_EntregarItemSiTieneTerceraItemCount"), 0, g_CustomConfigFile);




	g_minLevelTrade = GetPrivateProfileInt(_T("TRADE"), _T("MinLevelTrade"), 0, g_CustomConfigFile);


	TCHAR temp25[8192];
	if(GetPrivateProfileString(_T("SERVICES"), _T("ChangeSubClass_Message"), 0, temp25, 8190, g_CustomConfigFile))
	{
		g_ChangeSubClass_Message = temp25;
	}


	g_NoPermitirDosTanques = GetPrivateProfileInt(_T("SUBCLASS"), _T("NoPermitirDosTanques"), 0, g_CustomConfigFile);


	g_MaximoDeTercerasLogout = GetPrivateProfileInt(_T("SUBCLASS"), _T("LimiteMaximoDeTerceras"), 4, g_CustomConfigFile);



	if(GetPrivateProfileInt(_T("OTROS"), _T("CLogFilter"), 0, g_CustomConfigFile))
	{
		wstringstream file(ReadFileW(g_ChangeFolders.CLogFilter_txt));
		if(file)
		{
			lCLogFilter.clear();
			lCLogFilter_Ansi.clear();
			int lineCount = 0;
			wstring line;
			while(getline(file, line))
			{
				lineCount++;
				if(line.size() > 4)
				{
					if( line[0] == L'/' || line[0] == L';' )
						continue;

					if( line.find(L"line_begin") == 0 )
					{
						wstring wName = Parser::ParseOptionStringConEspacios(line, L"msg=");
			
						if(wName.size() > 0)
						{
							lCLogFilter.push_back(wName);
							lCLogFilter_Ansi.push_back(WStringToString(wName));
						}else
						{
							g_Log.Add(CLog::Error, "CLogFilter.txt Parser error line[%d]!", __FUNCTIONW__, lineCount);
						}
					}
				}
			}
		}else
		{
			g_Log.Add(CLog::Error, "[%s] Cannot find ..//script//script//CLogFilter.txt !", __FUNCTION__);
		}
	}
	else
	{
		lCLogFilter.clear();
		lCLogFilter_Ansi.clear();
	}



	if (GetPrivateProfileInt(_T("SOULSHOTS"), _T("NoSendSystemMessageUse"), FALSE, g_CustomConfigFile))
	{
		g_HookManager.NopMemory(0x7ADAB8, 5);								//342	1	Power of the spirits enabled.	7	79	9B	B0	-1	
		g_HookManager.NopMemory(0x7ADCF2, 5);								//533	1	Power of Mana enabled.	7	79	9B	B0	-1	
		g_HookManager.WriteCall(0x4EC451, CSocket::SendUseItem, 0);		//para no enviar Use  Soulshot: Grade.....
	}
	else
	{
		g_HookManager.WriteMemoryBYTES(0x007ADAB8,"E8 63 2E C6 FF");
		g_HookManager.WriteMemoryBYTES(0x007ADCF2,"E8 29 2C C6 FF");
		g_HookManager.WriteMemoryBYTES(0x004EC451,"E8 BA 9A 2E 00");
	}



	g_HookManager.WriteCall(0x514899, CSocket::SendDamage, 0);	
	g_HookManager.WriteCall(0x514BAC, CSocket::SendDamage2, 0);	
	g_HookManager.WriteCall(0x514906, CSocket::SendDamage2, 0);	





	//ANNOUNCES CUSTOM EVENTO 500K SIEGE GODDAR
	g_HookManager.WriteCall(0x811A05, NuevasFunciones::CHolyThing__SendWarningMessage, 0);	
	g_HookManager.WriteCall(0x4A80EB, NuevasFunciones::CResidence_SetPledge, 0);	
	g_HookManager.WriteCall(0x4A6AE6, NuevasFunciones::CPledge__GetPledgeName, 0);	





	if(GetPrivateProfileString(_T("NpcMod"), _T("BossListState"), 0, temp, 0x8000, g_ConfigFile))
	{
		wstringstream npcStream(temp);
		wstring npcName;
		while(npcStream >> npcName)
		{
			INT32 npcId = g_ObjectDB.GetClassIdFromName(npcName.c_str());
//			NuevasFunciones::AddBossState(npcId);
		}
	}

	
	g_DropRaidsCustom.LoadINI();


	//g_Achivments.LoadINI();

	g_RecargaEnProceso = false;
}

//----------------------------------------------------------------------------------------------------------------------



CIOBuffer* NuevasFunciones::GetIOBuffer()
{
    try
    {
        return reinterpret_cast<CIOBuffer*(*)()>(0x61E050L)();
    }
    catch(...)
    {
		
		g_Log.Add(CLog::Error, "[%s] CIOBuffer!! Exploit", __FUNCTION__);

        return pNulled;
    }
}



void NuevasFunciones::AddBossState(int id)
{
		if(CNPC *pNpc = CObject::GetObjectBySID(id)->CastNPC())
		{
			CustomRaidBossData data;
				data.id = pNpc->pSD->nNpcClassID;
				data.nameServer = pNpc->pSD->wszName;
				data.nameClient = g_NpcDb.GetClientNameByClassId(pNpc->pSD->nNpcClassID);;
				data.level = pNpc->pSD->nLevel;
				data.estado = 0;
				data.fechaSpawn = 0;
				data.fechaMuerto = 0;
				data.ultimoGolpe = L"";
				data.ultimoGolpeClan = L"";

				RaidBossDataMap.push_back(std::make_pair(id, &data));
		}
}

void NuevasFunciones::SetBossState(int id, int estado, int fechaSpawn, int fechaMuerto, wstring ultimoGolpe, wstring ultimoGolpeClan)
{
	for (vector<pair<int, CustomRaidBossData*>>::iterator it = RaidBossDataMap.begin(); it != RaidBossDataMap.end();) 
	{
		if(it->second->id == id)
		{
			//Iter->second->nameServer = nameServer;
			//Iter->second->nameClient = nameClient;
			//Iter->second->level = level;
			it->second->estado = estado;
			it->second->fechaSpawn = fechaSpawn;
			it->second->fechaMuerto = fechaMuerto;
			it->second->ultimoGolpe = ultimoGolpe;
			it->second->ultimoGolpeClan = ultimoGolpeClan;
			break;
		}
	}
}

//CustomRaidBossData* NuevasFunciones::GetBossState(int id)
//{
//	for (vector<pair<int, CustomRaidBossData*>>::iterator it = RaidBossDataMap.begin(); it != RaidBossDataMap.end();) 
//	{
//		if(it->second->id == id)
//		{
//			return it->second;
//			break;
//		}
//	}
//
//	return NULL;
//}

//RaidBossDataMap* NuevasFunciones::GetListBossState(int minLevel, int maxLevel)
//{

//	for (vector<pair<int, CustomRaidBossData*>>::iterator it = RaidBossDataMap.begin(); it != RaidBossDataMap.end();) 
//	{
//		if(it->second->id == id)
//		{
//			return it->second;
//			break;
//		}
//	}
//	return data;
//}


//CHolyThing__SendWarningMessage
void NuevasFunciones::CHolyThing__SendWarningMessage(DWORD instance)
{
	wstring m_Message = L"2902;;;Un clan esta casteando el castillo!!!.";
	Utils::BroadcastToAllUser_Announce(m_Message.c_str());

	typedef void(*f)(DWORD);
	return f(0x5DDBB0L)(instance);
}

void NuevasFunciones::CResidence_SetPledge(DWORD instance, CPledge *pPledge)
{
	wstring m_Message = L"2907;;;El clan $clanName ha tomado el castillo!!!.";

								size_t pos = m_Message.find(L"$clanName");
								while(pos != wstring::npos)
								{
									m_Message = m_Message.replace(pos, 9, pPledge->pSD->wszClanName);
									pos = m_Message.find(L"$clanName");
								}


	Utils::BroadcastToAllUser_Announce(m_Message.c_str());

	typedef void(*f)(DWORD, CPledge*);
	return f(0x776FB0L)(instance, pPledge);
}


WCHAR* NuevasFunciones::CPledge__GetPledgeName(CPledge *pPledge)
{

/*
	wstring m_Message = L"2907;;;El clan *** $clanName *** ha ha ganado el Asedio con un premio de $500.000 en Efectivo!!!.";

	size_t pos = m_Message.find(L"$clanName");
	while(pos != wstring::npos)
	{
		m_Message = m_Message.replace(pos, 9, pPledge->pSD->wszClanName);
		pos = m_Message.find(L"$clanName");
	}
	
	Utils::BroadcastToAllUser_Announce(m_Message.c_str());
*/

	typedef WCHAR*(*f)(CPledge*);
	return f(0x761A70L)(pPledge);
}



void NuevasFunciones::EnviarCrackInterfaceCelestine(CUserSocket *pSocket)
{
	CHAR pck[8190];
	int nSize = Assemble(pck, 8190, "cddSS", 0x4A, 0, 18, L"", g_CrackInterfaceCelestine.c_str());
	//L2Server::BroadcastToAllUser(nSize, pck);
	pSocket->Send("b", nSize, pck); 
}



void NuevasFunciones::EnviarHooksAlCliente(CUserSocket *pSocket)
{
	for (size_t i = 0; i < m_MemoryChangeData.size(); i++)
	{
		MemoryChangeData& detect = m_MemoryChangeData[i];

		int id = detect.id;
		int memoryaddr = detect.memoryaddr;
		int cantidad = detect.cantidad;
		wstring dll = detect.dllName;
		pSocket->Send("cdSddb", 0x87, 19, dll.c_str(), memoryaddr, cantidad, cantidad, detect.Data);
	}
}


User* NuevasFunciones::GetUser(CSocket *pSocket)
{
	User *pUser = pSocket->GetUser(pSocket);
	if(pUser->ValidUser())
	{
		if (!pUser->pSD->pExData->stopAnimations)
			return pUser;
		else
			return 0;
	}

	return pUser;
}

void NuevasFunciones::IncreaseUserPKCount(CDB* pInstance, User* pUser)
{
	g_Achivments.SetUser_CaptureTheFlag(pUser);
	g_DB.IncreaseUserPKCount(pUser);
}


void NuevasFunciones::RequestSaveCharacterInfoPVPCOUNT(CDB* pInstance, User *pUser, bool notActive, bool force)
{

	if(pUser->SafeCastUser()->pED->nNoSumarPVPniPk)
	{
		if(pUser->pSD->nPvpCount> 0)
		{
			pUser->lpSharedDataLock->Lock(__FILEW__, __LINE__);
			--pUser->pSD->nPvpCount;
			pUser->lpSharedDataLock->Unlock();
		}
	}

	typedef void (*f)(CDB*, User*, bool, bool);
	f(0x0053A250L)(pInstance, pUser, notActive, force);
}


void NuevasFunciones::RequestSaveCharacterInfoPKCOUNT(CDB* pInstance, User *pUser, bool notActive, bool force)
{

	if(pUser->SafeCastUser()->pED->nNoSumarPVPniPk)
	{
		if(pUser->pSD->nPkCount> 0)
		{
			pUser->lpSharedDataLock->Lock(__FILEW__, __LINE__);
			--pUser->pSD->nPkCount;
			pUser->lpSharedDataLock->Unlock();
		}
	}

	typedef void (*f)(CDB*, User*, bool, bool);
	f(0x0053A250L)(pInstance, pUser, notActive, force);
}


void NuevasFunciones::AddItemToInventorySpoilCount(CCreature* this1, int itemId, int amount, bool isPick, int enchanted, int blessed, int eroded)
{

	bool dropear = true;
	guard;

		if(itemId == 1877 || itemId == 4043 || itemId == 4044 || itemId == 1872 || itemId == 1867 || itemId == 1878 || itemId == 1871 || itemId == 1870 || itemId == 1879 || itemId == 1889 || itemId == 1884 || itemId == 1881 || itemId == 4042 || itemId == 1869 || itemId == 5549 || itemId == 1895 || itemId == 1876 || itemId == 4039 || itemId == 4040 || itemId == 4041 || itemId == 1882 || itemId == 1893 || itemId == 1874 || itemId == 1873 || itemId == 1880 || itemId == 1880 || itemId == 1864 || itemId == 1875 || itemId == 1866 || itemId == 1868 || itemId == 1865)
		{
			if(CItem *pItem = g_ObjectDB.GetTemplateObject(itemId)->SafeCastItem())
			{
				if (pItem->pSID->nConsumeType == ConsumeStackable)
				{
					double cantidad = static_cast<double>(amount);
					cantidad *= g_DropList.GetSpoilCountsRate();
					amount = static_cast<int>(cantidad);

					if (amount < 1)
						amount=1;
				}
			}
		}

		/*if(User *pUser = this1->SafeCastUser())
		{
			if(itemId == 959)		//scrl_of_ench_wp_s
			{
				dropear = false;
				
				if(pUser->pED->DropSpoilEnchantWeapon > 100)
				{
					dropear = true;
					pUser->pED->DropSpoilEnchantWeapon = 1;
				}
			}
			else if(itemId == 960)	//scrl_of_ench_am_s
			{
				dropear = false;
				
				if(pUser->pED->DropSpoilEnchantArmor > 100)
				{
					dropear = true;
					pUser->pED->DropSpoilEnchantArmor = 1;
				}
			}
		}*/




		if(itemId == 960)	//scrl_of_ench_am_s
		{
			if(g_DropSpoilEnchantArmorContadorDrop < g_DropSpoilEnchantArmorMaxCount)
			{
				g_DropSpoilEnchantArmorContadorDrop++;
			}
			else
				dropear = false;
		}

		if(itemId == 959)	//scrl_of_ench_wp_s
		{
			if(g_DropSpoilEnchantWeaponContadorDrop < g_DropSpoilEnchantWeaponMaxCount)
			{
				g_DropSpoilEnchantWeaponContadorDrop++;
			}
			else
				dropear = false;
		}





	unguard;

	if(dropear)
	{
		typedef void (__fastcall * f)(CCreature*, int, int, bool, int, int, int);
		f(0x004EF130L)(this1, itemId, amount, isPick, enchanted, blessed, eroded);
	}
}


void __stdcall NuevasFunciones::CSkillInfo__CubicActivate(CSkillInfo *pSkillInfo, CCreature *pSource, LPVOID pCubicInfo, CObject *pTarget)
{
	if(!g_RecargaDeSkillsEnProceso)
	{
		typedef void (__fastcall * f)(CSkillInfo *, CCreature *, LPVOID, CObject *);
		f(0x00798BE0L)(pSkillInfo, pSource, pCubicInfo, pTarget);
	}
}


void NuevasFunciones::AddItemToInventoryNpcAIDrop(CCreature* this1, int itemId, int amount, bool isPick, int enchanted, int blessed, int eroded)
{

	if(g_DropList.ItemForNotDrop(itemId))
		amount=0;

	typedef void (__fastcall * f)(CCreature*, int, int, bool, int, int, int);
	f(0x004EF130L)(this1, itemId, amount, isPick, enchanted, blessed, eroded);
}



//NoSellItems--------[ITEMS]-----
int NuevasFunciones::NPCBuySellListAssemble(CHAR *pBuf, int nBufLen, char *format, short nItemType1, int nObjectID, int nItemID, int nCount, short nItemType2, short nUnknown1, int nBodyPart, short nEnchantLevel, short nUnknown2, short nUnknown3, int nPrice)
{
	if (!g_RecargaEnProceso)
	{
		for(UINT n=0;n<m_NoSellItems.size();n++)
		{
			if(m_NoSellItems[n] == nItemID)
				return 0;
		}
	}
		
	typedef int (__fastcall * f)(CHAR *, int , char *, short , int , int , int , short , short , int , short , short , short , int );
	return f(0x0061EF80L)(pBuf, nBufLen, format, nItemType1, nObjectID, nItemID, nCount, nItemType2, nUnknown1, nBodyPart, nEnchantLevel, nUnknown2, nUnknown3, nPrice);
}


bool NuevasFunciones::CustomsBypass(User* pUser, wstring wBypass)
{
	if( wBypass.find(L"xxxxxxxxxxxxxxxx?") == 0)
	{
		return true;
	}else if(wBypass.find(L"va_equip_test?") == 0)
	{
		UINT armorId = Parser::GetBypassValueInt(wBypass.c_str(), L"id");
		g_VisualArmor.OnEquipTest(pUser, armorId);
		return true;
	}else if(wBypass.find(L"test_hats?") == 0)
	{
		UINT id = Parser::GetBypassValueInt(wBypass.c_str(), L"id");

		pUser->pED->hats_test_timestamp = time(0) + 10;
		pUser->pED->hats_test_id = id;
		PlayerAction::OnTeleportToLocation(pUser, static_cast<int>(pUser->pSD->Pos.x), static_cast<int>(pUser->pSD->Pos.y), static_cast<int>(pUser->pSD->Pos.z), 0);

		return true;
	}else if(wBypass.find(L"test_shield?") == 0)
	{
		UINT id = Parser::GetBypassValueInt(wBypass.c_str(), L"id");

		pUser->pED->shield_test_timestamp = time(0) + 10;
		pUser->pED->shield_test_id = id;
		PlayerAction::OnTeleportToLocation(pUser, static_cast<int>(pUser->pSD->Pos.x), static_cast<int>(pUser->pSD->Pos.y), static_cast<int>(pUser->pSD->Pos.z), 0);

		return true;
	}else if(wBypass.find(L"test_weapon?") == 0)
	{
		UINT id = Parser::GetBypassValueInt(wBypass.c_str(), L"id");

		pUser->pED->weapon_test_timestamp = time(0) + 10;
		pUser->pED->weapon_test_id = id;
		PlayerAction::OnTeleportToLocation(pUser, static_cast<int>(pUser->pSD->Pos.x), static_cast<int>(pUser->pSD->Pos.y), static_cast<int>(pUser->pSD->Pos.z), 0);

		return true;
	}else if( wBypass.find(L"admin?") == 0)
	{
		wstring wsCommand = CParser::GetBypassValueConEspacios(wBypass, L"comando=");
		if(pUser->pSD->nBuilder)
		{
			if(!CBuilderCommand::Handle2(pUser, wsCommand))
				CBuilderCommand::Handle(pUser, wsCommand);
		}
		return true;
	}else if( wBypass.find(L"html?") == 0)
	{
		wstring comando = CParser::GetBypassValue(wBypass, L"link=");
		const WCHAR* wHtml = g_HtmlCache.Get(comando);
		if(wHtml)
		{
			pUser->ShowHTML(comando.c_str(), wHtml, 0);
		}else
		{
			g_Log.Add(CLog::Error, "[%s] Cannot find html html custom!", __FUNCTION__);
		}
		return true;
	}else if( wBypass.find(L"player_set_namecolor?") == 0)
	{
		int nColorInt;
		wstring nColor = CParser::GetBypassValue(wBypass, L"color=");
		swscanf(nColor.c_str(), L"%x", &nColorInt);
		if(nColorInt > -1)
		{
			if(!pUser->DeleteItemInInventory(g_ChangeColorName_ItemId, g_ChangeColorName_ItemCount))
			{
				CSystemMessage msg1(SystemMessage::S1_POPUP);
				msg1.AddText(L"No tienes los items necesarios.");
				pUser->pSocket->SendSystemMessage(&msg1);
				return true;
			}

			g_DB.RequestSaveNameColor(pUser->pSD->nDBID,nColorInt);
			g_DB.RequestLoadNameTitleColor(pUser->nDBID);
			pUser->pED->nameColorEx = nColorInt;
			pUser->SetCharInfoChanged();
			pUser->SetUserInfoChanged();

			g_Logger.Add(L"User[%s] cambio color de nombre a [%d]", pUser->pSD->wszName, nColorInt);
			CSystemMessage msg2(SystemMessage::S1_POPUP);
			msg2.AddText(L"El color de tu nombre se modifico correctamente, si no ves el cambio, debes reloguear tu personaje..");
			pUser->pSocket->SendSystemMessage(&msg2);
		}
		return true;
	}else if( wBypass.find(L"player_set_titlecolor?") == 0)
	{
		int nColorInt;
		wstring nColor = CParser::GetBypassValue(wBypass, L"color=");
		swscanf(nColor.c_str(), L"%x", &nColorInt);
		if(nColorInt > -1)
		{
			if(!pUser->DeleteItemInInventory(g_ChangeColorTitle_ItemId, g_ChangeColorTitle_ItemCount))
			{
				CSystemMessage msg1(SystemMessage::S1_POPUP);
				msg1.AddText(L"No tienes los items necesarios.");
				pUser->pSocket->SendSystemMessage(&msg1);
				return true;
			}
			g_DB.RequestSaveTitleColor(pUser->pSD->nDBID,nColorInt);
			g_DB.RequestLoadNameTitleColor(pUser->nDBID);
			pUser->pED->titleColorEx = nColorInt;
			pUser->SetCharInfoChanged();
			pUser->SetUserInfoChanged();

			g_Logger.Add(L"User[%s] cambio color de titulo a [%d]", pUser->pSD->wszName, nColorInt);
			CSystemMessage msg2(SystemMessage::S1_POPUP);
			msg2.AddText(L"El color de tu titulo se modifico correctamente, si no ves el cambio, debes reloguear tu personaje..");
			pUser->pSocket->SendSystemMessage(&msg2);
		}
		return true;
	}else if( wBypass.find(L"player_test_namecolor?") == 0)
	{
		wstring nColor = CParser::GetBypassValue(wBypass, L"color=");
		int nColorInt;
		swscanf(nColor.c_str(), L"%x", &nColorInt);

		if(nColorInt > -1)
		{
			pUser->pED->nicknameColor = nColorInt;
			pUser->SetCharInfoChanged();
			pUser->SetUserInfoChanged();
		}
		return true;
	}else if( wBypass.find(L"player_bonus_code?") == 0)
	{
/*		wstring nBonus = CParser::GetBypassValue(wBypass, L"code=");
		int nBunusInt = -1;
		swscanf(nBonus.c_str(), L"%x", &nBunusInt);


//INT64 g_BonusCode
//g_BonusCode_Message
//INT32 g_BonusCode_Reward_Id
//INT32 g_BonusCode_Reward_Count


		if(nBunusInt > -1)
		{
			if(nBunusInt == g_BonusCode)
			{

				if(utilizado)
				{
					tstring announce = g_BonusCode_Message;
					announce = Utils::ReplaceString(announce, _T("[player_name]"), pUser->pSD->wszName, true);
					Utils::BroadcastToAllUser_Announce(announce.c_str());


					CSystemMessage msg2(SystemMessage::S1_POPUP);
					msg2.AddText(L"Felicitaciones por cargar el Bonus Code.");
					pUser->pSocket->SendSystemMessage(&msg2);

					pUser->AddItemToInventory(g_BonusCode_Reward_Id, g_BonusCode_Reward_Count);
					g_Logger.Add(L"User[%s] Ingreso BonusCode y recibio ItemId[%d] ItemCount[%d] ", pUser->pSD->wszName, g_BonusCode_Reward_Id, g_BonusCode_Reward_Count);

					g_BonusCode = 1691985498156 ;

				}
				else
				{
					CSystemMessage msg2(SystemMessage::S1_POPUP);
					msg2.AddText(L"Este Bonus Code ya fue utilizado.");
					pUser->pSocket->SendSystemMessage(&msg2);
				}
			}

		}*/
		return true;
	}else if( wBypass.find(L"exchange_weapon_ticket?") == 0)
	{
		int MinEnchant = 0, Reward_Id = 0;
		bool MessageError = false;

		MinEnchant = Parser::GetBypassValueInt(wBypass.c_str(), L"MinEnchant");
		Reward_Id = Parser::GetBypassValueInt(wBypass.c_str(), L"Reward");

		if(pUser->ValidUser())
		{
			CSharedItemData *pData = pUser->GetEquipedWeapon();
			if(pData)
			{
				CItem *pItem = pUser->inventory.GetItemBySID(pData->nObjectID);
				if(pItem->IsValidItem())
				{
					bool armaCorrecta = false;
					int itemId = pItem->pSID->nItemID;

					if(itemId >= 6580 && itemId <= 6610)			//todas menos los draconic
					{
						armaCorrecta = true;
					}
					else if(itemId >= 7575 && itemId <= 7578)		//los draconic
					{
						armaCorrecta = true;
					}
					else if(itemId >= 6364 && itemId <= 6372)		//todas menos los draconic sin sa
					{
						armaCorrecta = true;
					}
					else if(itemId == 6579)		//arcana_mace sin sa
					{
						armaCorrecta = true;
					}


					if(armaCorrecta)
					{
						if(pItem->pSID->nEnchantLevel == MinEnchant)
						{
							
							CItemEnchant::CustomEnchantItem(pUser, pItem, 0);
							pUser->AddItemToInventory(Reward_Id, 1);

							g_Logger.Add(L"User[%s] cambio arma +[%d] por ticket [%d] ", pUser->pSD->wszName, itemId, Reward_Id);
							CSystemMessage msg2(SystemMessage::S1_POPUP);
							msg2.AddText(L"Tu arma ha bajado a +0 y recibiste el Ticket que buscabas.");
							pUser->pSocket->SendSystemMessage(&msg2);

						}
						else
						{
							CSystemMessage msg2(SystemMessage::S1_POPUP);
							msg2.AddText(L"El arma no cumple con los requisitos.");
							pUser->pSocket->SendSystemMessage(&msg2);
							MessageError = true;
						}
					}
					else
					{
						CSystemMessage msg2(SystemMessage::S1_POPUP);
						msg2.AddText(L"El arma no cumple con los requisitos.");
						pUser->pSocket->SendSystemMessage(&msg2);
						MessageError = true;
					}
				}
			}else
			{
				CSystemMessage msg2(SystemMessage::S1_POPUP);
				msg2.AddText(L"Debes colocarte el arma enchantada.");
				pUser->pSocket->SendSystemMessage(&msg2);	
				MessageError = true;
			}


			if(MessageError)
			{
				const WCHAR* pFile = 0;
				pFile = g_HTMLCacheManager.GetHTMLFile( L"quest_tool_ticketexchange.htm", pUser->pSD->bLang);
				if(pFile)
				{
					PlayerAction::ShowHTML(pUser, L"quest_tool_ticketexchange.htm", pFile, 0);
				}
			}
		}




		return true;

	}else if( wBypass.find(L"streamers?") == 0)
	{
		const WCHAR* pFile = 0;
//		if(g_HtmlCache.IsEnabled())
//		{
//			pFile = g_HtmlCache.Get(L"streamers.htm");
//		}else
//		{
			pFile = g_HTMLCacheManager.GetHTMLFile( L"streamers.htm", pUser->pSD->bLang);
//		}
		if(pFile)
		{
			PlayerAction::ShowHTML(pUser, L"streamers.htm", pFile, 0);
		}
		return true;
	}else if( wBypass.find(L"player_test_titlecolor?") == 0)
	{
		wstring nColor = CParser::GetBypassValue(wBypass, L"color=");

		int nColorInt;
		swscanf(nColor.c_str(), L"%x", &nColorInt);

		if(nColorInt > -1)
		{
			pUser->pED->titleColor = nColorInt;
			pUser->SetCharInfoChanged();
			pUser->SetUserInfoChanged();
		}
		return true;
	}else if( wBypass.find(L"ver_boss_list?") == 0)
	{

		UINT id = Parser::GetBypassValueInt(wBypass.c_str(), L"id");

		const WCHAR* wHtml = g_HtmlCache.Get(L"npc_gk_global-21.htm");

		if(id == 1)
		{
			wHtml = g_HtmlCache.Get(L"npc_gk_global-21.htm");
		}
		else if(id == 2)
		{
			wHtml = g_HtmlCache.Get(L"npc_gk_global-22.htm");
		}



		if(wHtml)
		{

			//AnnounceRaidBossAnticipadoActualizar

			wstring html(wHtml);

			for (vector<pair<wstring, int>>::iterator Iter = AnnounceRaidBossAnticipado.begin(); Iter != AnnounceRaidBossAnticipado.end(); ++Iter) {

				if(Iter->second > 0)
				{
					time_t timestamp = static_cast<time_t>(Iter->second);
					tm* localTime = localtime(&timestamp);
					int hour = localTime->tm_hour;
					int minute = localTime->tm_min;
					WCHAR tmp[32] = { 0 };
					swprintf(tmp, 32, L"%02d:%02d", hour, minute);
					html = Utils::ReplaceString(html, Iter->first, tmp, false);
				}
				else if(Iter->second == -1)
				{
					wstring tmp = L"<font color=FF0000>DEAD</font>";
					html = Utils::ReplaceString(html, Iter->first, tmp.c_str(), false);
				}
				else
				{
					wstring tmp = L"<font color=00FF00>VIVO</font>";
					html = Utils::ReplaceString(html, Iter->first, tmp.c_str(), false);
				}

				
			}

			pUser->ShowHTML(L"npc_gk_global-21.htm", html.c_str(), 0);
		}else
		{
			g_Log.Add(CLog::Error, "[%s] Cannot find npc_gk_global-21.htm!", __FUNCTION__);
		}



	}else if( wBypass.find(L"player_cambiar_skin?") == 0)
	{
		int nClass = -1;

		if( wBypass.find(L"player_cambiar_skin? Human_Fighter") == 0)
			nClass = 0;
		if( wBypass.find(L"player_cambiar_skin? Human_Mystic") == 0)
			nClass = 10;
		if( wBypass.find(L"player_cambiar_skin? Elven_Fighter") == 0)
			nClass = 18;
		if( wBypass.find(L"player_cambiar_skin? Elven_Mystic") == 0)
			nClass = 28;
		if( wBypass.find(L"player_cambiar_skin? Dark_Fighter") == 0)
			nClass = 31;
		if( wBypass.find(L"player_cambiar_skin? Dark_Mystic") == 0)
			nClass = 38;
		if( wBypass.find(L"player_cambiar_skin? Orc_Fighter") == 0)
			nClass = 44;
		if( wBypass.find(L"player_cambiar_skin? Orc_Mystic") == 0)
			nClass = 49;
		if( wBypass.find(L"player_cambiar_skin? Dwarven_Fighter") == 0)
			nClass = 53;

		if(!pUser->DeleteItemInInventory(g_ChangeSkin_ItemId, g_ChangeSkin_ItemCount))
		{
			CSystemMessage msg1(SystemMessage::S1_POPUP);
			msg1.AddText(L"No tienes los items necesarios.");
			pUser->pSocket->SendSystemMessage(&msg1);
			return true;
		}

		g_DB.RequestSaveSkin(pUser->pSD->nDBID,nClass);
		g_AccountDB.AddCustomSkin(pUser->pSD->nDBID, nClass);
		pUser->pED->actualizarApariencias = true;
		pUser->SetCharInfoChanged();
		pUser->SetUserInfoChanged();

		g_Logger.Add(L"User[%s] cambio de skin a [%d]", pUser->pSD->wszName, nClass);
		CSystemMessage msg2(SystemMessage::S1_POPUP);
		msg2.AddText(L"Se ha cambiado tu Skin con exito. Ahora debes reloguear tu personaje.");
		pUser->pSocket->SendSystemMessage(&msg2);

		return true;
	}else if( wBypass.find(L"player_cambiar_subclass?") == 0)
	{
		int nClass = -1;
		int nClassTercera =  -10;
		if( wBypass.find(L"player_cambiar_subclass? Gladiator") == 0)
		{
			nClass = 2;
			nClassTercera = 88;
		}
		if( wBypass.find(L"player_cambiar_subclass? Warlord") == 0)
		{
			nClass = 3;
			nClassTercera = 89;
		}
		if( wBypass.find(L"player_cambiar_subclass? Paladin") == 0)
		{
			nClass = 5;
			nClassTercera = 90;
		}
		if( wBypass.find(L"player_cambiar_subclass? DarkAvenger") == 0)
		{
			nClass = 6;
			nClassTercera = 91;
		}
		if( wBypass.find(L"player_cambiar_subclass? TreasureHunter") == 0)
		{
			nClass = 8;
			nClassTercera = 93;
		}
		if( wBypass.find(L"player_cambiar_subclass? Hawkeye") == 0)
		{
			nClass = 9;
			nClassTercera = 92;
		}
		if( wBypass.find(L"player_cambiar_subclass? Sorceror") == 0)
		{
			nClass = 12;
			nClassTercera = 94;
		}
		if( wBypass.find(L"player_cambiar_subclass? Necromancer") == 0)
		{
			nClass = 13;
			nClassTercera = 95;
		}
		if( wBypass.find(L"player_cambiar_subclass? Warlock") == 0)
		{
			nClass = 14;
			nClassTercera = 96;
		}
		if( wBypass.find(L"player_cambiar_subclass? Bishop") == 0)
		{
			nClass = 16;
			nClassTercera = 97;
		}
		if( wBypass.find(L"player_cambiar_subclass? Prophet") == 0)
		{
			nClass = 17;
			nClassTercera = 98;
		}
		if( wBypass.find(L"player_cambiar_subclass? TempleKnight") == 0)
		{
			nClass = 20;
			nClassTercera = 99;
		}
		if( wBypass.find(L"player_cambiar_subclass? SwordSinger") == 0)
		{
			nClass = 21;
			nClassTercera = 100;
		}
		if( wBypass.find(L"player_cambiar_subclass? PlainsWalker") == 0)
		{
			nClass = 23;
			nClassTercera = 101;
		}
		if( wBypass.find(L"player_cambiar_subclass? SilverRanger") == 0)
		{
			nClass = 24;
			nClassTercera = 102;
		}
		if( wBypass.find(L"player_cambiar_subclass? SpellSinger") == 0)
		{
			nClass = 27;
			nClassTercera = 103;
		}
		if( wBypass.find(L"player_cambiar_subclass? ElementSummoner") == 0)
		{
			nClass = 28;
			nClassTercera = 104;
		}
		if( wBypass.find(L"player_cambiar_subclass? Elder") == 0)
		{
			nClass = 30;
			nClassTercera = 105;
		}
		if( wBypass.find(L"player_cambiar_subclass? ShillienKnight") == 0)
		{
			nClass = 33;
			nClassTercera = 106;
		}
		if( wBypass.find(L"player_cambiar_subclass? BladeDancer") == 0)
		{
			nClass = 34;
			nClassTercera = 107;
		}
		if( wBypass.find(L"player_cambiar_subclass? AbyssWalker") == 0)
		{
			nClass = 36;
			nClassTercera = 108;
		}
		if( wBypass.find(L"player_cambiar_subclass? PhantomRanger") == 0)
		{
			nClass = 37;
			nClassTercera = 109;
		}
		if( wBypass.find(L"player_cambiar_subclass? Spellhowler") == 0)
		{
			nClass = 40;
			nClassTercera = 110;
		}
		if( wBypass.find(L"player_cambiar_subclass? PhantomSummoner") == 0)
		{
			nClass = 41;
			nClassTercera = 111;
		}
		if( wBypass.find(L"player_cambiar_subclass? ShillienElder") == 0)
		{
			nClass = 43;
			nClassTercera = 112;
		}
		if( wBypass.find(L"player_cambiar_subclass? Destroyer") == 0)
		{
			nClass = 46;
			nClassTercera = 113;
		}
		if( wBypass.find(L"player_cambiar_subclass? Tyrant") == 0)
		{
			nClass = 48;
			nClassTercera = 114;
		}
		if( wBypass.find(L"player_cambiar_subclass? Overlord") == 0)
		{
			nClass = 51;
			nClassTercera = 115;
		}
		if( wBypass.find(L"player_cambiar_subclass? Warcryer") == 0)
		{
			nClass = 52;
			nClassTercera = 116;
		}
		if( wBypass.find(L"player_cambiar_subclass? BountyHunter") == 0)
		{
			nClass = 55;
			nClassTercera = 117;
		}
		if( wBypass.find(L"player_cambiar_subclass? Warsmith") == 0)
		{
			nClass = 57;
			nClassTercera = 118;
		}

		if (nClass == -1)
			return true;


		if (g_NoPermitirDosTanques)
		{
			if (nClass == 6 || nClass == 33 || nClass == 20 || nClass == 5)
			{
				if(pUser->pSD->nSubJobClass[pUser->pSD->nSubClassIndex] != 6 && 
					pUser->pSD->nSubJobClass[pUser->pSD->nSubClassIndex] != 33 &&
					pUser->pSD->nSubJobClass[pUser->pSD->nSubClassIndex] != 20 &&
					pUser->pSD->nSubJobClass[pUser->pSD->nSubClassIndex] != 5 && 
					pUser->pSD->nSubJobClass[pUser->pSD->nSubClassIndex] != 91 &&
					pUser->pSD->nSubJobClass[pUser->pSD->nSubClassIndex] != 106 &&
					pUser->pSD->nSubJobClass[pUser->pSD->nSubClassIndex] != 99 &&
					pUser->pSD->nSubJobClass[pUser->pSD->nSubClassIndex] != 90)
				{
					if (pUser->pSD->nSubJobClass[0] == 6 || pUser->pSD->nSubJobClass[0] == 33 || pUser->pSD->nSubJobClass[0] == 20 || pUser->pSD->nSubJobClass[0] == 5 || pUser->pSD->nSubJobClass[0] == 91 || pUser->pSD->nSubJobClass[0] == 106 || pUser->pSD->nSubJobClass[0] == 99 || pUser->pSD->nSubJobClass[0] == 90)
					{
						CSystemMessage msg1(SystemMessage::S1_POPUP);
						msg1.AddText(L"No se pueden mesclar: Dark Avenger, Shillien Knight, Temple Knight o Paladin. En el mismo personaje.");
						pUser->pSocket->SendSystemMessage(&msg1);
						return true;
					}
					if (pUser->pSD->nSubJobClass[1] == 6 || pUser->pSD->nSubJobClass[1] == 33 || pUser->pSD->nSubJobClass[1] == 20 || pUser->pSD->nSubJobClass[1] == 5 || pUser->pSD->nSubJobClass[1] == 91 || pUser->pSD->nSubJobClass[1] == 106 || pUser->pSD->nSubJobClass[1] == 99 || pUser->pSD->nSubJobClass[1] == 90)
					{
						CSystemMessage msg1(SystemMessage::S1_POPUP);
						msg1.AddText(L"No se pueden mesclar: Dark Avenger, Shillien Knight, Temple Knight o Paladin. En el mismo personaje.");
						pUser->pSocket->SendSystemMessage(&msg1);
						return true;
					}
					if (pUser->pSD->nSubJobClass[2] == 6 || pUser->pSD->nSubJobClass[2] == 33 || pUser->pSD->nSubJobClass[2] == 20 || pUser->pSD->nSubJobClass[2] == 5 || pUser->pSD->nSubJobClass[2] == 91 || pUser->pSD->nSubJobClass[2] == 106 || pUser->pSD->nSubJobClass[2] == 99 || pUser->pSD->nSubJobClass[2] == 90)
					{
						CSystemMessage msg1(SystemMessage::S1_POPUP);
						msg1.AddText(L"No se pueden mesclar: Dark Avenger, Shillien Knight, Temple Knight o Paladin. En el mismo personaje.");
						pUser->pSocket->SendSystemMessage(&msg1);
						return true;
					}
					if (pUser->pSD->nSubJobClass[3] == 6 || pUser->pSD->nSubJobClass[3] == 33 || pUser->pSD->nSubJobClass[3] == 20 || pUser->pSD->nSubJobClass[3] == 5 || pUser->pSD->nSubJobClass[3] == 91 || pUser->pSD->nSubJobClass[3] == 106 || pUser->pSD->nSubJobClass[3] == 99 || pUser->pSD->nSubJobClass[3] == 90)
					{
						CSystemMessage msg1(SystemMessage::S1_POPUP);
						msg1.AddText(L"No se pueden mesclar: Dark Avenger, Shillien Knight, Temple Knight o Paladin. En el mismo personaje.");
						pUser->pSocket->SendSystemMessage(&msg1);
						return true;
					}
				}
			}
		}

		if (pUser->pSD->nLevel <g_ChangeSubClass_MinLevel)
		{
			CSystemMessage msg1(SystemMessage::S1_POPUP);
			msg1.AddText(L"Debes ser level superior para borrar la subclass.");
			pUser->pSocket->SendSystemMessage(&msg1);
			return true;
		}

		if (pUser->pSD->nSubJobClass[0] == nClass || pUser->pSD->nSubJobClass[1] == nClass || pUser->pSD->nSubJobClass[2] == nClass || pUser->pSD->nSubJobClass[3] == nClass)
		{
			pUser->SendSystemMessage(L"Tu personaje ya tiene la SubClass que acabas de elejir y no se realizo ningun cambio en tu personaje.");
			return false;
		}

		if (pUser->pSD->nSubJobClass[0] == nClassTercera || pUser->pSD->nSubJobClass[1] == nClassTercera || pUser->pSD->nSubJobClass[2] == nClassTercera || pUser->pSD->nSubJobClass[3] == nClassTercera)
		{
			pUser->SendSystemMessage(L"Tu personaje ya tiene la SubClass que acabas de elejir y no se realizo ningun cambio en tu personaje.");
			return false;
		}



		if(!pUser->DeleteItemInInventory(g_ChangeSubClass_ItemId, g_ChangeSubClass_ItemCount))
		{
			CSystemMessage msg1(SystemMessage::S1_POPUP);
			msg1.AddText(L"No tienes los items necesarios.");
			pUser->pSocket->SendSystemMessage(&msg1);
			return true;
		}


		if(pUser->pSD->nClass > 87)
		{
			if(g_EntregarItemSiTieneTerceraItemId > 0 && g_EntregarItemSiTieneTerceraItemCount > 0)
			{
				COlympiadSystem::ResetPoints(pUser);
				pUser->AddItemToInventory(g_EntregarItemSiTieneTerceraItemId, g_EntregarItemSiTieneTerceraItemCount);
			}
		}

		g_RebirthSystem.OnResetSubClass(pUser);

		wstring sParams;
		wstringstream wParams2;
		wParams2 << pUser->pSD->wszName;
		getline(wParams2, sParams);

		typedef void (*f)(CSocket*, User*, WCHAR*);
		f(0x0047C490L)(pUser->GetSocket(), pUser, const_cast< wchar_t* >(sParams.c_str()));


		typedef void (*f)(CSocket*, User*, WCHAR*);
		f(0x0047C490L)(pUser->GetSocket(), pUser, const_cast< wchar_t* >(sParams.c_str()));

		PlayerAction::OnClassChange(pUser, nClass);		//cambiar clase

		typedef void (*f)(CSocket*, User*, WCHAR*);
		f(0x0047C490L)(pUser->GetSocket(), pUser, const_cast< wchar_t* >(sParams.c_str()));

		pUser->ValidateSubjobParameters();


		typedef void (*f)(CSocket*, User*, WCHAR*);
		f(0x0047C490L)(pUser->GetSocket(), pUser, const_cast< wchar_t* >(sParams.c_str()));

		//pUser->DeleteAllSkills();
		//pUser->DeleteAllSkills();
	//	pUser->DeleteAllSkills();
//		pUser->DeleteAllSkills();



		pUser->SetCharInfoChanged();
		pUser->SetUserInfoChanged();


		



		pUser->SocialAction(SocialActionLevelUp);

		g_Logger.Add(L"User[%s] cambio de SubClass a de [%d] a [%d]", pUser->pSD->wszName, pUser->pSD->nClass, nClass);
		CSystemMessage msg2(SystemMessage::S1_POPUP);
		msg2.AddText(L"Se ha cambiado tu SubClass con exito. Ahora debes reloguear tu personaje.");
		pUser->pSocket->SendSystemMessage(&msg2);


	//	if(g_ChangeSubClass_PonerLevel > 0)
	//		pUser->SetLevel(g_ChangeSubClass_PonerLevel);		//ESTO BUGEA LOS SKILLS, DEBE SER POR EL AUTOSKILL

		if (g_ChangeSubClass_Anunciar)
		{
			tstring announce = g_ChangeSubClass_Message;
			announce = Utils::ReplaceString(announce, _T("[player_name]"), pUser->pSD->wszName, true);
			Utils::BroadcastToAllUser_Announce(announce.c_str());
		}
		return true;


	}else if( wBypass.find(L"player_reset_tercera?") == 0)
	{
		if(pUser->pSD->nClass > 87)
		{

			if(!pUser->DeleteItemInInventory(g_ChangeSubClass_ItemId, g_ChangeSubClass_ItemCount))
			{
				CSystemMessage msg1(SystemMessage::S1_POPUP);
				msg1.AddText(L"No tienes los items necesarios.");
				pUser->pSocket->SendSystemMessage(&msg1);
				return true;
			}

			int nClass = Utils::GetIDdeSegundaToTercera(pUser->pSD->nClass);

			if(g_EntregarItemSiTieneTerceraItemId > 0 && g_EntregarItemSiTieneTerceraItemCount > 0)
			{
				COlympiadSystem::ResetPoints(pUser);
				pUser->AddItemToInventory(g_EntregarItemSiTieneTerceraItemId, g_EntregarItemSiTieneTerceraItemCount);
			}

			g_RebirthSystem.OnResetSubClass(pUser);

			wstring sParams;
			wstringstream wParams2;
			wParams2 << pUser->pSD->wszName;
			getline(wParams2, sParams);

			typedef void (*f)(CSocket*, User*, WCHAR*);
			f(0x0047C490L)(pUser->GetSocket(), pUser, const_cast< wchar_t* >(sParams.c_str()));


			typedef void (*f)(CSocket*, User*, WCHAR*);
			f(0x0047C490L)(pUser->GetSocket(), pUser, const_cast< wchar_t* >(sParams.c_str()));

			PlayerAction::OnClassChange(pUser, nClass);		//cambiar clase

			typedef void (*f)(CSocket*, User*, WCHAR*);
			f(0x0047C490L)(pUser->GetSocket(), pUser, const_cast< wchar_t* >(sParams.c_str()));

			pUser->ValidateSubjobParameters();

			typedef void (*f)(CSocket*, User*, WCHAR*);
			f(0x0047C490L)(pUser->GetSocket(), pUser, const_cast< wchar_t* >(sParams.c_str()));

			pUser->SetCharInfoChanged();
			pUser->SetUserInfoChanged();

			pUser->SocialAction(SocialActionLevelUp);

			g_Logger.Add(L"User[%s] Reseteo Tercera a [%d]", pUser->pSD->wszName, nClass);
			CSystemMessage msg2(SystemMessage::S1_POPUP);
			msg2.AddText(L"Se ha Reseteado tu tercera con exito. Ahora debes reloguear tu personaje.");
			pUser->pSocket->SendSystemMessage(&msg2);
		}
		return true;
	}else if( wBypass.find(L"player_set_hero?") == 0)
	{
		if(pUser->pSD->nHero == 2)
		{
			CSystemMessage msg1(SystemMessage::S1_POPUP);
			msg1.AddText(L"Tu personaje ya es Hero.");
			pUser->pSocket->SendSystemMessage(&msg1);
			return true;
		}	

		if (pUser->pSD->nLevel >75)
		{
			if(pUser->pSD->nNobless == 0)
			{
				CSystemMessage msg1(SystemMessage::S1_POPUP);
				msg1.AddText(L"Primero debes convertirte en Noble.");
				pUser->pSocket->SendSystemMessage(&msg1);
				return true;
			}		
				
			if(!pUser->DeleteItemInInventory(g_ChangeHero_ItemId, g_ChangeHero_ItemCount))
			{
				CSystemMessage msg1(SystemMessage::S1_POPUP);
				msg1.AddText(L"No tienes los items necesarios.");
				pUser->pSocket->SendSystemMessage(&msg1);
				return true;
			}
			pUser->pED->customVerAuraHero = 1;
			g_DB.RequestSaveHeroType(pUser, 2);
			g_HeroSystem.AcquireHeroSkills(pUser);
				
			g_Logger.Add(L"User[%s] se convirtio en Hero", pUser->pSD->wszName);
		}
		return true;
	}else if( wBypass.find(L"player_cambiar_sexo?") == 0)
	{
		int Sex_a = pUser->pSD->nSex;

		int custom_sex = g_AccountDB.GetCustomSex(pUser->pSD->nDBID);
		if (custom_sex >-1)
			Sex_a = custom_sex;

		int Sex = pUser->pSD->nSex;
		if (Sex_a == 0) 
			Sex = 1;
		else
			Sex = 0;

		if(!pUser->DeleteItemInInventory(g_ChangeSex_ItemId, g_ChangeSex_ItemCount))
		{
			CSystemMessage msg1(SystemMessage::S1_POPUP);
			msg1.AddText(L"No tienes los items necesarios.");
			pUser->pSocket->SendSystemMessage(&msg1);
			return true;
		}

		g_DB.RequestSaveSex(pUser->pSD->nDBID,Sex);
		g_AccountDB.AddCustomSex(pUser->pSD->nDBID, Sex);
		pUser->pED->actualizarApariencias = true;
		pUser->SetCharInfoChanged();
		pUser->SetUserInfoChanged();

		g_Logger.Add(L"User[%s] cambio de sexo a [%d]", pUser->pSD->wszName, Sex);
		CSystemMessage msg2(SystemMessage::S1_POPUP);
		msg2.AddText(L"Se ha cambiado tu Sexo con exito. Ahora debes reloguear tu personaje.");
		pUser->pSocket->SendSystemMessage(&msg2);

		return true;
	}else if( wBypass.find(L"player_set_karma?") == 0)
	{
		if(!pUser->DeleteItemInInventory(g_ChangeKarma_ItemId, g_ChangeKarma_ItemCount))
		{
			CSystemMessage msg1(SystemMessage::S1_POPUP);
			msg1.AddText(L"No tienes los items necesarios.");
			pUser->pSocket->SendSystemMessage(&msg1);
			return true;
		}

		pUser->SetKarma(0);
		pUser->SendCharInfo(false);
		pUser->SendUserInfo(false);
		return true;
	}else if( wBypass.find(L"player_no_sleep?") == 0)
	{
		if(g_nosleep)
		{
			if(pUser->ValidUser())
			{
				pUser->pSocket->Send("cd", 0x87, 16);
				CSystemMessage msg1(SystemMessage::S1_POPUP);
				msg1.AddText(L"Se activo NoSleep en tu cliente, sirve para tener multiples clientes o monitores y al cambiar que la otra pantalla no quede con freeze (consume mas recursos de la pc), si quieres desactivarlo deberas cerrar el cliente y volver a entrar.");
				pUser->pSocket->SendSystemMessage(&msg1);

			}
		}
		return true;
	}else if( wBypass.find(L"aganthion_test?") == 0)
	{
		UINT id = Parser::GetBypassValueInt(wBypass.c_str(), L"AganthionId");
		UINT dSkillId = Parser::GetBypassValueInt(wBypass.c_str(), L"SkillId");
		wstring nAI = CParser::GetBypassValue(wBypass, L"Ai=");

		if(pUser->ValidUser())
		{
			int nClassID = id;
			int nSkillID = dSkillId;

			CNPC *pAganthion = pUser->pSD->pExData->Aganthion;
			if(pAganthion->ValidCreature())
			{
				pAganthion->TeleportToLocation(0,0,0,0);

				typedef double (*b)(CNPC*);
				b(0x4D4570)(pUser->pSD->pExData->Aganthion);


				if(pUser->HaveSkill(nSkillID, 1))
				{
					pUser->DeleteSkill(nSkillID);

					typedef char (*f)(CCreature*);
					f(0x5173F0)(pUser->CastCreature());	//CCreature::ValidateAttachedSkills
					pUser->CastCreature()->ValidateAllOnSIM();
				}

				pUser->pSD->pExData->Aganthion = NULL;
			}





			nClassID += 1000000;
			const WCHAR* wszName = g_ObjectDB.GetName(nClassID);
			CSummon *pNPC = g_ObjectDB.CreateCSummon(nClassID);

			if(pNPC)
			{
				//const WCHAR* wszAI = g_ObjectDB.GetAI(nClassID);
				const WCHAR* wszAI = nAI.c_str();
				
				if(wszAI)
				{
					CPacket packet;
					int nCnt = 0;

					//wcscpy_s((PWCHAR)((UINT64)pNPC + 0x19D8), 25, pUser->pSD->wszName);
					pNPC->pSD->nMasterID = pUser->pSD->nObjectID;	//1920; m_SummonerID,summoner_id	(en L2NPC AI)
					pNPC->pSD->nPrivateID = pUser->pSD->nPrivateID;

					pNPC->pSD->nMakerParam3 = nSkillID;


					typedef void (*A)(int*, User*);							//bien setea ek master 
					A(0x74B380)(&pNPC->pSD->_n0760, pUser);

					pNPC->pSD->nSummonType = 3;
					pNPC->pSD->_n0770 = 1;
					pNPC->pSD->_n0784 = pUser->pSD->nObjectID;

					pNPC->pSD->_n077C = 1;	//type

					(*(LPDWORD)((UINT64)pNPC+0x1A58)) = pUser->nDBID;

					(*(LPDWORD)((UINT64)pNPC+0x1A5C)) = pUser->pSD->nObjectID;


					(*(LPDWORD)((UINT64)pNPC+0x1A68)) = 57; //adena
					(*(LPDWORD)((UINT64)pNPC+0x1A6C)) = 1;  //count

					pNPC->pSD->nSp = 10000000;
					pNPC->pSD->fHP = 10000000;
					pNPC->pSD->fMP = 10000000;
					pNPC->pSD->nMaxFeed	= 10000000;
					pNPC->pSD->nCurrentFeed = 10000000;

					CHAR buff[2048];
					memset(buff, 0, 2048);
					if(pUser->pSD->pExData->TargetGroundLoc.IsSet())
						pUser->ChangeTarget(pNPC, false);
					else
						pUser->pSD->pExData->TargetGroundLoc.Set(pUser->pSD->Pos.x, pUser->pSD->Pos.y, pUser->pSD->Pos.z);
					int nBuffSize = Assemble(buff, 2048,"cddpddddddddSdb", 0x01, pNPC->pSD->nServerIndex, pNPC->nObjectID, 
						0, 0, pUser->pSD->pExData->TargetGroundLoc.nX, pUser->pSD->pExData->TargetGroundLoc.nY, pUser->pSD->pExData->TargetGroundLoc.nZ,
						pUser->pSD->sHeading, 0, 0, 0, wszAI, nCnt, (int)packet.GetSize(), packet.GetBuff());

		
					NpcServer::Send(nBuffSize, buff);

					pUser->pSD->pExData->TargetGroundLoc.Clear();

					if(nClassID >= 1033910 && nClassID <= 1033928)
					{
						pUser->pSD->pExData->Aganthion = pNPC;
						pNPC->pSD->fSpeed = pUser->pSD->fSpeed;
						pNPC->pSD->m_nMoveTypeSpeed = pUser->pSD->m_nMoveTypeSpeed;

						pNPC->_unkn6C0 = pUser->_unkn6C0;
						pNPC->_n500[29] = pUser->_n500[29];
						pNPC->speedPER = pUser->speedPER;
						pNPC->f_area_speed_coef = pUser->f_area_speed_coef;
						pNPC->carry_weight_speed_coef = pUser->carry_weight_speed_coef;
						pNPC->speedDIFF = pUser->speedDIFF;

						typedef double (*f)(INT64, int, int, int, int);
						pNPC->pND->run_speed = f(0x744B80)(0xE1F3430, pUser->pSD->nSex, pUser->pSD->nClass, 1, 0);
						pNPC->pND->walk_speed = f(0x744B80)(0xE1F3430, pUser->pSD->nSex, pUser->pSD->nClass, 0, 0);
						pNPC->pND->swim_run_speed = f(0x744B80)(0xE1F3430, pUser->pSD->nSex, pUser->pSD->nClass, 1, 1);
						pNPC->pND->swim_walk_speed = f(0x744B80)(0xE1F3430, pUser->pSD->nSex, pUser->pSD->nClass, 0, 1);
						pNPC->pND->fly_run_speed = f(0x744B80)(0xE1F3430, pUser->pSD->nSex, pUser->pSD->nClass, 1, 3);
						pNPC->pND->fly_walk_speed = f(0x744B80)(0xE1F3430, pUser->pSD->nSex, pUser->pSD->nClass, 0, 3);
						pNPC->pND->fly_run_speed2 = f(0x744B80)(0xE1F3430, pUser->pSD->nSex, pUser->pSD->nClass, 1, 2);
						pNPC->pND->fly_walk_speed2 = f(0x744B80)(0xE1F3430, pUser->pSD->nSex, pUser->pSD->nClass, 0, 2);

						pNPC->pCreatureController->AsyncDoNothing();
						pNPC->pSD->pExData->TimerHandler.AddTimer(CCreatureTimerHandler::MOVE_AGANTHION, 0);

						pNPC->broadcastInfoPacket = true;
					}
				}else
					g_Log.Add(CLog::Error, "[%s] There is no AI specified for npc with class id[%d]", __FUNCTION__, nClassID);
			}else
				g_Log.Add(CLog::Error, "[%s] There is no npc with class id[%d]", __FUNCTION__, nClassID);
		}
		return true;
	}else if( wBypass.find(L"player_set_level?") == 0)	//player_set_level?level=78
	{
		int nLevel = _wtoi(CParser::GetBypassValue(wBypass, L"level=").c_str());
		if(nLevel > 0 && nLevel < 81 && pUser->pSD->nLevel < 75)
		{

			if(!pUser->DeleteItemInInventory(g_ChangeLevel_ItemId, g_ChangeLevel_ItemCount))
			{
				CSystemMessage msg1(SystemMessage::S1_POPUP);
				msg1.AddText(L"No tienes los items necesarios.");
				pUser->pSocket->SendSystemMessage(&msg1);
				return true;
			}


			pUser->SetLevel(nLevel);
			pUser->ValidateParameters();
			pUser->AutoSkills();
		}
		return true;
	}else if( wBypass.find(L"player_reset_reuse?") == 0)
	{
		pUser->ResetSkillReuse();
		return true;
	}else if( wBypass.find(L"player_set_clan_level?") == 0)
	{
		int nLevel = _wtoi(CParser::GetBypassValue(wBypass, L"level=").c_str());
		if(nLevel > 0 && nLevel < 9)
		{
			CPledge *pPledge = pUser->GetPledge();
			CPledgeSharedData *pSD = pPledge->GetSharedData();
			if(pSD)
			{
				if(pPledge)
				{
					if (pPledge->pSD->nLevel < 8)
					{
						if(!pUser->DeleteItemInInventory(g_ChangeClan8_ItemId, g_ChangeClan8_ItemCount))
						{
							CSystemMessage msg1(SystemMessage::S1_POPUP);
							msg1.AddText(L"No tienes los items necesarios.");
							pUser->pSocket->SendSystemMessage(&msg1);
							return true;
						}

						pPledge->pSD->nLevel = 8;
						pPledge->UpdatePledgeNameValue(900000);
						pPledge->Save(5);
						pPledge->UpdateInfo();

						UserVector vUsers;
						pPledge->GetAllMembers(vUsers);
						for(UINT n=0;n<vUsers.size();n++)
						{
							if(User *pMember = vUsers[n]->SafeCastUser())
							{
								pMember->AquireClanSkill(370);
								pMember->AquireClanSkill(391);
								pMember->AquireClanSkill(373);
								pMember->AquireClanSkill(379);
								pMember->AquireClanSkill(376);
								pMember->AquireClanSkill(374);
								pMember->AquireClanSkill(377);
								pMember->AquireClanSkill(383);
								pMember->AquireClanSkill(371);
								pMember->AquireClanSkill(390);
								pMember->AquireClanSkill(386);
								pMember->AquireClanSkill(387);
								pMember->AquireClanSkill(380);
								pMember->AquireClanSkill(385);
								pMember->AquireClanSkill(384);
								pMember->AquireClanSkill(382);
								pMember->AquireClanSkill(388);
								pMember->AquireClanSkill(381);
								pMember->AquireClanSkill(375);
								pMember->AquireClanSkill(378);
								pMember->AquireClanSkill(389);
								pMember->AquireClanSkill(372);
							}
						}

						g_Logger.Add(L"User[%s] creo clan level8", pUser->pSD->wszName);
					}
				}
				else
				{
					CSystemMessage msg1(SystemMessage::S1_POPUP);
					msg1.AddText(L"Debes tener un clan primero.");
					pUser->pSocket->SendSystemMessage(&msg1);
					return true;
				}
			}
			else
			{
				CSystemMessage msg1(SystemMessage::S1_POPUP);
				msg1.AddText(L"Debes tener un clan primero...");
				pUser->pSocket->SendSystemMessage(&msg1);
				return true;
			}


		}
		return true;
	}else if ( wBypass.find(L"drop_items_off") == 0)
	{
		if(pUser->pED->dropItems)
		{
			pUser->pED->dropItems = false;
			pUser->pSocket->SendSystemMessage(L"Stop drop Books/Amulet Items.");
		}
		return true;
	}else if ( wBypass.find(L"drop_items_on") == 0)
	{
		if(!pUser->pED->dropItems)
		{
			pUser->pED->dropItems = true;
			pUser->pSocket->SendSystemMessage(L"Drop Books/Amulet Items.");
		}
		return true;
	}else if ( wBypass.find(L"animation_mode") == 0)
	{
		BOOL enabled = CParser::GetBypassValueInt(wBypass, L"state=");
		if(enabled)
		{
			if(!pUser->pSD->pExData->stopAnimations)
			{
				pUser->pSD->pExData->stopAnimations = enabled;		
				pUser->pSocket->SendSystemMessage(L"FPS Optimizations enabled.");
			}
		}else
		{
			if(pUser->pSD->pExData->stopAnimations)
			{
				pUser->pSD->pExData->stopAnimations = enabled;
				pUser->pSocket->SendSystemMessage(L"FPS Optimizations disabled.");
			}
		}
		return true;
	}else if ( wBypass.find(L"show_vip_html") == 0)
	{
			if(pUser->pSD->vipLevel > 0)
			{
				g_VIPSystem.SendBonusInfo2(pUser);
			}
			else
			{
				const WCHAR* pFile = g_HTMLCacheManager.GetHTMLFile( L"vip.htm", pUser->pSD->bLang);
				if(pFile)
				{
					PlayerAction::ShowHTML(pUser, L"vip.htm", pFile, 0);
				}
			}
		return true;
	}else if( wBypass.find(L"add_item?") == 0)
	{
		int itemId = 0, itemCount = 0, priceId = 0, priceCount = 0;

		itemId = Parser::GetBypassValueInt(wBypass.c_str(), L"itemId");
		itemCount = Parser::GetBypassValueInt(wBypass.c_str(), L"itemCount");
		priceId = Parser::GetBypassValueInt(wBypass.c_str(), L"priceId");
		priceCount = Parser::GetBypassValueInt(wBypass.c_str(), L"priceCount");

//bypass add_item?itemId=4423&itemCount=1&priceId=57&priceCount=100000000				para vender striders 
		if(!pUser->DeleteItemInInventory(priceId, priceCount))
		{
			CSystemMessage msg1(SystemMessage::S1_POPUP);
			msg1.AddText(L"No tienes los items necesarios.");
			pUser->pSocket->SendSystemMessage(&msg1);
			return true;
		}

		pUser->AddItemToInventory(itemId, itemCount);
	}else if( wBypass.find(L"register_3v3?") == 0)
	{
		wstring wName = CParser::GetBypassValue(wBypass, L"n=");

		if(CParty *pParty = pUser->GetParty())
		{
			if( pParty->GetMaster() == pUser )
			{
				if(pParty->memberCount == 3)
				{
					UINT player1= 0;
					UINT player2= 0;
					UINT player3= 0;
					UINT player4= 0;
					UINT player5= 0;
					UINT player6= 0;
					UINT player7= 0;
					UINT player8= 0;
					UINT player9= 0;

					UserVector vUsers;
					pParty->GetAllMembersEx(vUsers);
					for(UINT n=0;n<vUsers.size();n++)
					{
						if(User *pMember = vUsers[n]->SafeCastUser())
						{
							if(n == 0)	player1 = pMember->nDBID;
							if(n == 1)	player2 = pMember->nDBID;
							if(n == 2)	player3 = pMember->nDBID;
							if(n == 3)	player4 = pMember->nDBID;
							if(n == 4)	player5 = pMember->nDBID;
							if(n == 5)	player6 = pMember->nDBID;
							if(n == 6)	player7 = pMember->nDBID;
							if(n == 7)	player8 = pMember->nDBID;
							if(n == 8)	player9 = pMember->nDBID;
						}
					}

				   WCHAR Name[25];
				   wcscpy(Name, wName.c_str());

					g_DB.RequestRegisterChampionshipTeam(wName, player1, player2, player3);
					CSystemMessage msg1(SystemMessage::S1_POPUP);
					msg1.AddText(L"Party anotada (Esperando nueva pelea).");
					pUser->pSocket->SendSystemMessage(&msg1);

				}
				else
				{
					CSystemMessage msg1(SystemMessage::S1_POPUP);
					msg1.AddText(L"Deben ser 3 players en party para anotarce.");
					pUser->pSocket->SendSystemMessage(&msg1);
				}
			}
			else
			{
				//SOLO EL LIDER DE LA PARTY PUEDE ANOTAR
					CSystemMessage msg1(SystemMessage::S1_POPUP);
					msg1.AddText(L"Solo el lider de la party puede anotar.");
					pUser->pSocket->SendSystemMessage(&msg1);
			}
		}
		else
		{
			//DEBEN ANOTARCE EN PARTY
			CSystemMessage msg1(SystemMessage::S1_POPUP);
			msg1.AddText(L"Solo pueden anotar en party.");
			pUser->pSocket->SendSystemMessage(&msg1);

		}

	}else if ( wBypass.find(L"custom_observer?") == 0)
	{
		int x = 0, y = 0, z = 0, yaw = 0, pitch = 0, period = 0;

		x = Parser::GetBypassValueInt(wBypass.c_str(), L"x");
		y = Parser::GetBypassValueInt(wBypass.c_str(), L"y");
		z = Parser::GetBypassValueInt(wBypass.c_str(), L"z");
		yaw = Parser::GetBypassValueInt(wBypass.c_str(), L"yaw");
		pitch = Parser::GetBypassValueInt(wBypass.c_str(), L"pitch");
		period = Parser::GetBypassValueInt(wBypass.c_str(), L"period");

		if(x != 0)
		{
			PlayerAction::ObserverStart(pUser, x, y, z, yaw, pitch, period);
		}
		return true;
	}else if ( wBypass.find(L"customspawn_teleport?") == 0)
	{
		g_NpcMaker.ByPassTeleport(pUser);
		return true;
	}else if( wBypass.find(L"new_sub?") == 0)
	{
		int nClass = -1;
		if( wBypass.find(L"new_sub? Gladiator Gladiator") == 0)
			nClass = 2;
		if( wBypass.find(L"new_sub? Warlord Warlord") == 0)
			nClass = 3;
		if( wBypass.find(L"new_sub? Paladin Paladin") == 0)
			nClass = 5;
		if( wBypass.find(L"new_sub? DarkAvenger DarkAvenger") == 0)
			nClass = 6;
		if( wBypass.find(L"new_sub? TreasureHunter TreasureHunter") == 0)
			nClass = 8;
		if( wBypass.find(L"new_sub? Hawkeye Hawkeye") == 0)
			nClass = 9;

		if( wBypass.find(L"new_sub? Sorceror Sorceror") == 0)
			nClass = 12;
		if( wBypass.find(L"new_sub? Necromancer Necromancer") == 0)
			nClass = 13;
		if( wBypass.find(L"new_sub? Warlock Warlock") == 0)
			nClass = 14;
		if( wBypass.find(L"new_sub? Bishop Bishop") == 0)
			nClass = 16;
		if( wBypass.find(L"new_sub? Prophet Prophet") == 0)
			nClass = 17;

		if( wBypass.find(L"new_sub? TempleKnight TempleKnight") == 0)
			nClass = 20;
		if( wBypass.find(L"new_sub? SwordSinger SwordSinger") == 0)
			nClass = 21;
		if( wBypass.find(L"new_sub? PlainsWalker PlainsWalker") == 0)
			nClass = 23;
		if( wBypass.find(L"new_sub? SilverRanger SilverRanger") == 0)
			nClass = 24;

		if( wBypass.find(L"new_sub? SpellSinger SpellSinger") == 0)
			nClass = 27;
		if( wBypass.find(L"new_sub? ElementalSummon ElementalSummon") == 0)
			nClass = 28;

		if( wBypass.find(L"new_sub? Elder Elder") == 0)
			nClass = 30;

		if( wBypass.find(L"new_sub? ShillienKnight ShillienKnight") == 0)
			nClass = 33;
		if( wBypass.find(L"new_sub? BladeDancer BladeDancer") == 0)
			nClass = 34;
		if( wBypass.find(L"new_sub? AbyssWalker AbyssWalker") == 0)
			nClass = 36;
		if( wBypass.find(L"new_sub? PhantomRanger PhantomRanger") == 0)
			nClass = 37;

		if( wBypass.find(L"new_sub? Spellhowler Spellhowler") == 0)
			nClass = 40;
		if( wBypass.find(L"new_sub? PhantomSummoner PhantomSummoner") == 0)
			nClass = 41;
		if( wBypass.find(L"new_sub? ShillienElder ShillienElder") == 0)
			nClass = 43;

		if( wBypass.find(L"new_sub? Destroyer Destroyer") == 0)
			nClass = 46;
		if( wBypass.find(L"new_sub? Tyrant Tyrant") == 0)
			nClass = 48;

		if( wBypass.find(L"new_sub? Overlord Overlord") == 0)
			nClass = 51;
		if( wBypass.find(L"new_sub? Warcryer Warcryer") == 0)
			nClass = 52;

		if( wBypass.find(L"new_sub? BountyHunter BountyHunter") == 0)
			nClass = 55;
		if( wBypass.find(L"new_sub? Warsmith Warsmith") == 0)
			nClass = 57;

		if (nClass == -1)
			return true;


		if (g_NoPermitirDosTanques)
		{
			if (nClass == 6 || nClass == 33 || nClass == 20 || nClass == 5)
			{
				if (pUser->pED->nCustomSubClass[0] == 6 || pUser->pED->nCustomSubClass[0] == 33 || pUser->pED->nCustomSubClass[0] == 20 || pUser->pED->nCustomSubClass[0] == 5 || pUser->pED->nCustomSubClass[0] == 91 || pUser->pED->nCustomSubClass[0] == 106 || pUser->pED->nCustomSubClass[0] == 99 || pUser->pED->nCustomSubClass[0] == 90)
				{
					CSystemMessage msg1(SystemMessage::S1_POPUP);
					msg1.AddText(L"No se pueden mesclar: Dark Avenger, Shillien Knight, Temple Knight o Paladin. En el mismo personaje.");
					pUser->pSocket->SendSystemMessage(&msg1);
					return true;
				}
				if (pUser->pED->nCustomSubClass[1] == 6 || pUser->pED->nCustomSubClass[1] == 33 || pUser->pED->nCustomSubClass[1] == 20 || pUser->pED->nCustomSubClass[1] == 5 || pUser->pED->nCustomSubClass[1] == 91 || pUser->pED->nCustomSubClass[1] == 106 || pUser->pED->nCustomSubClass[1] == 99 || pUser->pED->nCustomSubClass[1] == 90)
				{
					CSystemMessage msg1(SystemMessage::S1_POPUP);
					msg1.AddText(L"No se pueden mesclar: Dark Avenger, Shillien Knight, Temple Knight o Paladin. En el mismo personaje.");
					pUser->pSocket->SendSystemMessage(&msg1);
					return true;
				}
				if (pUser->pED->nCustomSubClass[2] == 6 || pUser->pED->nCustomSubClass[2] == 33 || pUser->pED->nCustomSubClass[2] == 20 || pUser->pED->nCustomSubClass[2] == 5 || pUser->pED->nCustomSubClass[2] == 91 || pUser->pED->nCustomSubClass[2] == 106 || pUser->pED->nCustomSubClass[2] == 99 || pUser->pED->nCustomSubClass[2] == 90)
				{
					CSystemMessage msg1(SystemMessage::S1_POPUP);
					msg1.AddText(L"No se pueden mesclar: Dark Avenger, Shillien Knight, Temple Knight o Paladin. En el mismo personaje.");
					pUser->pSocket->SendSystemMessage(&msg1);
					return true;
				}
				if (pUser->pED->nCustomSubClass[3] == 6 || pUser->pED->nCustomSubClass[3] == 33 || pUser->pED->nCustomSubClass[3] == 20 || pUser->pED->nCustomSubClass[3] == 5 || pUser->pED->nCustomSubClass[3] == 91 || pUser->pED->nCustomSubClass[3] == 106 || pUser->pED->nCustomSubClass[3] == 99 || pUser->pED->nCustomSubClass[3] == 90)
				{
					CSystemMessage msg1(SystemMessage::S1_POPUP);
					msg1.AddText(L"No se pueden mesclar: Dark Avenger, Shillien Knight, Temple Knight o Paladin. En el mismo personaje.");
					pUser->pSocket->SendSystemMessage(&msg1);
					return true;
				}
			}
		}


		if (!g_NewSubClass_Enable)
		{
			CSystemMessage msg1(SystemMessage::S1_POPUP);
			msg1.AddText(L"Sistema deshabilitado.");
			pUser->pSocket->SendSystemMessage(&msg1);
			return true;
		}

		if (pUser->pSD->nClass == nClass || pUser->pED->nCustomSubClass[0] == nClass || pUser->pED->nCustomSubClass[1] == nClass || pUser->pED->nCustomSubClass[2] == nClass || pUser->pED->nCustomSubClass[3] == nClass )
		{
			CSystemMessage msg1(SystemMessage::S1_POPUP);
			msg1.AddText(L"No puedes agregar esta subclass porque tu personaje ya la tiene aprendida.");
			pUser->pSocket->SendSystemMessage(&msg1);
			return true;
		}


		if (pUser->pSD->nLevel <75)
		{
			CSystemMessage msg1(SystemMessage::S1_POPUP);
			msg1.AddText(L"Debes ser level superior a 75 para hacer subclass.");
			pUser->pSocket->SendSystemMessage(&msg1);
			return true;
		}


		if(pUser->pSD->nClass !=2 && pUser->pSD->nClass !=3 && pUser->pSD->nClass !=5 && pUser->pSD->nClass !=6 && pUser->pSD->nClass !=8 && pUser->pSD->nClass !=9 && pUser->pSD->nClass !=12 && pUser->pSD->nClass !=13 && pUser->pSD->nClass !=14 && pUser->pSD->nClass !=16 && pUser->pSD->nClass !=17 && pUser->pSD->nClass !=20 && pUser->pSD->nClass !=21 && pUser->pSD->nClass !=23 && pUser->pSD->nClass !=24 && pUser->pSD->nClass !=27 && pUser->pSD->nClass !=28 && pUser->pSD->nClass !=30 && pUser->pSD->nClass !=33 && pUser->pSD->nClass !=34 && pUser->pSD->nClass !=36 && pUser->pSD->nClass !=37 && pUser->pSD->nClass !=40 && pUser->pSD->nClass !=41 && pUser->pSD->nClass !=43 && pUser->pSD->nClass !=46 && pUser->pSD->nClass !=48 && pUser->pSD->nClass !=51 && pUser->pSD->nClass !=52 && pUser->pSD->nClass !=55 && pUser->pSD->nClass !=57)
		{
			CSystemMessage msg1(SystemMessage::S1_POPUP);
			msg1.AddText(L"Tu personaje debe tener segunda clase.");
			pUser->pSocket->SendSystemMessage(&msg1);
			return true;
		}

		if(pUser->pED->nCustomSubClassIndex > 2)
		{
			CSystemMessage msg1(SystemMessage::S1_POPUP);
			msg1.AddText(L"Tu personaje ya esta completo, no puedes agregar mas subclass.");
			pUser->pSocket->SendSystemMessage(&msg1);
			return true;
		}

		pUser->SetLevel(g_NewSubClass_PonerLevel);

		if(pUser->pED->nCustomSubClassIndex == 0)
		{
			pUser->pED->nCustomSubClass[0] = pUser->pSD->nClass;
		}

		pUser->AutoSkills();
		pUser->AutoSkills();
		pUser->AutoSkills();
		pUser->AutoSkills();
		pUser->AutoSkills();

		PlayerAction::OnClassChange(pUser, nClass);		//cambiar clase

		pUser->pED->nCustomSubClassIndex++;
		pUser->pED->nCustomSubClass[pUser->pED->nCustomSubClassIndex] = nClass;

		g_DB.RequestSaveCustomSubClass(pUser->nDBID,pUser->pED->nCustomSubClassIndex,pUser->pED->nCustomSubClass[0],pUser->pED->nCustomSubClass[1],pUser->pED->nCustomSubClass[2],pUser->pED->nCustomSubClass[3]);

		if(g_NewSubClass_ItemId)
			pUser->AddItemToInventory(g_NewSubClass_ItemId, 1);
		

		pUser->ValidateSubjobParameters();

		pUser->AutoSkills();
		pUser->AutoSkills();
		pUser->AutoSkills();

		if(pUser->pED->nCustomSubClassIndex == 1)
			pUser->AutoSkillsByClass(pUser->pED->nCustomSubClass[0],g_MiAutoSkillMaxLevel+1);

		if(pUser->pED->nCustomSubClassIndex == 2)
		{
			pUser->AutoSkillsByClass(pUser->pED->nCustomSubClass[0],g_MiAutoSkillMaxLevel+1);
			pUser->AutoSkillsByClass(pUser->pED->nCustomSubClass[1],g_MiAutoSkillMaxLevel+1);
		}

		if(pUser->pED->nCustomSubClassIndex == 3)
		{
			pUser->AutoSkillsByClass(pUser->pED->nCustomSubClass[0],g_MiAutoSkillMaxLevel+1);
			pUser->AutoSkillsByClass(pUser->pED->nCustomSubClass[1],g_MiAutoSkillMaxLevel+1);
			pUser->AutoSkillsByClass(pUser->pED->nCustomSubClass[2],g_MiAutoSkillMaxLevel+1);
		}


		pUser->QuitarSkillDeTerceraDeLasOtrasClases();
		pUser->AutoSkills();



		pUser->SetCharInfoChanged();
		pUser->SetUserInfoChanged();

		pUser->SocialAction(SocialActionLevelUp);

		g_Logger.Add(L"User[%s] Nueva SubClass a [%d]", pUser->pSD->wszName, nClass);
		CSystemMessage msg2(SystemMessage::S1_POPUP);
		msg2.AddText(L"Se ha creado tu SubClass con exito. Ahora debes reloguear tu personaje.");
		pUser->pSocket->SendSystemMessage(&msg2);

		if (g_AnnounceSubClass)
		{
			if (pUser->pED->nCustomSubClassIndex == 1)
			{
				tstring announce = g_AnnounceSubClassMsg1;
				announce = Utils::ReplaceString(announce, _T("[player_name]"), pUser->pSD->wszName, true);
				Utils::BroadcastToAllUser_Announce(announce.c_str());
			}
			else if (pUser->pED->nCustomSubClassIndex == 2)
			{
				tstring announce = g_AnnounceSubClassMsg2;
				announce = Utils::ReplaceString(announce, _T("[player_name]"), pUser->pSD->wszName, true);
				Utils::BroadcastToAllUser_Announce(announce.c_str());
			}
			else if (pUser->pED->nCustomSubClassIndex == 3)
			{
				tstring announce = g_AnnounceSubClassMsg3;
				announce = Utils::ReplaceString(announce, _T("[player_name]"), pUser->pSD->wszName, true);
				Utils::BroadcastToAllUser_Announce(announce.c_str());

				if(m_TerminarPersonajeRewardId > 0 && m_TerminarPersonajeRewardAmount > 0)
				{
						pUser->AddItemToInventory(m_TerminarPersonajeRewardId, m_TerminarPersonajeRewardAmount);
				}
			}
		}

		return true;
	}else if( wBypass.find(L"reset_new_sub_show?") == 0)
	{
		const WCHAR* wHtml = g_HtmlCache.Get(L"tool_createsubclass_reset.htm");
		wstring html(wHtml);

		if(pUser->pED->nCustomSubClassIndex == 0)
		{
			html = Utils::ReplaceString(html, L"<?SubClass0?>", L"", true);
			html = Utils::ReplaceString(html, L"<?SubClass1?>", L"", true);
			html = Utils::ReplaceString(html, L"<?SubClass2?>", L"", true);
			html = Utils::ReplaceString(html, L"<?SubClass3?>", L"", true);
		}
		else if(pUser->pED->nCustomSubClassIndex == 1)
		{
			html = Utils::ReplaceString(html, L"<?SubClass0?>", Utils::GetClassByID(pUser->pED->nCustomSubClass[0]), true);
			html = Utils::ReplaceString(html, L"<?SubClass1?>", Utils::GetClassByID(pUser->pED->nCustomSubClass[1]), true);
			html = Utils::ReplaceString(html, L"<?SubClass2?>", L"", true);
			html = Utils::ReplaceString(html, L"<?SubClass3?>", L"", true);
		}
		if(pUser->pED->nCustomSubClassIndex == 2)
		{
			html = Utils::ReplaceString(html, L"<?SubClass0?>", Utils::GetClassByID(pUser->pED->nCustomSubClass[0]), true);
			html = Utils::ReplaceString(html, L"<?SubClass1?>", Utils::GetClassByID(pUser->pED->nCustomSubClass[1]), true);
			html = Utils::ReplaceString(html, L"<?SubClass2?>", Utils::GetClassByID(pUser->pED->nCustomSubClass[2]), true);
			html = Utils::ReplaceString(html, L"<?SubClass3?>", L"", true);
		}
		if(pUser->pED->nCustomSubClassIndex == 3)
		{
			html = Utils::ReplaceString(html, L"<?SubClass0?>", Utils::GetClassByID(pUser->pED->nCustomSubClass[0]), true);
			html = Utils::ReplaceString(html, L"<?SubClass1?>", Utils::GetClassByID(pUser->pED->nCustomSubClass[1]), true);
			html = Utils::ReplaceString(html, L"<?SubClass2?>", Utils::GetClassByID(pUser->pED->nCustomSubClass[2]), true);
			html = Utils::ReplaceString(html, L"<?SubClass3?>", Utils::GetClassByID(pUser->pED->nCustomSubClass[3]), true);
		}

		pUser->ShowHTML(L"tool_createsubclass_reset.htm", html.c_str(), 0);
	}else if( wBypass.find(L"reset_new_sub?") == 0)
	{
		wstring ClaseBorrar = CParser::GetBypassValue(wBypass, L"borrar=").c_str();
		wstring NewClass = CParser::GetBypassValue(wBypass, L"clase=").c_str();

		//g_Log.Add(CLog::Error, "wBypass[%S]", wBypass.c_str());
		//g_Log.Add(CLog::Error, "ClaseBorrar[%S]", ClaseBorrar.c_str());
		//g_Log.Add(CLog::Error, "NewClass[%S]", NewClass.c_str());


		int nClass = -1;
		int nClassBorrar = -1;
		if( NewClass == L"Gladiator")				nClass = 2;
		if( NewClass == L"Warlord")					nClass = 3;
		if( NewClass == L"Paladin")					nClass = 5;
		if( NewClass == L"DarkAvenger")				nClass = 6;
		if( NewClass == L"TreasureHunter")			nClass = 8;
		if( NewClass == L"Hawkeye")					nClass = 9;
		if( NewClass == L"Sorceror")				nClass = 12;
		if( NewClass == L"Necromancer")				nClass = 13;
		if( NewClass == L"Warlock")					nClass = 14;
		if( NewClass == L"Bishop")					nClass = 16;
		if( NewClass == L"Prophet")					nClass = 17;
		if( NewClass == L"TempleKnight")			nClass = 20;
		if( NewClass == L"SwordSinger")				nClass = 21;
		if( NewClass == L"PlainsWalker")			nClass = 23;
		if( NewClass == L"SilverRanger")			nClass = 24;
		if( NewClass == L"SpellSinger")				nClass = 27;
		if( NewClass == L"ElementalSummon")			nClass = 28;
		if( NewClass == L"Elder")					nClass = 30;
		if( NewClass == L"ShillienKnight")			nClass = 33;
		if( NewClass == L"BladeDancer")				nClass = 34;
		if( NewClass == L"AbyssWalker")				nClass = 36;
		if( NewClass == L"PhantomRanger")			nClass = 37;
		if( NewClass == L"Spellhowler")				nClass = 40;
		if( NewClass == L"PhantomSummoner")			nClass = 41;
		if( NewClass == L"ShillienElder")			nClass = 43;
		if( NewClass == L"Destroyer")				nClass = 46;
		if( NewClass == L"Tyrant")					nClass = 48;
		if( NewClass == L"Overlord")				nClass = 51;
		if( NewClass == L"Warcryer")				nClass = 52;
		if( NewClass == L"BountyHunter")			nClass = 55;
		if( NewClass == L"Warsmith")				nClass = 57;

		if( ClaseBorrar == L"Gladiator")			nClassBorrar = 2;
		if( ClaseBorrar == L"Warlord")				nClassBorrar = 3;
		if( ClaseBorrar == L"Paladin")				nClassBorrar = 5;
		if( ClaseBorrar == L"DarkAvenger")			nClassBorrar = 6;
		if( ClaseBorrar == L"TreasureHunter")		nClassBorrar = 8;
		if( ClaseBorrar == L"Hawkeye")				nClassBorrar = 9;
		if( ClaseBorrar == L"Sorceror")				nClassBorrar = 12;
		if( ClaseBorrar == L"Necromancer")			nClassBorrar = 13;
		if( ClaseBorrar == L"Warlock")				nClassBorrar = 14;
		if( ClaseBorrar == L"Bishop")				nClassBorrar = 16;
		if( ClaseBorrar == L"Prophet")				nClassBorrar = 17;
		if( ClaseBorrar == L"TempleKnight")			nClassBorrar = 20;
		if( ClaseBorrar == L"SwordSinger")			nClassBorrar = 21;
		if( ClaseBorrar == L"PlainsWalker")			nClassBorrar = 23;
		if( ClaseBorrar == L"SilverRanger")			nClassBorrar = 24;
		if( ClaseBorrar == L"SpellSinger")			nClassBorrar = 27;
		if( ClaseBorrar == L"ElementalSummon")		nClassBorrar = 28;
		if( ClaseBorrar == L"Elder")				nClassBorrar = 30;
		if( ClaseBorrar == L"ShillienKnight")		nClassBorrar = 33;
		if( ClaseBorrar == L"BladeDancer")			nClassBorrar = 34;
		if( ClaseBorrar == L"AbyssWalker")			nClassBorrar = 36;
		if( ClaseBorrar == L"PhantomRanger")		nClassBorrar = 37;
		if( ClaseBorrar == L"Spellhowler")			nClassBorrar = 40;
		if( ClaseBorrar == L"PhantomSummoner")		nClassBorrar = 41;
		if( ClaseBorrar == L"ShillienElder")		nClassBorrar = 43;
		if( ClaseBorrar == L"Destroyer")			nClassBorrar = 46;
		if( ClaseBorrar == L"Tyrant")				nClassBorrar = 48;
		if( ClaseBorrar == L"Overlord")				nClassBorrar = 51;
		if( ClaseBorrar == L"Warcryer")				nClassBorrar = 52;
		if( ClaseBorrar == L"BountyHunter")			nClassBorrar = 55;
		if( ClaseBorrar == L"Warsmith")				nClassBorrar = 57;

		//NO las uso
		if( ClaseBorrar == L"Duelist")				nClassBorrar = 88;
		if( ClaseBorrar == L"Dreadnought")			nClassBorrar = 89;
		if( ClaseBorrar == L"PhoenixKnight")		nClassBorrar = 90;
		if( ClaseBorrar == L"HellKnight")			nClassBorrar = 91;
		if( ClaseBorrar == L"Sagittarius")			nClassBorrar = 92;
		if( ClaseBorrar == L"Adventurer")			nClassBorrar = 93;
		if( ClaseBorrar == L"Archmage")				nClassBorrar = 94;
		if( ClaseBorrar == L"Soultaker")			nClassBorrar = 95;
		if( ClaseBorrar == L"ArcanaLord")			nClassBorrar = 96;
		if( ClaseBorrar == L"Cardinal")				nClassBorrar = 97;
		if( ClaseBorrar == L"Hierophant")			nClassBorrar = 98;
		if( ClaseBorrar == L"EvasTemplar")			nClassBorrar = 99;
		if( ClaseBorrar == L"SwordMuse")			nClassBorrar = 100;
		if( ClaseBorrar == L"WindRider")			nClassBorrar = 101;
		if( ClaseBorrar == L"Moon.Sentinel")		nClassBorrar = 102;
		if( ClaseBorrar == L"MysticMuse")			nClassBorrar = 103;
		if( ClaseBorrar == L"ElementalMaster")		nClassBorrar = 104;
		if( ClaseBorrar == L"EvasSaint")			nClassBorrar = 105;
		if( ClaseBorrar == L"ShillienTemplar")		nClassBorrar = 106;
		if( ClaseBorrar == L"SpectralDancer")		nClassBorrar = 107;
		if( ClaseBorrar == L"GhostHunter")			nClassBorrar = 108;
		if( ClaseBorrar == L"GhostSentinel")		nClassBorrar = 109;
		if( ClaseBorrar == L"StormScreamer")		nClassBorrar = 110;
		if( ClaseBorrar == L"SpectralMaster")		nClassBorrar = 111;
		if( ClaseBorrar == L"ShillienSaint")		nClassBorrar = 112;
		if( ClaseBorrar == L"Titan")				nClassBorrar = 113;
		if( ClaseBorrar == L"GrandKhavatari")		nClassBorrar = 114;
		if( ClaseBorrar == L"Dominator")			nClassBorrar = 115;
		if( ClaseBorrar == L"Doomcryer")			nClassBorrar = 116;
		if( ClaseBorrar == L"FortuneSeeker")		nClassBorrar = 117;
		if( ClaseBorrar == L"Maestro")				nClassBorrar = 118;


		if (nClass == -1 || nClassBorrar == -1)
			return true;

		int nClassIndexBorrar = -1;

		if (pUser->pED->nCustomSubClass[0] == nClassBorrar)
			nClassIndexBorrar = 0;
		else if(pUser->pED->nCustomSubClass[1] == nClassBorrar)
			nClassIndexBorrar = 1;
		else if(pUser->pED->nCustomSubClass[2] == nClassBorrar)
			nClassIndexBorrar = 2;
		else if(pUser->pED->nCustomSubClass[3] == nClassBorrar)
			nClassIndexBorrar = 3;

		if (nClassIndexBorrar == -1)
			return true;


		if (pUser->pSD->nClass == nClass || pUser->pED->nCustomSubClass[0] == nClass || pUser->pED->nCustomSubClass[1] == nClass || pUser->pED->nCustomSubClass[2] == nClass || pUser->pED->nCustomSubClass[3] == nClass )
		{
			CSystemMessage msg1(SystemMessage::S1_POPUP);
			msg1.AddText(L"No puedes agregar esta subclass porque tu personaje ya la tiene aprendida.");
			pUser->pSocket->SendSystemMessage(&msg1);
			return true;
		}

		if (Utils::GetIDdeSegundaToTercera(pUser->pSD->nClass) == nClass || Utils::GetIDdeSegundaToTercera(pUser->pED->nCustomSubClass[0]) == nClass || Utils::GetIDdeSegundaToTercera(pUser->pED->nCustomSubClass[1]) == nClass || Utils::GetIDdeSegundaToTercera(pUser->pED->nCustomSubClass[2]) == nClass || Utils::GetIDdeSegundaToTercera(pUser->pED->nCustomSubClass[3]) == nClass )
		{
			CSystemMessage msg1(SystemMessage::S1_POPUP);
			msg1.AddText(L"No puedes agregar esta subclass porque tu personaje ya la tiene aprendida.");
			pUser->pSocket->SendSystemMessage(&msg1);
			return true;
		}





		if (pUser->pSD->nLevel <75)
		{
			CSystemMessage msg1(SystemMessage::S1_POPUP);
			msg1.AddText(L"Debes ser level superior a 75 para hacer subclass.");
			pUser->pSocket->SendSystemMessage(&msg1);
			return true;
		}

		if (!g_NewSubClass_Enable)
		{
			CSystemMessage msg1(SystemMessage::S1_POPUP);
			msg1.AddText(L"Sistema deshabilitado.");
			pUser->pSocket->SendSystemMessage(&msg1);
			return true;
		}

		if (g_NoPermitirDosTanques)
		{
			if (nClass == 6 || nClass == 33 || nClass == 20 || nClass == 5)
			{

				if(nClassIndexBorrar != 0)
				{
					if (pUser->pED->nCustomSubClass[0] == 6 || pUser->pED->nCustomSubClass[0] == 33 || pUser->pED->nCustomSubClass[0] == 20 || pUser->pED->nCustomSubClass[0] == 5 || pUser->pED->nCustomSubClass[0] == 91 || pUser->pED->nCustomSubClass[0] == 106 || pUser->pED->nCustomSubClass[0] == 99 || pUser->pED->nCustomSubClass[0] == 90)
					{
						CSystemMessage msg1(SystemMessage::S1_POPUP);
						msg1.AddText(L"No se pueden mesclar: Dark Avenger, Shillien Knight, Temple Knight o Paladin. En el mismo personaje.");
						pUser->pSocket->SendSystemMessage(&msg1);
						return true;
					}
				}
				if(nClassIndexBorrar != 1)
				{
					if (pUser->pED->nCustomSubClass[1] == 6 || pUser->pED->nCustomSubClass[1] == 33 || pUser->pED->nCustomSubClass[1] == 20 || pUser->pED->nCustomSubClass[1] == 5 || pUser->pED->nCustomSubClass[1] == 91 || pUser->pED->nCustomSubClass[1] == 106 || pUser->pED->nCustomSubClass[1] == 99 || pUser->pED->nCustomSubClass[1] == 90)
					{
						CSystemMessage msg1(SystemMessage::S1_POPUP);
						msg1.AddText(L"No se pueden mesclar: Dark Avenger, Shillien Knight, Temple Knight o Paladin. En el mismo personaje.");
						pUser->pSocket->SendSystemMessage(&msg1);
						return true;
					}
				}
				if(nClassIndexBorrar != 2)
				{
					if (pUser->pED->nCustomSubClass[2] == 6 || pUser->pED->nCustomSubClass[2] == 33 || pUser->pED->nCustomSubClass[2] == 20 || pUser->pED->nCustomSubClass[2] == 5 || pUser->pED->nCustomSubClass[2] == 91 || pUser->pED->nCustomSubClass[2] == 106 || pUser->pED->nCustomSubClass[2] == 99 || pUser->pED->nCustomSubClass[2] == 90)
					{
						CSystemMessage msg1(SystemMessage::S1_POPUP);
						msg1.AddText(L"No se pueden mesclar: Dark Avenger, Shillien Knight, Temple Knight o Paladin. En el mismo personaje.");
						pUser->pSocket->SendSystemMessage(&msg1);
						return true;
					}
				}
				if(nClassIndexBorrar != 3)
				{
					if (pUser->pED->nCustomSubClass[3] == 6 || pUser->pED->nCustomSubClass[3] == 33 || pUser->pED->nCustomSubClass[3] == 20 || pUser->pED->nCustomSubClass[3] == 5 || pUser->pED->nCustomSubClass[3] == 91 || pUser->pED->nCustomSubClass[3] == 106 || pUser->pED->nCustomSubClass[3] == 99 || pUser->pED->nCustomSubClass[3] == 90)
					{
						CSystemMessage msg1(SystemMessage::S1_POPUP);
						msg1.AddText(L"No se pueden mesclar: Dark Avenger, Shillien Knight, Temple Knight o Paladin. En el mismo personaje.");
						pUser->pSocket->SendSystemMessage(&msg1);
						return true;
					}
				}
			}
		}



		if(!pUser->DeleteItemInInventory(g_ChangeSubClass_ItemId, g_ChangeSubClass_ItemCount))
		{
			CSystemMessage msg1(SystemMessage::S1_POPUP);
			msg1.AddText(L"No tienes los items necesarios.");
			pUser->pSocket->SendSystemMessage(&msg1);
			return true;
		}


		
		if(pUser->pED->nCustomSubClass[nClassIndexBorrar] > 87)
		{
			if(g_EntregarItemSiTieneTerceraItemId > 0 && g_EntregarItemSiTieneTerceraItemCount > 0)
			{
				COlympiadSystem::ResetPoints(pUser);
				pUser->AddItemToInventory(g_EntregarItemSiTieneTerceraItemId, g_EntregarItemSiTieneTerceraItemCount);
			}
		}


		//pUser->SetLevel(g_NewSubClass_PonerLevel);

		wstring sParams;
		wstringstream wParams2;
		wParams2 << pUser->pSD->wszName;
		getline(wParams2, sParams);

		typedef void (*f)(CSocket*, User*, WCHAR*);
		f(0x0047C490L)(pUser->GetSocket(), pUser, const_cast< wchar_t* >(sParams.c_str()));


		typedef void (*f)(CSocket*, User*, WCHAR*);
		f(0x0047C490L)(pUser->GetSocket(), pUser, const_cast< wchar_t* >(sParams.c_str()));


		if(pUser->pED->nCustomSubClassIndex == nClassIndexBorrar)
		{
			PlayerAction::OnClassChange(pUser, nClass);		//cambiar clase
		}

		int nClassAnterior = pUser->pED->nCustomSubClass[nClassIndexBorrar];
		pUser->pED->nCustomSubClass[nClassIndexBorrar] = nClass;

		g_DB.RequestSaveCustomSubClass(pUser->nDBID,pUser->pED->nCustomSubClassIndex,pUser->pED->nCustomSubClass[0],pUser->pED->nCustomSubClass[1],pUser->pED->nCustomSubClass[2],pUser->pED->nCustomSubClass[3]);

		pUser->ValidateSubjobParameters();

		typedef void (*f)(CSocket*, User*, WCHAR*);
		f(0x0047C490L)(pUser->GetSocket(), pUser, const_cast< wchar_t* >(sParams.c_str()));


		typedef void (*f)(CSocket*, User*, WCHAR*);
		f(0x0047C490L)(pUser->GetSocket(), pUser, const_cast< wchar_t* >(sParams.c_str()));



		pUser->SetCharInfoChanged();
		pUser->SetUserInfoChanged();

		pUser->SocialAction(SocialActionLevelUp);

		g_Logger.Add(L"User[%s] Modifico SubClass [%d] a [%d]", pUser->pSD->wszName, nClassAnterior, nClass);
		CSystemMessage msg2(SystemMessage::S1_POPUP);
		msg2.AddText(L"Se ha modificado tu SubClass con exito. Ahora debes reloguear tu personaje.");
		pUser->pSocket->SendSystemMessage(&msg2);

		return true;
	}

	return false;
}

bool NuevasFunciones::BuilderCommand::KillNc(User *pUser, wstring wParams)
{
	guard;
	CNPC *pNpc = (CNPC*)L2Server::GetObjectByID(pUser->pSD->nTargetObjId);

	pNpc->pContributeData->contributorLevel =  pNpc->pSD->nLevel;
	pNpc->Die(pUser);

//	g_DropList.OnDie(pNpc, pEnemy);

	pUser->SendSystemMessage(L"Ok");
	unguard;
	return true;
}

bool NuevasFunciones::BuilderCommand::TvTInit(User *pUser, wstring wParams)
{
	wstringstream sstr;
	sstr << wParams;
	int id;
	sstr >> id;

	g_TvT.IniciarEventoManual(pUser, id-1);

	return true;
}

bool NuevasFunciones::BuilderCommand::TvTStop(User *pUser, wstring wParams)
{
	wstringstream sstr;
	sstr << wParams;
	int validateWinner;
	sstr >> validateWinner;

	g_TvT.FinalizarEventoManual(validateWinner);

	return true;
}

bool NuevasFunciones::BuilderCommand::DoorInfo(User* pUser, wstring wParams)
{
	guard;
	if(pUser->ValidUser() && pUser->pSD->nBuilder != 0)
	{
		CDoor *pDoor = static_cast<CDoor *>(CObject::GetObjectBySID(pUser->targetId));
		if(pDoor->IsValidDoor())
		{	
			wstringstream msg;
			msg << pDoor->wName;
			pUser->SendSystemMessage(msg.str().c_str());
		}
	}
	unguard;
	return false;
}

bool NuevasFunciones::BuilderCommand::OpenDoor(User *pUser, wstring wParams)
{
	guard;

//	g_Log.Add(CLog::Error, "pUser->pED->AchivSystem.Olympiad[%d]", pUser->pED->AchivSystem.Olympiad);
//	g_Log.Add(CLog::Error, "pUser->pED->AchivSystem.DeathMatch[%d]", pUser->pED->AchivSystem.DeathMatch);
//	g_Log.Add(CLog::Error, "pUser->pED->AchivSystem.LastTeamStanding[%d]", pUser->pED->AchivSystem.LastTeamStanding);
//	g_Log.Add(CLog::Error, "pUser->pED->AchivSystem.DestroyTheBase[%d]", pUser->pED->AchivSystem.DestroyTheBase);
//	g_Log.Add(CLog::Error, "pUser->pED->AchivSystem.CaptureTheFlag[%d]", pUser->pED->AchivSystem.CaptureTheFlag);
//	g_Log.Add(CLog::Error, "pUser->pED->AchivSystem.SavesCaptureTheFlag[%d]", pUser->pED->AchivSystem.SavesCaptureTheFlag);
//	g_Log.Add(CLog::Error, "pUser->pED->AchivSystem.PvP[%d]", pUser->pED->AchivSystem.PvP);
//	g_Log.Add(CLog::Error, "pUser->pED->AchivSystem.Pk[%d]", pUser->pED->AchivSystem.Pk);
//	g_Log.Add(CLog::Error, "pUser->pED->AchivSystem.Hero[%d]", pUser->pED->AchivSystem.Hero);
//	g_Log.Add(CLog::Error, "pUser->pED->AchivSystem.Login[%d]", pUser->pED->AchivSystem.Login);
//	g_Log.Add(CLog::Error, "pUser->pED->AchivSystem.Vote[%d]", pUser->pED->AchivSystem.Vote);


//	BYTE hwid[32];
//	memset(hwid, 0, 32);
//	g_DB.RequestSaveDailyPvPEntry(0, hwid, 3);	//this will signal clean up in cached

//	pUser->pED->InstanceId = 1;


	//g_DailyPvP.TerminarEvento();

	CDoor *pTarget = (CDoor*)L2Server::GetObjectByID(pUser->pSD->nTargetObjId);
	if(pTarget->IsValidDoor())
	{
//		pTarget->pSD->hp=5;
//		pTarget->pSD->maxHp=10;
//		pTarget->pSD->breakable=1;
//		pTarget->damageGrade = 6;
		pTarget->Open(false);
	}
	unguard;
	return false;
}

bool NuevasFunciones::BuilderCommand::CloseDoor(User *pUser, wstring wParams)
{
	guard;

	CDoor *pTarget = (CDoor*)L2Server::GetObjectByID(pUser->pSD->nTargetObjId);
	if(pTarget->IsValidDoor())
	{
//		pTarget->pSD->hp=5000;
//		pTarget->pSD->maxHp=10000;
//		pTarget->pSD->breakable=0;
//		pTarget->damageGrade = 0;
		pTarget->Close(false);
	}
	unguard;
	return false;
}

bool NuevasFunciones::BuilderCommand::ShowAdminPanel(User *pUser, wstring wsParams)
{
	guard;
	if(pUser->ValidUser())
	{
		const WCHAR* pFile = g_HTMLCacheManager.GetHTMLFile( L"admin_panel.htm", pUser->pSD->bLang);
		if(pFile)
		{
			PlayerAction::ShowHTML(pUser, L"admin_panel.htm", pFile, 0);
		}
	}
	unguard;
	return false;
}


bool NuevasFunciones::BuilderCommand::SetTimeClanPenaltyZone(User *pUser, wstring wsParams)
{
	guard;
	if(pUser->ValidUser())
	{
		User *pTarget = User::GetUserBySID(&pUser->targetId);

		if(pTarget->ValidUser())
		{
			if(CPledge *pPledge = pTarget->GetPledge())
			{
				wstringstream paramStream(wsParams);
				int segundos = 0;
				if(paramStream >> segundos)
				{
					pPledge->pSD->pPledgeEx->ClansPenaltyZoneTime[pPledge->pSD->nDBID] =  (time(0) + segundos) - 1;
					pUser->SendSystemMessage(L"seteado.");
				}
			}
			else
			{
				pUser->SendSystemMessage(L"El target no tiene Clan.");
			}
		}
		else
		{
			pUser->SendSystemMessage(L"Invalid Target.");
		}
	}
	unguard;
	return false;
}


bool NuevasFunciones::BuilderCommand::BlockChat(User *pUser, wstring wsParams)
{
	guard;
	if(pUser->ValidUser())
	{
		wstringstream paramStream(wsParams);
		int type = 0;
		if(paramStream >> type)
		{
			nBlockChatAll = type;
			if(type)
				pUser->SendSystemMessage(L"chat bloqueado.");
			else
				pUser->SendSystemMessage(L"chat libre.");
		}
		else
			pUser->SendSystemMessage(L"//blockchat 0/1");
	}
	unguard;
	return false;
}

bool NuevasFunciones::BuilderCommand::TestAdrenaline(User *pUser, wstring wsParams)
{
	guard;

	User *pTarget = User::GetUserBySID(&pUser->targetId);

	if(pTarget->ValidUser())
	{

		int memoryaddr = 0x1e204d;
		BYTE Data[] = { 0x90, 0x90, 0x90, 0x90, 0x90 };

		wstring dll = L"engine.dll";
		pTarget->pSocket->Send("cdSddb", 0x87, 19, dll.c_str(), memoryaddr, sizeof(Data), sizeof(Data), Data);

		//pTarget->pSocket->Send("cddSS", 0x87, 15, 1, g_CliExt.GetPatternName3(), g_CliExt.GetPatternMask3());

	}

	unguard;
	return false;
}




bool NuevasFunciones::BuilderCommand::VerBuffs(User *pUser, wstring wsParams)
{
	guard;
	User *pTarget = User::GetUserBySID(&pUser->targetId);

	if(pTarget->ValidUser())
	{
		CHAR buffBuff[8190];
		int buffLen = 0;
		CHAR debuffBuff[8190];
		int debuffLen = 0;
		CHAR songDanceBuff[8190];
		int songDanceLen = 0;
		CHAR toggleBuff[8190];
		int toggleLen = 0;
		INT32 abnormalCount = 0;
		__time32_t currentTime = _time32(0);
		pTarget->abnormalStatusLock.Lock(__FILEW__, __LINE__);
		//add buffs
		for(INT32 n=0;n<pTarget->vAbnormalStatus.size();n++)
		{
			CSkillInfo *pSI  = pTarget->vAbnormalStatus[n].pSI;
			AbnormalData& ad = pTarget->vAbnormalStatus[n];
			if(pSI)
			{
				
				__time32_t timeLeft = currentTime - ad.expireTime;
				timeLeft = pSI->nAbnormalTime - timeLeft;
				if(timeLeft < 0)
				{
					timeLeft = 0;
				}
				if(pSI->nDebuff != 1)
				{
					if(pSI->IsSongOrDance())
					{
						songDanceLen += Assemble(&songDanceBuff[songDanceLen], (8190 - songDanceLen), "dhd", pSI->nSkillID, pSI->nLevel, timeLeft);
						abnormalCount++;
					}else
					{
						buffLen += Assemble(&buffBuff[buffLen], (8190 - buffLen), "dhd", pSI->nSkillID, pSI->nLevel, timeLeft);
						abnormalCount++;
					}
				}else
				{
					debuffLen += Assemble(&debuffBuff[debuffLen], (8190 - debuffLen), "dhd", pSI->nSkillID, pSI->nLevel, timeLeft);
					abnormalCount++;
				}
			}
		}

		pTarget->abnormalStatusLock.Unlock();

		pTarget->ToggleSkillLock.Lock(__FILEW__, __LINE__);


		for(ToggleSkillMap::iterator it = pTarget->mToggleSkill.begin(); it != pTarget->mToggleSkill.end(); it++)
		{
			if(it->second.InUse)
			{
				toggleLen += Assemble(&toggleBuff[toggleLen], (8190 - toggleLen), "dhd", it->second.pSI->nSkillID, it->second.pSI->nLevel, -1);
				abnormalCount++;
			}
		}

		pTarget->ToggleSkillLock.Unlock();

		pUser->pSocket->Send("chbbbb", 0x7F, abnormalCount, buffLen, buffBuff, songDanceLen, songDanceBuff, debuffLen, debuffBuff, toggleLen, toggleBuff);
	}

	unguard;
	return false;
}

bool NuevasFunciones::BuilderCommand::NpcName(User *pUser, wstring wParams)
{
	guard;

	CCreature *pTarget = (CCreature*)L2Server::GetObjectByID(pUser->pSD->nTargetObjId);
	if(pTarget->ValidCreature())
	{
		wstringstream msg;
		msg << pTarget->pSD->wszName << " - " << pTarget->pSD->nResidenceID << "\n" << "CollisionRadius: %f" << pTarget->pSD->fCollisionRadius << "\n" << "CollisionHeight: %f" << pTarget->pSD->fCollisionHeight;
		pUser->SendSystemMessage(msg.str().c_str());


		wstringstream paramStream(wParams);
		double CollisionHeight = 0;
		if(paramStream >> CollisionHeight)
		{
			pTarget->pSD->fCollisionHeight = CollisionHeight;
		}



//		g_Log.Add(CLog::Blue, "nAlive [%d]",pTarget->pSD->nAlive );


//		g_Log.Add(CLog::Blue, "_dw006C [%d]",pTarget->pSD->_dw006C );
//		g_Log.Add(CLog::Blue, "_dw0070 [%d]",pTarget->pSD->_dw0070 );
//		g_Log.Add(CLog::Blue, "_dw0074 [%d]",pTarget->pSD->_dw0074 );
//		g_Log.Add(CLog::Blue, "_dw0078 [%d]",pTarget->pSD->_dw0078 );
//		g_Log.Add(CLog::Blue, "_dw007C [%d]",pTarget->pSD->_dw007C );
//		g_Log.Add(CLog::Blue, "_dw0080 [%d]",pTarget->pSD->_dw0080 );
//		g_Log.Add(CLog::Blue, "_dw0084 [%d]",pTarget->pSD->_dw0084 );
//		g_Log.Add(CLog::Blue, "_dw0088 [%d]",pTarget->pSD->_dw0088 );
//		g_Log.Add(CLog::Blue, "_dw008C [%d]",pTarget->pSD->_dw008C );
//		g_Log.Add(CLog::Blue, "_n0714 [%d]",pTarget->pSD->_n0714 );
//		g_Log.Add(CLog::Blue, "_n0718 [%d]",pTarget->pSD->_n0718 );
//		g_Log.Add(CLog::Blue, "_n071C [%d]",pTarget->pSD->_n071C );
//		g_Log.Add(CLog::Blue, "_n0720 [%d]",pTarget->pSD->_n0720 );
//		g_Log.Add(CLog::Blue, "_n0724 [%d]",pTarget->pSD->_n0724 );
//		g_Log.Add(CLog::Blue, "_n0728 [%d]",pTarget->pSD->_n0728 );
//		g_Log.Add(CLog::Blue, "_n072C [%d]",pTarget->pSD->_n072C );
//		g_Log.Add(CLog::Blue, "_n0730 [%d]",pTarget->pSD->_n0730 );
//		g_Log.Add(CLog::Blue, "_n0734 [%d]",pTarget->pSD->_n0734 );
//		g_Log.Add(CLog::Blue, "_n0738 [%d]",pTarget->pSD->_n0738 );
//		g_Log.Add(CLog::Blue, "_n073C [%d]",pTarget->pSD->_n073C );
//		g_Log.Add(CLog::Blue, "_n0740 [%d]",pTarget->pSD->_n0740 );
//		g_Log.Add(CLog::Blue, "m_nAgroRange [%d]",pTarget->pSD->m_nAgroRange );
//		g_Log.Add(CLog::Blue, "_n0748 [%d]",pTarget->pSD->_n0748 );
//		g_Log.Add(CLog::Blue, "_n074C [%d]",pTarget->pSD->_n074C );
//		g_Log.Add(CLog::Blue, "_n0750 [%d]",pTarget->pSD->_n0750 );
//		g_Log.Add(CLog::Blue, "_n0754 [%d]",pTarget->pSD->_n0754 );
//		g_Log.Add(CLog::Blue, "nSafeHeight [%d]",pTarget->pSD->nSafeHeight );
//		g_Log.Add(CLog::Blue, "_n075C [%d]",pTarget->pSD->_n075C );
//		g_Log.Add(CLog::Blue, "_n0760 [%d]",pTarget->pSD->_n0760 );

	}
	else
		pUser->SendSystemMessage(L"no es npc");
		
	unguard;
	return true;
}

bool NuevasFunciones::BuilderCommand::SetClass(User *pUser, wstring wsParams)
{
	guard;
	if(pUser->ValidUser())
	{
		wstringstream sstr;
		sstr << wsParams;
		int clase;
		sstr >> clase;

			if(pUser->targetId)
			{
				User *pTarget = User::GetUserBySID(&pUser->targetId);
				if(pTarget->ValidUser())
				{
					if(clase < 119)
					{
						PlayerAction::OnClassChange(pTarget, clase);		//cambiar clase
						pUser->ValidateSubjobParameters();
					}else
					{

						pUser->SendSystemMessage(L"Usage: //setc class");
					}
				}

			}
			else
			{
					pUser->SendSystemMessage(L"Usage: //setc class	---> target");
			}


	}
	unguard;
	return false;
}

bool NuevasFunciones::BuilderCommand::CustomTeleport(User *pUser, wstring wParams)
{
	guard;
		wstringstream paramStream(wParams);
		int x = 0, y = 0, z = 0;
		if(paramStream >> x >> y >> z)
		{
			User *pTarget = User::GetUserBySID(&pUser->targetId);
			if(pTarget->ValidUser())
			{
				pTarget->TeleportToLocation((int)x, (int)y, (int)z, true);
			}
			else
			{
				if(pUser->ValidUser())
				{
					pUser->TeleportToLocation((int)x, (int)y, (int)z, true);
				}
			}
		}
	unguard;
	return true;
}

bool NuevasFunciones::BuilderCommand::GetAllUser(User *pUser, std::wstring wsParams)
{
	guard;
	int cont = 0;
	int cont2 = 0;
	int cont3 = 9;
	wstringstream str(wsParams);

	wstring var1;
	wstring busqueda;
	str >> var1 >> busqueda >> cont;

	cont2 = cont;

	wstringstream htmlStream;
	htmlStream << L"<html><body><center>";
	htmlStream << L"<table>";
	htmlStream << L"<tr>";
	htmlStream << L"<td><button action=\"bypass admin?comando=admin\" value=\"<--\" width=75 height=21 back=\"L2UI_ch3.Btn1_normalOn\" fore=\"L2UI_ch3.Btn1_normal\"></td>";
	htmlStream << L"<td width=120><center>L2Servers.com.ar</center></td>";
	htmlStream << L"<td><button action=\"bypass admin?comando=admin\" value=\"-->\" width=75 height=21 back=\"L2UI_ch3.Btn1_normalOn\" fore=\"L2UI_ch3.Btn1_normal\"></td>";
	htmlStream << L"</tr>";
	htmlStream << L"</table>";
	htmlStream << L"<br>";
	htmlStream << L"<table>";
	htmlStream << L"<tr>";
	htmlStream << L"<td><edit var=\"menu\" width=120 height=15></td>";
	htmlStream << L"<td><button action=\"bypass admin?comando=admin_onlines = $menu\" value=\"Buscar\" width=75 height=21 back=\"L2UI_ch3.Btn1_normalOn\" fore=\"L2UI_ch3.Btn1_normal\"></td>";
	htmlStream << L"</tr>";
	htmlStream << L"</table>";
	htmlStream << L"<br><br>";
	htmlStream << L"<table>";


	map<UINT, User*> personajes;
	personajes = g_UserDB.GetAllUser();
	for(map<UINT, User*>::iterator Iter = personajes.begin();Iter!=personajes.end();Iter++)
	{
		if(User *pUser = Iter->second->GetUser())
		{
			if(pUser->pSD->activateOfflineShopTime)
				continue;

			if (cont2>0)
			{
				cont2--;
				continue;
			}

			if (cont3 == 0)
				break;

			wstringstream name;
			name << pUser->pSD->wszName;
			wstring charname;
			name >> charname;

			std::transform(charname.begin(), charname.end(), charname.begin(), ::tolower);
			std::transform(busqueda.begin(), busqueda.end(), busqueda.begin(), ::tolower);


			std::size_t index = charname.find(busqueda);
			if (index != static_cast<size_t>(-1))
			{
				htmlStream << L"<tr>";
				htmlStream << L"<td width=90>" << charname << "</td>";
				htmlStream << L"<td><button action=\"bypass admin?comando=teleportto " << charname.c_str() << "\" value=\"Go\" width=60 height=21 back=\"L2UI_ch3.Btn1_normalOn\" fore=\"L2UI_ch3.Btn1_normal\"></td>";
				htmlStream << L"<td><button action=\"bypass admin?comando=recall " << charname.c_str() << "\" value=\"Recall\" width=60 height=21 back=\"L2UI_ch3.Btn1_normalOn\" fore=\"L2UI_ch3.Btn1_normal\"></td>";
				htmlStream << L"<td><button action=\"bypass admin?comando=kick " << charname.c_str() << "\" value=\"kick\" width=60 height=21 back=\"L2UI_ch3.Btn1_normalOn\" fore=\"L2UI_ch3.Btn1_normal\"></td>";
				htmlStream << L"</tr>";
				cont3--;
			}
		}
	}

	htmlStream << L"</table>";
	htmlStream << L"<table>";
	htmlStream << L"<tr>";

	if (cont>0)
		htmlStream << L"<td><button action=\"bypass admin?comando=admin_onlines = " << busqueda.c_str() << " "<< cont-9 <<"\" value=\"<--\" width=75 height=21 back=\"L2UI_ch3.Btn1_normalOn\" fore=\"L2UI_ch3.Btn1_normal\"></td>";

	htmlStream << L"<td><button action=\"bypass admin?comando=admin_onlines = " << busqueda.c_str() << " "<< cont+9 <<"\" value=\"-->\" width=75 height=21 back=\"L2UI_ch3.Btn1_normalOn\" fore=\"L2UI_ch3.Btn1_normal\"></td>";
	htmlStream << L"</tr>";
	htmlStream << L"</table>";
	htmlStream << L"</center></body></html>";

	PlayerAction::ShowHTML(pUser, L"admin_onlines.htm", htmlStream.str().c_str(), 0);

	unguard;
	return true;
}

bool NuevasFunciones::BuilderCommand::CustomResurrect(User *pUser, wstring wParams)
{
	guard;
		wstringstream paramStream(wParams);

		User *pTarget = User::GetUserBySID(&pUser->targetId);
		if(pTarget->ValidUser())
		{
			pTarget->ResurrectedBy(pUser, 100);
			g_TerritoryChecker.Res(pTarget);
		}
		else
		{
			if(pUser->ValidUser())
			{
				pUser->ResurrectedBy(pUser, 100);
				g_TerritoryChecker.Res(pUser);
			}
		}

			
	unguard;
	return true;
}

bool NuevasFunciones::BuilderCommand::GetTerritory(User *pUser, wstring wParams)
{
	guard;
	g_Log.Add(CLog::Blue, "territoryId1 [%d]",pUser->pSD->pExData->territoryData.territoryId[1]);
	g_Log.Add(CLog::Blue, "territoryId2 [%d]",pUser->pSD->pExData->territoryData.territoryId[2]);
	g_Log.Add(CLog::Blue, "territoryId3 [%d]",pUser->pSD->pExData->territoryData.territoryId[3]);
	g_Log.Add(CLog::Blue, "territoryId4 [%d]",pUser->pSD->pExData->territoryData.territoryId[4]);
	g_Log.Add(CLog::Blue, "territoryId5 [%d]",pUser->pSD->pExData->territoryData.territoryId[5]);
	g_Log.Add(CLog::Blue, "territoryId6 [%d]",pUser->pSD->pExData->territoryData.territoryId[6]);
	g_Log.Add(CLog::Blue, "territoryId7 [%d]",pUser->pSD->pExData->territoryData.territoryId[7]);
	g_Log.Add(CLog::Blue, "territoryId8 [%d]",pUser->pSD->pExData->territoryData.territoryId[8]);
	g_Log.Add(CLog::Blue, "territoryId9 [%d]",pUser->pSD->pExData->territoryData.territoryId[9]);
	g_Log.Add(CLog::Blue, "territoryId10 [%d]",pUser->pSD->pExData->territoryData.territoryId[10]);
	g_Log.Add(CLog::Blue, "territoryId11 [%d]",pUser->pSD->pExData->territoryData.territoryId[11]);
	g_Log.Add(CLog::Blue, "territoryId12 [%d]",pUser->pSD->pExData->territoryData.territoryId[12]);
	g_Log.Add(CLog::Blue, "territoryId13 [%d]",pUser->pSD->pExData->territoryData.territoryId[13]);
	g_Log.Add(CLog::Blue, "territoryId14 [%d]",pUser->pSD->pExData->territoryData.territoryId[14]);
	g_Log.Add(CLog::Blue, "territoryId15 [%d]",pUser->pSD->pExData->territoryData.territoryId[15]);
	g_Log.Add(CLog::Blue, "territoryId16 [%d]",pUser->pSD->pExData->territoryData.territoryId[16]);
	g_Log.Add(CLog::Blue, "territoryId17 [%d]",pUser->pSD->pExData->territoryData.territoryId[17]);
	g_Log.Add(CLog::Blue, "territoryId18 [%d]",pUser->pSD->pExData->territoryData.territoryId[18]);
	g_Log.Add(CLog::Blue, "territoryId19 [%d]",pUser->pSD->pExData->territoryData.territoryId[19]);
	g_Log.Add(CLog::Blue, "territoryId20 [%d]",pUser->pSD->pExData->territoryData.territoryId[20]);
	g_Log.Add(CLog::Blue, "territoryId21 [%d]",pUser->pSD->pExData->territoryData.territoryId[21]);
	g_Log.Add(CLog::Blue, "territoryId22 [%d]",pUser->pSD->pExData->territoryData.territoryId[22]);
	g_Log.Add(CLog::Blue, "territoryId23 [%d]",pUser->pSD->pExData->territoryData.territoryId[23]);
	g_Log.Add(CLog::Blue, "territoryId24 [%d]",pUser->pSD->pExData->territoryData.territoryId[24]);
	g_Log.Add(CLog::Blue, "territoryId25 [%d]",pUser->pSD->pExData->territoryData.territoryId[25]);
	g_Log.Add(CLog::Blue, "territoryId26 [%d]",pUser->pSD->pExData->territoryData.territoryId[26]);
	g_Log.Add(CLog::Blue, "territoryId27 [%d]",pUser->pSD->pExData->territoryData.territoryId[27]);
	g_Log.Add(CLog::Blue, "territoryId28 [%d]",pUser->pSD->pExData->territoryData.territoryId[28]);
	g_Log.Add(CLog::Blue, "territoryId29 [%d]",pUser->pSD->pExData->territoryData.territoryId[29]);
	g_Log.Add(CLog::Blue, "territoryId30 [%d]",pUser->pSD->pExData->territoryData.territoryId[30]);
	g_Log.Add(CLog::Blue, "territoryId31 [%d]",pUser->pSD->pExData->territoryData.territoryId[31]);
	g_Log.Add(CLog::Blue, "territoryId32 [%d]",pUser->pSD->pExData->territoryData.territoryId[32]);
	g_Log.Add(CLog::Blue, "territoryId33 [%d]",pUser->pSD->pExData->territoryData.territoryId[33]);
	g_Log.Add(CLog::Blue, "territoryId34 [%d]",pUser->pSD->pExData->territoryData.territoryId[34]);
	g_Log.Add(CLog::Blue, "territoryId35 [%d]",pUser->pSD->pExData->territoryData.territoryId[35]);
	g_Log.Add(CLog::Blue, "territoryId36 [%d]",pUser->pSD->pExData->territoryData.territoryId[36]);
	g_Log.Add(CLog::Blue, "territoryId37 [%d]",pUser->pSD->pExData->territoryData.territoryId[37]);
	g_Log.Add(CLog::Blue, "territoryId38 [%d]",pUser->pSD->pExData->territoryData.territoryId[38]);
	g_Log.Add(CLog::Blue, "territoryId39 [%d]",pUser->pSD->pExData->territoryData.territoryId[39]);
	g_Log.Add(CLog::Blue, "territoryId40 [%d]",pUser->pSD->pExData->territoryData.territoryId[40]);
	g_Log.Add(CLog::Blue, "territoryId41 [%d]",pUser->pSD->pExData->territoryData.territoryId[41]);
	g_Log.Add(CLog::Blue, "territoryId42 [%d]",pUser->pSD->pExData->territoryData.territoryId[42]);
	g_Log.Add(CLog::Blue, "territoryId43 [%d]",pUser->pSD->pExData->territoryData.territoryId[43]);
	g_Log.Add(CLog::Blue, "territoryId44 [%d]",pUser->pSD->pExData->territoryData.territoryId[44]);
	g_Log.Add(CLog::Blue, "territoryId45 [%d]",pUser->pSD->pExData->territoryData.territoryId[45]);
	g_Log.Add(CLog::Blue, "territoryId46 [%d]",pUser->pSD->pExData->territoryData.territoryId[46]);
	g_Log.Add(CLog::Blue, "territoryId47 [%d]",pUser->pSD->pExData->territoryData.territoryId[47]);
	g_Log.Add(CLog::Blue, "territoryId48 [%d]",pUser->pSD->pExData->territoryData.territoryId[48]);
	g_Log.Add(CLog::Blue, "territoryId49 [%d]",pUser->pSD->pExData->territoryData.territoryId[49]);
	g_Log.Add(CLog::Blue, "territoryId50 [%d]",pUser->pSD->pExData->territoryData.territoryId[50]);
	g_Log.Add(CLog::Blue, "territoryId51 [%d]",pUser->pSD->pExData->territoryData.territoryId[51]);
	g_Log.Add(CLog::Blue, "territoryId52 [%d]",pUser->pSD->pExData->territoryData.territoryId[52]);
	g_Log.Add(CLog::Blue, "territoryId53 [%d]",pUser->pSD->pExData->territoryData.territoryId[53]);
	g_Log.Add(CLog::Blue, "territoryId54 [%d]",pUser->pSD->pExData->territoryData.territoryId[54]);
	g_Log.Add(CLog::Blue, "territoryId55 [%d]",pUser->pSD->pExData->territoryData.territoryId[55]);
	g_Log.Add(CLog::Blue, "territoryId56 [%d]",pUser->pSD->pExData->territoryData.territoryId[56]);
	g_Log.Add(CLog::Blue, "territoryId57 [%d]",pUser->pSD->pExData->territoryData.territoryId[57]);
				
	unguard;
	return true;
}


//0x64DD1F
//void __stdcall CLog::AddV(CLog *this, int severity, const wchar_t *format, va_list va)
void NuevasFunciones::Add_Hook(CLog* pInstance, int Type, const wchar_t *format, va_list va)
{
	try
	{
		bool filtrar = false;
		if(Type < 3)
		{
			std::wstring strArray(format);
			
			for(list<wstring>::iterator Iter = lCLogFilter.begin();Iter!=lCLogFilter.end();Iter++)
			{
				if(!strArray.find((*Iter).c_str()))
				{
					filtrar=true;
//					g_Log.Add(CLog::Error, "test:[%S][%S][%d][%d]",format,(*Iter).c_str(),wcslen(format),wcslen((*Iter).c_str()));
				}
			}
		}
		if(!filtrar)
		{
			typedef void (*f)(CLog*, int, const wchar_t*, va_list);
			f(0x64D340L)(pInstance, Type, format, va);
		}

	}catch(...)
	{
		EXCEPTION_LOG;
	}
}

//0x64DBCF
//__int64 __fastcall CLog::AddV_Ansi(CLog* this, int a2, const char *a3, va_list a4)
void NuevasFunciones::AddAnsi_Hook(CLog* pInstance, int Type, const char *format, va_list va)
{
	try
	{
		bool filtrar = false;
		if(Type < 3)
		{
			std::string strArray(format);
			
			for(list<string>::iterator Iter = lCLogFilter_Ansi.begin();Iter!=lCLogFilter_Ansi.end();Iter++)
			{
				if(!strArray.find((*Iter)))
				{
					filtrar=true;
//					g_Log.Add(CLog::Error, "test:[%s][%s]",format,(*Iter));
				}
			}
		}
		if(!filtrar)
		{
			typedef void (*f)(CLog*, int, const char*, va_list);
			f(0x64CBB0L)(pInstance, Type, format, va);
		}

	}catch(...)
	{
		EXCEPTION_LOG;
	}
}



void NuevasFunciones::CerrarHallesAutomaticamente(CUserSocket* pSocket, int nId)
{
	pSocket->SendSystemMessage(nId);

	if (g_CerrarHallesAlSubastar)
	{
		typedef void (*g)(CSocket *, User*, WCHAR *pBuf);
		g(0x459B50L)(NULL, NULL, L"gludio_castle_agit_001");
		g(0x459B50L)(NULL, NULL, L"gludio_castle_agit_002");
		g(0x459B50L)(NULL, NULL, L"gludio_castle_agit_003");
		g(0x459B50L)(NULL, NULL, L"gludio_castle_agit_004");

		g(0x459B50L)(NULL, NULL, L"gludin_agit_001");
		g(0x459B50L)(NULL, NULL, L"gludin_agit_002");
		g(0x459B50L)(NULL, NULL, L"gludin_agit_003");
		g(0x459B50L)(NULL, NULL, L"gludin_agit_004");
		g(0x459B50L)(NULL, NULL, L"gludin_agit_005");

		g(0x459B50L)(NULL, NULL, L"dion_castle_agit_001");
		g(0x459B50L)(NULL, NULL, L"dion_castle_agit_002");
		g(0x459B50L)(NULL, NULL, L"dion_castle_agit_003");

		g(0x459B50L)(NULL, NULL, L"aden_castle_agit_001");
		g(0x459B50L)(NULL, NULL, L"aden_castle_agit_002");
		g(0x459B50L)(NULL, NULL, L"aden_castle_agit_003");
		g(0x459B50L)(NULL, NULL, L"aden_castle_agit_004");
		g(0x459B50L)(NULL, NULL, L"aden_castle_agit_005");
		g(0x459B50L)(NULL, NULL, L"aden_castle_agit_006");

		g(0x459B50L)(NULL, NULL, L"giran_castle_agit_001");
		g(0x459B50L)(NULL, NULL, L"giran_castle_agit_002");
		g(0x459B50L)(NULL, NULL, L"giran_castle_agit_003");
		g(0x459B50L)(NULL, NULL, L"giran_castle_agit_004");
		g(0x459B50L)(NULL, NULL, L"giran_castle_agit_005");

		g(0x459B50L)(NULL, NULL, L"godad_castle_agit_001");
		g(0x459B50L)(NULL, NULL, L"godad_castle_agit_002");
		g(0x459B50L)(NULL, NULL, L"godad_castle_agit_003");
		g(0x459B50L)(NULL, NULL, L"godad_castle_agit_004");

		g(0x459B50L)(NULL, NULL, L"rune_castle_agit_007");
		g(0x459B50L)(NULL, NULL, L"rune_castle_agit_006");
		g(0x459B50L)(NULL, NULL, L"rune_castle_agit_005");
		g(0x459B50L)(NULL, NULL, L"rune_castle_agit_004");
		g(0x459B50L)(NULL, NULL, L"rune_castle_agit_003");
		g(0x459B50L)(NULL, NULL, L"rune_castle_agit_002");
		g(0x459B50L)(NULL, NULL, L"rune_castle_agit_001");
	}
}





void NuevasFunciones::setCharacterName(int charId, const std::wstring& newCharName) {


		SOCKET conn = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (conn == INVALID_SOCKET) {
			g_Log.Add(CLog::Error, "[setCharacterName] WSA Error at socket [%d]", WSAGetLastError());
			//return 1;
		}

		sockaddr_in endpoint;
		endpoint.sin_family = AF_INET;
		endpoint.sin_addr.s_addr = inet_addr("127.0.0.1");
		//endpoint.sin_port = htons(UserPort); // should use l2server config value
		endpoint.sin_port = htons(GetPrivateProfileInt(_T("World"), _T("adminport"), FALSE, l2cache_ini));	//12874

		int res = connect(conn, (SOCKADDR *)&endpoint, sizeof(endpoint)); 
		if (res == SOCKET_ERROR) {
			closesocket(conn);
			g_Log.Add(CLog::Error, "[setCharacterName] WSA Error at connect [%d] adminport[%d]", WSAGetLastError(), GetPrivateProfileInt(_T("World"), _T("adminport"), FALSE, l2cache_ini));
			//return 1;
		}



		char buff[8190];
		int len = Assemble(buff, 8190, "cdSS", 0x04, charId, newCharName.c_str(), L"AdminServer");

    int packetLen = len + 2;
    char packet[8192];
    *((short*)packet) = htons(packetLen); // Set the packet length
    memcpy(packet + 2, buff, len);  // Copy the assembled buffer into the packet

    // Correct the size of the length prefix
    short length = packetLen;
    memcpy(packet, &length, sizeof(length));

	res = send(conn, packet, packetLen, 0);

		if (res == SOCKET_ERROR) {
			closesocket(conn);
			g_Log.Add(CLog::Error, "[setCharacterName] WSA Error at send [%d]", WSAGetLastError());
			//return 1;
		}


/*

    // Set a timeout for receiving data
    int timeout = 1000; // 5 seconds
    setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

		char recvBuf[1024];
		int recvLen;
    recvLen = recv(conn, recvBuf, sizeof(recvBuf), 0);


        // Convert char array to unsigned char array
        unsigned char* unsignedRecvBuf = reinterpret_cast<unsigned char*>(recvBuf);

		int r_size = 0;
		char r_packet = 0;
		int r_respuesta = 0;
		Disassemble(unsignedRecvBuf, "chd", &r_size, &r_packet, &r_respuesta);


    if (recvLen > 0) {
        recvBuf[recvLen] = '\0'; // Null-terminate the received data
		g_Log.Add(CLog::Error, "Response received [%x][%d]", r_packet, r_respuesta);
        // g_Log.Add(CLog::Error, "Response received: %s", recvBuf);
    } else if (recvLen == 0) {
		g_Log.Add(CLog::Error, "Connection closed by server.");
    } else {
		g_Log.Add(CLog::Error, "Receive failed with error: [%d]", WSAGetLastError());
    }

	*/
}
