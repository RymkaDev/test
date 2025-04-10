#include "StdAfx.h"
#include "MenuExtension.h"
#include "HerbSystem.h"
#include "AntiDDoS.h"
#include "ItemEnchant.h"
#include "BuildCmdHandler.h"
#include "TerritoryData.h"
#include "SchemeBuffer.h"
#include "TvT.h"
#include "Augmentation.h"
#include "MiningSystem.h"
#include "IpBlocker.h"
#include "TeleportBypass.h"
#include "VoteSystem.h"
#include "AutoAnnounce.h"
#include "ObsceneFilter.h"
#include "ArmorPenalty.h"
#include "VisualArmor.h"
#include "CliExt.h"
#include "ChatManager.h"
#include "DBNpcMaker.h"
#include "ClassManager.h"
#include "HtmlCache.h"
#include "Captcha.h"
#include "JailSystem.h"
#include "Antibot.h"
#include "OfflineBuffer.h"
#include "ChampionNpc.h"
#include "DonateSystem.h"
#include "DonateAugment.h"

#include "DropList.h"
#include "MultiSell.h"
#include "ReloadSkillData.h"
#include "VipSystem.h"
#include "AutoLearn.h"
#include "AutoLoot.h"
#include "CastleSiegeManager.h"
#include "CharacterLock.h"
#include "ClanPvPStatus.h"
#include "ClanReputationRank.h"
#include "ClanSys.h"
#include "CreatureAction.h"
#include "LureProtection.h"

#include "PvPEvents.h"
#include "DailyPvP.h"

#include "RatesDinamicos.h"
#include "Rebirth.h"

#include "AIO.h"

extern BOOL g_RecargaDeSkillsEnProceso;

typedef void (__fastcall *_VNS_INI) ();	//PARA RECARGARGAR EL L2SERVER.INI
_VNS_INI ReloadL2ServerINI = (_VNS_INI)0x004CD0F0L;

void CMenuExtension::Install()
{
	g_HookManager.WriteCall(0x63FB68, CMenuExtension::HandleCommand, 1);
	g_HookManager.WriteCall(0x64438E, ShowWindowHook, 1);
};

BOOL CMenuExtension::ShowWindowHook(HWND hWnd, int nCmdShow)
{
	HMENU hOriginalMenu = GetMenu(hWnd);	
	HMENU hExtMenu = CreateMenu();
	HMENU hExtMenu2 = CreateMenu();
	HMENU hExtMenu3 = CreateMenu();
	HMENU hExtMenu4 = CreateMenu();
	HMENU hExtMenu5 = CreateMenu();

	AppendMenu(hExtMenu, 0, KILL_DEATH_STAT_ID, _T("Switch Kill/Death Stats"));
	AppendMenu(hExtMenu, 0, RELOAD_ANTI_DDOS, _T("Reload AntiDDoS"));
	AppendMenu(hExtMenu, 0, RELOAD_ARMOR_PENALTY_ID, _T("Reload Armor Penalty"));
	AppendMenu(hExtMenu, 0, RELOAD_AUGMENTATION_ID, _T("Reload Augmentation"));
	AppendMenu(hExtMenu, 0, RELOAD_AUTO_ANNOUNCE, _T("Reload Auto Announce"));
	AppendMenu(hExtMenu, 0, RELOAD_BANLIST, _T("Reload BanList"));
	AppendMenu(hExtMenu, 0, RELOAD_CHAT_MANAGER, _T("Reload Chat Manager"));
	AppendMenu(hExtMenu, 0, RELOAD_CLASS_MANAGER, _T("Reload Class Manager"));
	AppendMenu(hExtMenu, 0, RELOAD_DB_NPC_MAKER, _T("Reload DB NpcMaker"));
	AppendMenu(hExtMenu, 0, RELOAD_ENCHANT_ID, _T("Reload Enchant Rates"));
	AppendMenu(hExtMenu, 0, RELOAD_ITEM_DATA_EX, _T("Reload ItemDataEx"));
	AppendMenu(hExtMenu, 0, RELOAD_ITEM_ENCHANT, _T("Reload Item Enchant Rates"));
	AppendMenu(hExtMenu, 0, RELOAD_HERBS_ID, _T("Reload Herb Data"));
	AppendMenu(hExtMenu, 0, RELOAD_MINING_DATA, _T("Reload MiningData"));
	AppendMenu(hExtMenu, 0, RELOAD_NPC_POS_EX, _T("Reload NpcPosEx"));
	AppendMenu(hExtMenu, 0, RELOAD_OBSCENE_FILTER, _T("Reload Obscene Filter"));
	AppendMenu(hExtMenu, 0, RELOAD_SCHEME_BUFFER, _T("Reload Scheme Buffer"));
	AppendMenu(hExtMenu, 0, RELOAD_SPIRIT_SYSTEM_ID, _T("Reload Spirit System"));
	AppendMenu(hExtMenu, 0, RELOAD_TELEPORT_DATA_ID, _T("Reload Teleport Data"));
	AppendMenu(hExtMenu, 0, RELOAD_TVT, _T("Reload TvT"));
	AppendMenu(hExtMenu, 0, RELOAD_TERRITORY_DATA_ID, _T("Reload Territory Data"));
	AppendMenu(hExtMenu, 0, RELOAD_VISUAL_ARMOR, _T("Reload VisualArmor Data"));
	AppendMenu(hExtMenu, 0, RELOAD_VOTE_SYSTEM, _T("Reload Vote System"));
	AppendMenu(hExtMenu, 0, RELOAD_CAPTCHA_SYSTEM, _T("Reload Captcha System"));
	AppendMenu(hExtMenu, 0, RELOAD_JAIL_SYSTEM, _T("Reload Jail System"));
	AppendMenu(hExtMenu, 0, RELOAD_ENTERWORLD_SYSTEM, _T("Reload Enterworld Html Option"));
	AppendMenu(hExtMenu, 0, RELOAD_FACTION_SYSTEM, _T("Reload Faction System"));
	AppendMenu(hExtMenu, 0, RELOAD_DONATE_SHOP, _T("Reload Donate Shop"));
	AppendMenu(hExtMenu, 0, RELOAD_OFFLINE_BUFFER, _T("Reload OfflineBuffer"));
	AppendMenu(hExtMenu, 0, RELOAD_CHAMPION_DATA, _T("Reload Champion NPC"));

	AppendMenu(hExtMenu2, 0, RELOAD_CLIEXT, _T("Reload CliExt"));
	AppendMenu(hExtMenu2, 0, RELOAD_BUILDER_LIST, _T("Reload Builder ID List"));
	AppendMenu(hExtMenu2, 0, RELOAD_BUILDERLEVELS_EX, _T("Reload BuilderCmd.txt"));


	



	AppendMenu(hExtMenu3, 0, RELOAD_ANTIBOT2, _T("Reload AntiBot"));
	AppendMenu(hExtMenu3, 0, RELOAD_VIPSYSTEM, _T("Reload Vip System"));
	AppendMenu(hExtMenu3, 0, RELOAD_AUCTION, _T("Reload Auction"));
	AppendMenu(hExtMenu3, 0, RELOAD_AUTOLOOT, _T("Reload AutoLoot"));
	AppendMenu(hExtMenu3, 0, RELOAD_CASTLESIEGEMANAGER, _T("Reload CastleSiegeManager"));
	AppendMenu(hExtMenu3, 0, RELOAD_CHARACTERLOCK, _T("Reload CharacterLock"));
	AppendMenu(hExtMenu3, 0, RELOAD_CLANPVPSTATUS, _T("Reload ClanPvPStatus"));
	AppendMenu(hExtMenu3, 0, RELOAD_AUTOLEARN, _T("Reload AutoLearn"));
	AppendMenu(hExtMenu3, 0, RELOAD_CLANREPUTATIONRANK, _T("Reload ClanReputationRank"));
	AppendMenu(hExtMenu3, 0, RELOAD_CLANSYSTEM, _T("Reload ClanSystem"));
	AppendMenu(hExtMenu3, 0, RELOAD_CCREATUREACTION, _T("Reload CreatureAction"));
	AppendMenu(hExtMenu3, 0, RELOAD_LURE_PROTECTION, _T("Reload Lure Protection"));
	AppendMenu(hExtMenu3, 0, RELOAD_AIO_SYSTEM, _T("Reload AIO System"));


	

	AppendMenu(hExtMenu3, 0, RELOAD_DAILY_PVP, _T("Reload Daily PVP"));



	AppendMenu(hExtMenu4, 0, RELOAD_CUSTOMS, _T("Reload Customs.ini"));
	AppendMenu(hExtMenu4, 0, RELOAD_L2SERVERINI, _T("Reload l2server.ini"));
	AppendMenu(hExtMenu4, 0, RELOAD_SKILLDATA, _T("Reload SkillData.txt"));
	AppendMenu(hExtMenu4, 0, RELOAD_DOORDATA, _T("Reload doordata.txt"));
	AppendMenu(hExtMenu4, 0, RELOAD_DECODATA, _T("Reload decodata.txt"));
	AppendMenu(hExtMenu4, 0, RELOAD_MULTISELL, _T("Reload Multisell"));
	AppendMenu(hExtMenu4, 0, RELOAD_DROPLIST, _T("Reload DropList"));
	AppendMenu(hExtMenu4, 0, RELOAD_PVP_EVENT, _T("Reload PvP Event"));
	AppendMenu(hExtMenu4, 0, RELOAD_DINAMIC_RATES, _T("Reload Dinamic Rates"));
	AppendMenu(hExtMenu4, 0, RELOAD_REBIRTH_SYSTEM, _T("Reload Rebirth System"));
	AppendMenu(hExtMenu4, 0, RELOAD_CHATMANAGER_SYSTEM, _T("Reload ChatManager"));
	AppendMenu(hExtMenu4, 0, RELOAD_SKILLDATA_EX, _T("Reload SkillDataEx.txt"));
	AppendMenu(hExtMenu4, 0, RELOAD_NPCDATA, _T("Reload npcdata.txt objects"));
	AppendMenu(hExtMenu4, 0, VERIFICAR_ESTRUCTURAS, _T("Verificar Estructuras"));


	


	InsertMenu(hOriginalMenu, -1, MF_BYPOSITION|MF_POPUP, (UINT_PTR)hExtMenu, _T("Extender"));	

	InsertMenu(hOriginalMenu, -1, MF_BYPOSITION|MF_POPUP, (UINT_PTR)hExtMenu2, _T("CliExt"));
	InsertMenu(hOriginalMenu, -1, MF_BYPOSITION|MF_POPUP, (UINT_PTR)hExtMenu3, _T("Otros"));
	InsertMenu(hOriginalMenu, -1, MF_BYPOSITION|MF_POPUP, (UINT_PTR)hExtMenu4, _T("Customs"));

	return ShowWindow(hWnd, nCmdShow);
};

LRESULT CALLBACK CMenuExtension::HandleCommand(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	if(message == WM_COMMAND)
	{
		switch (LOWORD(wParam)) 
		{ 
		case RELOAD_HERBS_ID:
			{
				g_Log.Add(CLog::Blue, "Reloading Herb Data...");
				g_HerbSystem.Init();
				return TRUE;
				break;
			}
		case RELOAD_ENCHANT_ID:
			{
				g_Log.Add(CLog::Blue, "Reloading Enchant Rates...");
				CItemEnchant::LoadINI();
				return TRUE;
				break;
			}
		case RELOAD_CLASS_MANAGER:
			{
				g_Log.Add(CLog::Blue, "Reloading Class Manager...");
				g_ClassManager.Init();
				return TRUE;
			}
		case RELOAD_SPIRIT_SYSTEM_ID:
			{
				g_Log.Add(CLog::Blue, "Reloading Spirit System...");
				g_Config.SpiritSystemInfo.Load();
				g_SpiritSystem.Initialize();
				return TRUE;
				break;
			}
		case RELOAD_CHAT_MANAGER:
			{
				g_ChatManager.SetReloadTimestamp(time(0) + 2);
				return TRUE;
			}
		case RELOAD_SCHEME_BUFFER:
			{
				g_Log.Add(CLog::Blue, "Reloading Scheme Buffer...");
				g_SchemeBuffer.RequestReload();
				return TRUE;
				break;
			}
		case RELOAD_ARMOR_PENALTY_ID:
			{
				g_Log.Add(CLog::Blue, "Reloading Armor Penalty System...");
				g_ArmorPenalty.Initialize();
				g_ArmorMasteryDB.ReadData();
				g_Log.Add(CLog::Blue, "Armor Penalty System has been reloaded.");
				return TRUE;
				break;
			}
		case RELOAD_DB_NPC_MAKER:
			{
				g_DBNpcMaker.Init();
				return TRUE;
			}
		case KILL_DEATH_STAT_ID:
			{
				bool IsSet = g_Config.IsSet(CConfig::KILL_DEATH_STAT);
				if(IsSet)
				{
					g_Log.Add(CLog::Blue, "Kill / Death Stats have been disabled.");
					g_Config.SetSystem(CConfig::KILL_DEATH_STAT, false);
				}else
				{
					g_Log.Add(CLog::Blue, "Kill / Death Stats have been enabled.");
					g_Config.SetSystem(CConfig::KILL_DEATH_STAT, true);
				}
				return TRUE;
				break;
			}
		case RELOAD_TERRITORY_DATA_ID:
			{
				g_TerritoryChecker.Initialize();
				return TRUE;
				break;
			}
		case RELOAD_AUGMENTATION_ID:
			{
				g_Config.AugmentationInfo.Load();
				g_Log.Add(CLog::Blue, "Augmentation - Reloaded chances from ini file.");
				g_Augmentation.ReadSkillData();
				g_Augmentation.ReadStatData();
				g_Augmentation.ReadNameData();
				return TRUE;
				break;
			}
		case RELOAD_ITEM_DATA_EX:
			{
				g_ItemDBEx.Init();
				return TRUE;
				break;
			}
		case RELOAD_BANLIST:
			{
				g_IpBlocker.ReadData();
				return TRUE;
				break;
			}
		case RELOAD_MINING_DATA:
			{
				g_MiningSystem.LoadData();
				return TRUE;
				break;
			}
		case RELOAD_NPC_POS_EX:
			{
				g_NpcMaker.SetRequestReload();
				return TRUE;
				break;
			}
		case RELOAD_TVT:
			{
				g_TvT.Init();
				return TRUE;
				break;
			}
		case RELOAD_ANTI_DDOS:
			{
				g_AntiDDoS.LoadINI();
				return TRUE;
				break;
			}
		case RELOAD_ITEM_ENCHANT:
			{
				CItemEnchant::LoadINI();
				g_Log.Add(CLog::Blue, "Item Enchant - Reloaded data from ini file.");
				return TRUE;
				break;
			}
		case RELOAD_BUILDER_LIST:
			{
				CBuilderCommand::LoadBuilderList();
				g_Log.Add(CLog::Blue, "Reloaded builder list.");
				return TRUE;
				break;
			}
		case RELOAD_TELEPORT_DATA_ID:
			{
				g_TeleportBypass.Init();
				return TRUE;
				break;
			}
		case RELOAD_VOTE_SYSTEM:
			{
				g_VoteSystem.Init();
				return TRUE;
				break;
			}
		case RELOAD_AUTO_ANNOUNCE:
			{
				g_AutoAnnounce.SetReload();
				return TRUE;
				break;
			}
		case RELOAD_OBSCENE_FILTER:
			{
				g_ObsceneFilter.RequestReload();
				return TRUE;
				break;
			}
		case RELOAD_VISUAL_ARMOR:
			{
				g_VisualArmor.RequestReload();
				return TRUE;
			}
		case RELOAD_CAPTCHA_SYSTEM:
			{
				g_Captcha.LoadINI();
				g_Log.Add(CLog::Blue, "Captcha System - Reloaded config from ini file.");
				return TRUE;
				break;
			}
		case RELOAD_JAIL_SYSTEM:
			{
				g_Jail.LoadINI();
				g_Log.Add(CLog::Blue, "Jail System - Reloaded config from ini file.");
				return TRUE;
				break;
			}
		case RELOAD_ENTERWORLD_SYSTEM:
			{
				L2Ext::ReloadEnterworldHtml();
				g_Log.Add(CLog::Blue, "Enterworld Html System has been reloaded.");
				return TRUE;
				break;
			}
		case RELOAD_FACTION_SYSTEM:
			{
				g_FactionSystem.Init();
				g_Log.Add(CLog::Blue, "Faction System Options Reloaded.");
				return TRUE;
				break;
			}
		case RELOAD_ANTIBOT2:
			{
				g_Antibot.Init();
				return TRUE;
				break;
			}
		case RELOAD_OFFLINE_BUFFER:
			{
				g_OfflineBuffer.Initialize();
				return TRUE;
				break;
			}
		case RELOAD_CHAMPION_DATA:
			{
				g_ChampionNpc.Init();
				return TRUE;
				break;
			}
		case RELOAD_DONATE_SHOP:
			{
				g_DonateSystem.Init();
				g_DonateSystemAugment.Init();
				return TRUE;
				break;
			}
		case RELOAD_CUSTOMS:
			{
				NuevasFunciones::LoadINI();
				g_Log.Add(CLog::Error, "Configuraciones Customs.ini recargadas!");
				return TRUE;
				break;
			}
		case RELOAD_L2SERVERINI:
			{
				ReloadL2ServerINI();
				g_Log.Add(CLog::Blue, "Reload l2server.ini");
				return TRUE;
				break;
			}
		case RELOAD_MULTISELL:
			{
				void* pMultisell = (void*)0x7D55278;


				typedef void (*f)(void*);
				f(0x9576A0)(pMultisell);	//destructor


				typedef void (*f)(void*);
				f(0x692F60)(pMultisell);	//load multisell

				g_MultiSellDB.Init();

				return TRUE;
			}
		case RELOAD_DROPLIST:
			{
				ReloadL2ServerINI();
				g_Log.Add(CLog::Blue, "Reload l2server.ini");

				g_DropList.Init();
				return TRUE;
			}
		case RELOAD_VIPSYSTEM:
			{
				g_VIPSystem.LoadINI();
				g_Log.Add(CLog::Blue, "VipSystem reloaded.");
				return TRUE;
			}
		case RELOAD_SKILLDATA:
			{
				g_RecargaDeSkillsEnProceso =true;
				g_HookManager.WriteMemoryBYTES(0x0079A779, "90 90 90 90 90");

				typedef void (*f)();
				f(0x95FE40)();	//destructor skilldata

				//--------------------------------------------------------------------
				void* g_CPrecompiledHeaderDB = (void*)0xE2858B0;
				typedef void (*z)(void*, WCHAR*, FILE*);
				z(0x9576A0)(&g_CPrecompiledHeaderDB, L"..\\script\\", 0);	//CPrecompiledHeaderDB::Load
				//--------------------------------------------------------------------

				ReloadSkillData::ReloadSkills(999999);

				typedef void (*f)();
				f(0x79BDA0)();	//load skilldata

				g_HookManager.WriteMemoryBYTES(0x79A779, "E8 E2 34 EB FF");




				void* pMultisell = (void*)0x7D55278;

				typedef void (*y)(void*);
				y(0x9576A0)(pMultisell);	//destructor

				typedef void (*y)(void*);
				y(0x692F60)(pMultisell);	//load multisell

				g_MultiSellDB.Init();


				g_Log.Add(CLog::Blue, "pch's.txt fueron recargados");
				g_Log.Add(CLog::Blue, "skilldata.txt fue recargado");

				g_RecargaDeSkillsEnProceso = false;
//				DWORD* offset = (*(LPDWORD*)0xE4172D0);
//				std::map<CSkillKey,CSkillInfo *>* m_mapSkills = (std::map<CSkillKey,CSkillInfo *>*)offset;

//				g_Log.Add(CLog::Error, "OFFSET [%x]", m_mapSkills);
//				m_mapSkills->clear();

				return TRUE;
			}
		case RELOAD_DOORDATA:
			{
				void* pDoorData = (void*)0x155E250;

				typedef void (*f)();
				f(0x950950)();	//destructor doordata

				ReloadSkillData::ReloadSkills(999999);


				typedef void (*g)(void*);
				g(0x59CB90)(pDoorData);	//load multisell

				g_Log.Add(CLog::Blue, "doordata.txt fue recargado");

				return TRUE;
			}
		case RELOAD_NPCDATA:
			{
				void* pCObjectDB = (void*)0xBC5D810;

				typedef void (*f)();
				f(0x95E3C0)();	//destructor CObjectDB

				ReloadSkillData::ReloadSkills(999999);


				int* direccion_memoria = reinterpret_cast<int*>(0xBC5D7EC);
				*direccion_memoria = 0;


				typedef void (*g)(void*);
				g(0x6FA0C0)(pCObjectDB);	//CObjectDB::LoadNPC(&g_CObjectDB);

				g_Log.Add(CLog::Blue, "npcdata.txt fue recargado");

		
				return TRUE;
			}


		case RELOAD_DECODATA:
			{
				void* pDecoData = (void*)0xC019E0;

				typedef void (*f)();
				f(0x941400)();	//destructor CAgitDecoDb

				ReloadSkillData::ReloadSkills(999999);

				typedef void (*g)(void*);
				g(0x40FE00)(pDecoData);	//CAgitDecoDb::Load

				g_Log.Add(CLog::Blue, "decodata.txt fue recargado");

				return TRUE;
			}
		case RELOAD_AUCTION:
			{
				g_Auction.LoadINI();

				g_Log.Add(CLog::Blue, "Auction Recargado");

				return TRUE;
			}
		case RELOAD_AUTOLEARN:
			{
				CAutoLearn::Initialize();

				g_Log.Add(CLog::Blue, "AutoLearn Recargado");

				return TRUE;
			}
		case RELOAD_AUTOLOOT:
			{
				g_AutoLoot.Init();;

				g_Log.Add(CLog::Blue, "AutoLoot Recargado");

				return TRUE;
			}
		case RELOAD_CASTLESIEGEMANAGER:
			{
				g_CastleSiegeManager.m_EnReload=true;
				g_CastleSiegeManager.Init();;


				g_Log.Add(CLog::Blue, "CastleSiegeManager Recargado");

				return TRUE;
			}
		case RELOAD_CHARACTERLOCK:
			{
				g_CharacterLock.Init();;

				g_Log.Add(CLog::Blue, "CharacterLock Recargado");

				return TRUE;
			}
		case RELOAD_CLANPVPSTATUS:
			{
				g_ClanPvPStatus.LoadINI();;

				g_Log.Add(CLog::Blue, "ClanPvPStatus Recargado");

				return TRUE;
			}
		case RELOAD_CLANREPUTATIONRANK:
			{
				g_ClanReputationRank.LoadINI();;

				g_Log.Add(CLog::Blue, "ClanReputationRank Recargado");

				return TRUE;
			}
		case RELOAD_CLANSYSTEM:
			{
				//g_PledgeSkillDb.Initialize();
				ClanSys::Initialize();

				g_Log.Add(CLog::Blue, "ClanSystem Recargado");

				return TRUE;
			}
		case RELOAD_CCREATUREACTION:
			{
				CreatureAction::LoadINI();

				g_Log.Add(CLog::Blue, "CreatureAction Recargado");

				return TRUE;
			}
		case RELOAD_CLIEXT:
			{
				g_CliExt.LoadINI();
				g_Log.Add(CLog::Blue, "CliExt config Recargado");

				return TRUE;
			}
		case RELOAD_LURE_PROTECTION:
			{
				g_LureProtection.Init();
				g_Log.Add(CLog::Blue, "Lure Protection Recargado");

				return TRUE;
			}
		case RELOAD_PVP_EVENT:
			{
				g_PvPEvents.LoadINI();
				g_Log.Add(CLog::Blue, "Event PvP Recargado");

				return TRUE;
			}
		case RELOAD_DAILY_PVP:
			{
				g_DailyPvP.LoadINI();
				g_Log.Add(CLog::Blue, "Daily PvP Recargado");

				return TRUE;
			}
		case RELOAD_DINAMIC_RATES:
			{
				g_RatesDinamicos.Init();
				g_Log.Add(CLog::Blue, "RatesDinamicos Recargado");

				return TRUE;
			}
		case RELOAD_REBIRTH_SYSTEM:
			{
				g_RebirthSystem.Init();
				g_Log.Add(CLog::Blue, "CRebirthSystem Recargado");

				return TRUE;
			}
		case RELOAD_CHATMANAGER_SYSTEM:
			{
				g_ChatManager.Init();
				g_Log.Add(CLog::Blue, "ChatManager Recargado");

				return TRUE;
			}
		case RELOAD_SKILLDATA_EX:
			{
				g_SkillDBEx.Initialize();
				g_Log.Add(CLog::Blue, "SkillDBEx Recargado");

				return TRUE;
			}
		case RELOAD_BUILDERLEVELS_EX:
			{
				CBuilderCommand::LoadData();
				g_Log.Add(CLog::Blue, "CBuilderCommand Level Recargado");

				return TRUE;
			}
		case VERIFICAR_ESTRUCTURAS:
			{
				NuevasFunciones::VerificarEstructuras();
				return TRUE;
			}
		case RELOAD_AIO_SYSTEM:
			{
				g_AIOSystem.Init();
				return TRUE;
			}

		}






	}
	return DefWindowProc(hWnd, message, wParam, lParam);
}