#include "StdAfx.h"


ChangeFolders g_ChangeFolders;

TCHAR  m_ConfigsIlExt[260];

void ChangeFolders::Init()
{
	LoadInI();

	lstrcat(m_ConfigsIlExt, L"");

	if(m_Enabled)
	{
		SetearRutasL2Server();
		SetearRutasExtender();
	}
}

void ChangeFolders::LoadInI()
{
	GetCurrentDirectory(MAX_PATH, l2server_ini);
	lstrcat(g_CustomConfigFile, _T("\\l2server.ini"));

	m_Enabled = GetPrivateProfileInt(_T("FOLDERS_CUSTOM"), _T("Enabled"), 0, l2server_ini);


	GetPrivateProfileStringW(_T("FOLDERS_CUSTOM"), _T("Script"),L"",m_Script, 260, l2server_ini);
	GetPrivateProfileStringW(_T("FOLDERS_CUSTOM"), _T("Html"),L"",m_Html, 260, l2server_ini);
	GetPrivateProfileStringW(_T("FOLDERS_CUSTOM"), _T("GeoData"),L"",m_GeoData, 260, l2server_ini);

	GetPrivateProfileStringW(_T("FOLDERS_CUSTOM"), _T("ConfigsIlExt"),L"",m_ConfigsIlExt, 260, l2server_ini);



	lstrcat(m_Html_cache, L"..\\html\\");

	lstrcat(m_Html, L"%s");

	
	

	_UnicodeToAnsi(m_Script, m_Script_Ansi);


augmentation_name_txt = L"..\\Script\\augmentation_name.txt";
MiningData_txt =		L"..\\Script\\MiningData.txt";
MultiSell_txt = 		L"..\\Script\\MultiSell.txt";
Skill_Pch_txt = 		L"..\\Script\\Skill_Pch.txt";
SkillAcquire_txt =		L"..\\Script\\SkillAcquire.txt";
SkillData_txt =			L"..\\Script\\SkillData.txt";
Setting_txt =			L"..\\Script\\Setting.txt";
item_pch_txt =			L"..\\Script\\item_pch.txt";
ItemsNotDropped_txt =	L"..\\Script\\ItemsNotDropped.txt";


ItemsDroppedAIMultiplier_txt =	L"..\\Script\\ItemsDroppedAIMultiplier.txt";
ItemAutoConsume_txt =	L"..\\Script\\ItemAutoConsume.txt";	
AIOData_txt =			L"..\\Script\\AIOData.txt";	
BuilderCmd_txt =		L"..\\Script\\BuilderCmd.txt";
PledgeSkillAcquire_txt =L"..\\Script\\PledgeSkillAcquire.txt";	
ItemGrp_txt =			L"..\\Script\\ItemGrp.txt";
ItemName_txt =			L"..\\Script\\ItemName.txt";
CLogFilter_txt =		L"..\\script\\CLogFilter.txt";
ObsceneFilter_txt =		L"..\\Script\\ObsceneFilter.txt";
SkillName_txt =			L"..\\Script\\SkillName.txt";
SkillGrp_txt =			L"..\\Script\\SkillGrp.txt";
VisualArmor_txt =		L"..\\Script\\VisualArmor.txt";
SchemeBuffer_txt =		L"..\\Script\\SchemeBuffer.txt";
NpcName_txt =			L"..\\Script\\NpcName.txt";
NpcName2_txt =			L"..\\Script\\NpcName2.txt";
ItemData_txt =			L"..\\Script\\ItemData.txt";
NpcData_txt =			L"..\\Script\\NpcData.txt";
HerbData_txt =			L"..\\Script\\HerbData.txt";
DoorData_txt =			L"..\\Script\\DoorData.txt";
ClassName_txt =			L"..\\Script\\ClassName.txt";	
SkillMaster_txt =		L"..\\Script\\SkillMaster.txt";
OlympiadSupport_txt =	L"..\\Script\\OlympiadSupport.txt";
Recipe_txt =			L"..\\Script\\Recipe.txt";


//g_ChangeFolders.EnchantedSetData_txt
SkillDataEx_txt =		"..\\Script\\SkillDataEx.txt";
TeleportData_txt =		"..\\Script\\TeleportData.txt";
CastleDataEx_txt =		"..\\Script\\CastleDataEx.txt";
NpcPosEx_txt =			"..\\Script\\NpcPosEx.txt";
DonateAugmentList_txt =	"..\\Script\\DonateAugmentList.txt";
DonateList_txt =		"..\\Script\\DonateList.txt";
ItemDataEx_txt =		"..\\Script\\ItemDataEx.txt";
ArmorPenaltyData_txt =	"..\\Script\\ArmorPenaltyData.txt";
augmentation_skill_txt ="..\\Script\\augmentation_skill.txt";
augmentation_stat_txt =	"..\\Script\\augmentation_stat.txt";
NpcChampionData_txt =	"..\\Script\\NpcChampionData.txt";
NpcReputationData_txt =	"..\\Script\\NpcReputationData.txt";	
TerritoryData_txt =		"..\\Script\\TerritoryData.txt";
EnchantedSetData_txt =	"..\\Script\\EnchantedSetData.txt";



}

void ChangeFolders::SetearRutasExtender()
{

	lstrcat(m_Html_cache, m_Html);

	{
		std::wstringstream wss;
		wss << m_Script << L"augmentation_name.txt";
		augmentation_name_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"MiningData.txt";
		MiningData_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"MultiSell.txt";
		MultiSell_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"Skill_Pch.txt";
		Skill_Pch_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"SkillAcquire.txt";
		SkillAcquire_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"SkillData.txt";
		SkillData_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"Setting.txt";
		Setting_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"item_pch.txt";
		item_pch_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"ItemsNotDropped.txt";
		ItemsNotDropped_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"ItemsDroppedAIMultiplier.txt";
		ItemsDroppedAIMultiplier_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"ItemAutoConsume.txt";
		ItemAutoConsume_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"AIOData.txt";
		AIOData_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"BuilderCmd.txt";
		BuilderCmd_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"PledgeSkillAcquire.txt";
		PledgeSkillAcquire_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"ItemGrp.txt";
		ItemGrp_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"ItemName.txt";
		ItemName_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"CLogFilter.txt";
		CLogFilter_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"ObsceneFilter.txt";
		ObsceneFilter_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"SkillName.txt";
		SkillName_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"SkillGrp.txt";
		SkillGrp_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"VisualArmor.txt";
		VisualArmor_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"SchemeBuffer.txt";
		SchemeBuffer_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"NpcName.txt";
		NpcName_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"NpcName2.txt";
		NpcName2_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"NpcData.txt";
		NpcData_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"ItemData.txt";
		ItemData_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"HerbData.txt";
		HerbData_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"DoorData.txt";
		DoorData_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"ClassName.txt";
		ClassName_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"SkillMaster.txt";
		SkillMaster_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"OlympiadSupport.txt";
		OlympiadSupport_txt = wss.str();
	}

	{
		std::wstringstream wss;
		wss << m_Script << L"Recipe.txt";
		Recipe_txt = wss.str();
	}
	//---------------string
	{
		std::stringstream wss;
		wss << m_Script_Ansi << "SkillDataEx.txt";
		SkillDataEx_txt = wss.str();
	}
	{
		std::stringstream wss;
		wss << m_Script_Ansi << "TeleportData.txt";
		TeleportData_txt = wss.str();
	}
	{
		std::stringstream wss;
		wss << m_Script_Ansi << "CastleDataEx.txt";
		CastleDataEx_txt = wss.str();
	}
	{
		std::stringstream wss;
		wss << m_Script_Ansi << "NpcPosEx.txt";
		NpcPosEx_txt = wss.str();
	}
	{
		std::stringstream wss;
		wss << m_Script_Ansi << "DonateAugmentList.txt";
		DonateAugmentList_txt = wss.str();
	}
	{
		std::stringstream wss;
		wss << m_Script_Ansi << L"DonateList.txt";
		DonateList_txt = wss.str();
	}
	{
		std::stringstream wss;
		wss << m_Script_Ansi << "ItemDataEx.txt";
		ItemDataEx_txt = wss.str();
	}
	{
		std::stringstream wss;
		wss << m_Script_Ansi << "ArmorPenaltyData.txt";
		ArmorPenaltyData_txt = wss.str();
	}
	{
		std::stringstream wss;
		wss << m_Script_Ansi << "augmentation_skill.txt";
		augmentation_skill_txt = wss.str();
	}
	{
		std::stringstream wss;
		wss << m_Script_Ansi << "augmentation_stat.txt";
		augmentation_stat_txt = wss.str();
	}

	{
		std::stringstream wss;
		wss << m_Script_Ansi << "NpcChampionData.txt";
		NpcChampionData_txt = wss.str();
	}
	{
		std::stringstream wss;
		wss << m_Script_Ansi << "NpcReputationData.txt";
		NpcReputationData_txt = wss.str();
	}
	{

		std::stringstream wss;
		wss << m_Script_Ansi << "TerritoryData.txt";
		TerritoryData_txt = wss.str();
	}
	{
		std::stringstream wss;
		wss << m_Script_Ansi << "EnchantedSetData.txt";
		EnchantedSetData_txt = wss.str();
	}
}

void ChangeFolders::SetearRutasL2Server()
{

	//GEODATA
	lstrcat(w_map_bug, m_GeoData);
	lstrcat(w_BadGeoData, m_GeoData);
	lstrcat(w_geo_index, m_GeoData);
	lstrcat(w_pathnode_bin, m_GeoData);
	lstrcat(w_pathnode_idx, m_GeoData);

	lstrcat(w_map_bug, L"%02d_%02d_bug.txt");
	lstrcat(w_BadGeoData, L"BadGeoData.txt");
	lstrcat(w_geo_index, L"geo_index.txt");
	lstrcat(w_pathnode_bin, L"pathnode.bin");
	lstrcat(w_pathnode_idx, L"pathnode.idx");


	//SCRIPT

	lstrcat(w_decodata_File, m_Script);
	lstrcat(w_AreaData_File, m_Script);
	lstrcat(w_BuilderCmdAlias_File, m_Script);
	lstrcat(w_categorydata_File, m_Script);
	lstrcat(w_doordata_File, m_Script);
	lstrcat(w_fishingdata_File, m_Script);
	lstrcat(w_eventdata_File, m_Script);
	lstrcat(w_Dyedata_File, m_Script);
	lstrcat(w_quest_pch2_File, m_Script);
	lstrcat(w_petdata_File, m_Script);
	lstrcat(w_manordata_File, m_Script);
	lstrcat(w_monrace_File, m_Script);
	lstrcat(w_MultiSell_File, m_Script);
	lstrcat(w_itemdata_File, m_Script);
	lstrcat(w_PC_Parameter_File, m_Script);
	lstrcat(w_PetitionCategory_File, m_Script);
	lstrcat(w_recipe_File, m_Script);
	lstrcat(w_castledata_File, m_Script);
	lstrcat(w_setting_File, m_Script);
	lstrcat(w_skilldata_File, m_Script);
	lstrcat(w_SkillAcquire_File, m_Script);
	lstrcat(w_skillenchantdata_File, m_Script);
	lstrcat(w_vehicledata_File, m_Script);
	lstrcat(w_watch_list_File, m_Script);
	lstrcat(w_npcdata_File, m_Script);
	//---------------------------------------------------------
	lstrcat(w_decodata_File, L"decodata.txt");
	lstrcat(w_AreaData_File, L"AreaData.txt");
	lstrcat(w_BuilderCmdAlias_File, L"BuilderCmdAlias.txt");
	lstrcat(w_categorydata_File, L"categorydata.txt");
	lstrcat(w_doordata_File, L"doordata.txt");
	lstrcat(w_fishingdata_File, L"fishingdata.txt");
	lstrcat(w_eventdata_File, L"eventdata.ini");
	lstrcat(w_Dyedata_File, L"Dyedata.txt");
	lstrcat(w_quest_pch2_File, L"quest_pch2.txt");
	lstrcat(w_petdata_File, L"petdata.txt");
	lstrcat(w_manordata_File, L"manordata.txt");
	lstrcat(w_monrace_File, L"monrace.txt");
	lstrcat(w_MultiSell_File, L"MultiSell.txt");
	lstrcat(w_itemdata_File, L"itemdata.txt");
	lstrcat(w_PC_Parameter_File, L"PC_Parameter.txt");
	lstrcat(w_PetitionCategory_File, L"PetitionCategory.txt");
	lstrcat(w_recipe_File, L"recipe.txt");
	lstrcat(w_castledata_File, L"castledata.txt");
	lstrcat(w_setting_File, L"setting.txt");
	lstrcat(w_skilldata_File, L"skilldata.txt");
	lstrcat(w_SkillAcquire_File, L"SkillAcquire.txt");
	lstrcat(w_skillenchantdata_File, L"skillenchantdata.txt");
	lstrcat(w_vehicledata_File, L"vehicledata.txt");
	lstrcat(w_watch_list_File, L"watch_list.txt");
	lstrcat(w_npcdata_File, L"npcdata.txt");



//TO ANSI

	_UnicodeToAnsi(w_pathnode_idx,w_pathnode_idx_Ansi);

	_UnicodeToAnsi(w_decodata_File, w_decodata_File_Ansi);
	_UnicodeToAnsi(w_AreaData_File, w_AreaData_File_Ansi);
	_UnicodeToAnsi(w_BuilderCmdAlias_File, w_BuilderCmdAlias_File_Ansi);
	_UnicodeToAnsi(w_categorydata_File, w_categorydata_File_Ansi);
	_UnicodeToAnsi(w_doordata_File, w_doordata_File_Ansi);
	_UnicodeToAnsi(w_fishingdata_File, w_fishingdata_File_Ansi);
	_UnicodeToAnsi(w_eventdata_File, w_eventdata_File_Ansi);
	_UnicodeToAnsi(w_Dyedata_File, w_Dyedata_File_Ansi);
	_UnicodeToAnsi(w_quest_pch2_File, w_quest_pch2_File_Ansi);
	_UnicodeToAnsi(w_petdata_File, w_petdata_File_Ansi);
	_UnicodeToAnsi(w_manordata_File, w_manordata_File_Ansi);
	_UnicodeToAnsi(w_monrace_File, w_monrace_File_Ansi);
	_UnicodeToAnsi(w_MultiSell_File, w_MultiSell_File_Ansi);
	_UnicodeToAnsi(w_itemdata_File, w_itemdata_File_Ansi);
	_UnicodeToAnsi(w_PC_Parameter_File, w_PC_Parameter_File_Ansi);
	_UnicodeToAnsi(w_PetitionCategory_File, w_PetitionCategory_File_Ansi);
	_UnicodeToAnsi(w_recipe_File, w_recipe_File_Ansi);
	_UnicodeToAnsi(w_castledata_File, w_castledata_File_Ansi);
	_UnicodeToAnsi(w_setting_File, w_setting_File_Ansi);
	_UnicodeToAnsi(w_skilldata_File, w_skilldata_File_Ansi);
	_UnicodeToAnsi(w_SkillAcquire_File, w_SkillAcquire_File_Ansi);
	_UnicodeToAnsi(w_skillenchantdata_File, w_skillenchantdata_File_Ansi);
	_UnicodeToAnsi(w_vehicledata_File, w_vehicledata_File_Ansi);
	_UnicodeToAnsi(w_watch_list_File, w_watch_list_File_Ansi);
	_UnicodeToAnsi(w_npcdata_File, w_npcdata_File_Ansi);


	_UnicodeToAnsi(w_geo_index, w_geo_index_Ansi);
	_UnicodeToAnsi(w_map_bug, w_map_bug_Ansi);



	//HTML
	g_HookManager.WriteRelativeAddress(0x4AF145, 3, &m_Script,0);						//                 lea     rdx, pszBaseDir 		; "..\\script\\"
	g_HookManager.WriteRelativeAddress(0x5F6A1B, 3, &m_Html,0);						//                 lea     rdx, aHtmlS			; "..\\HTML\\%s"
	g_HookManager.WriteRelativeAddress(0x5F7573, 3, &m_Html,0);						//                 lea     r8, aHtmlS_0			; "..\\html\\%s"



	g_HookManager.WriteRelativeAddress(0x5D6345, 3, &w_geo_index_Ansi,0);						//                 lea     rdx, aGeodataGeoInde ; "..\\GeoData\\geo_index.txt"
	g_HookManager.WriteRelativeAddress(0x667E85, 3, &w_map_bug_Ansi,0);						//                 lea     rdx, aGeodata02d02dB ; "..\\GeoData\\%02d_%02d_bug.txt"
	g_HookManager.WriteRelativeAddress(0x73FF22, 3, &w_pathnode_idx_Ansi,0);						//                 lea     rdx, aGeodataPathnod ; "..\\geodata\\pathnode.idx"

	g_HookManager.WriteRelativeAddress(0x5D63A2, 3, &m_GeoData,0);						//                 lea     r8, aGeodata    ; "..\\GeoData\\"

	g_HookManager.WriteRelativeAddress(0x5D6895, 3, &w_BadGeoData,0);						//                 lea     rdx, aGeodataBadgeod ; "..\\GeoData\\BadGeoData.txt"
	
	g_HookManager.WriteRelativeAddress(0x73FF9D, 3, &w_pathnode_bin,0);						//                 lea     rcx, aGeodataPathnod_0 ; "..\\geodata\\pathnode.bin"




	g_HookManager.WriteRelativeAddress(0x6FC10C, 3, &w_itemdata_File_Ansi,0);				//                 lea     rdx, aScriptItemdata ; "..\\Script\\itemdata.txt"
	g_HookManager.WriteRelativeAddress(0x79BE44, 3, &w_skilldata_File_Ansi,0);				//                 lea     rdx, aScriptSkilldat ; "..\\Script\\skilldata.txt"
	g_HookManager.WriteRelativeAddress(0x49BF37, 3, &w_BuilderCmdAlias_File_Ansi,0);		//                 lea     rdx, aScriptBuilderc ; "..\\Script\\BuilderCmdAlias.txt"
	g_HookManager.WriteRelativeAddress(0x7459C5, 3, &w_PC_Parameter_File_Ansi,0);			//                 lea     rdx, aScriptPcParame ; "..\\Script\\PC_Parameter.txt"

	g_HookManager.WriteRelativeAddress(0x79D082, 3, &w_SkillAcquire_File_Ansi,0);			//                 lea     rdx, aScriptSkillacq ; "..\\Script\\SkillAcquire.txt"
	g_HookManager.WriteRelativeAddress(0x7A23CC, 3, &w_skillenchantdata_File_Ansi,0);		//                 lea     rdx, aScriptSkillenc ; "..\\Script\\skillenchantdata.txt"
	g_HookManager.WriteRelativeAddress(0x428412, 3, &w_AreaData_File_Ansi,0);				//                 lea     rdx, aScriptAreadata ; "..\\Script\\AreaData.txt"
	g_HookManager.WriteRelativeAddress(0x693004, 3, &w_MultiSell_File_Ansi,0);				//                 lea     rdx, aScriptMultisel ; "..\\Script\\MultiSell.txt"
	g_HookManager.WriteRelativeAddress(0x40FEA4, 3, &w_decodata_File_Ansi,0);				//                 lea     rdx, aScriptDecodata ; "..\\Script\\decodata.txt"
	g_HookManager.WriteRelativeAddress(0x5C2144, 3, &w_fishingdata_File_Ansi,0);			//                 lea     rdx, aScriptFishingd ; "..\\Script\\fishingdata.txt"
	g_HookManager.WriteRelativeAddress(0x774474, 3, &w_recipe_File_Ansi,0);				//                 lea     rdx, aScriptRecipeTx ; "..\\Script\\recipe.txt"
	g_HookManager.WriteRelativeAddress(0x66405C, 3, &w_manordata_File_Ansi,0);				//                 lea     rdx, aScriptManordat ; "..\\Script\\manordata.txt"
	g_HookManager.WriteRelativeAddress(0x59CC3C, 3, &w_doordata_File_Ansi,0);				//                 lea     rdx, aScriptDoordata ; "..\\Script\\doordata.txt"
	g_HookManager.WriteRelativeAddress(0x4AF16A, 3, &w_categorydata_File_Ansi,0);			//                 lea     rdx, aScriptCategory ; "..\\Script\\categorydata.txt"
	g_HookManager.WriteRelativeAddress(0x786FAC, 3, &w_setting_File_Ansi,0);				//                 lea     rdx, aScriptSettingT ; "..\\Script\\setting.txt"
	g_HookManager.WriteRelativeAddress(0x5D7D24, 3, &w_Dyedata_File_Ansi,0);				//                 lea     rdx, aScriptDyedataT ; "..\\Script\\Dyedata.txt"
	g_HookManager.WriteRelativeAddress(0x7803D4, 3, &w_castledata_File_Ansi,0);			//                 lea     rdx, aScriptCastleda ; "..\\Script\\castledata.txt"




	g_HookManager.WriteRelativeAddress(0x5C90F9, 3, &w_eventdata_File,0);				//                 lea     r14, FileName   	  ; "..\\Script\\eventdata.ini"
	g_HookManager.WriteRelativeAddress(0x5CA129, 3, &w_eventdata_File,0);				//                 lea     rcx, FileName   	  ; "..\\Script\\eventdata.ini"
	g_HookManager.WriteRelativeAddress(0x5CA186, 3, &w_eventdata_File,0);				//                 lea     r9, FileName    	  ; "..\\Script\\eventdata.ini"
	g_HookManager.WriteRelativeAddress(0x5CA1BB, 3, &w_eventdata_File,0);				//                 lea     r15, FileName   	  ; "..\\Script\\eventdata.ini"
	

	g_HookManager.WriteRelativeAddress(0x6362C7, 3, &w_quest_pch2_File,0);			//                 lea     rdx, aScriptQuestPch ; "..\\script\\quest_pch2.txt"
	g_HookManager.WriteRelativeAddress(0x6430CC, 3, &w_petdata_File,0);				//                 lea     rdx, aScriptPetdataT ; "..\\Script\\petdata.txt"
	g_HookManager.WriteRelativeAddress(0x679CC1, 3, &w_monrace_File,0);				//                 lea     rdx, aScriptMonraceT ; "..\\script\\monrace.txt"
	g_HookManager.WriteRelativeAddress(0x679CE9, 3, &w_monrace_File,0);				//                 lea     rcx, aScriptMonraceT ; "..\\script\\monrace.txt"
	g_HookManager.WriteRelativeAddress(0x756151, 3, &w_PetitionCategory_File,0);		//                 lea     rdx, aScriptPetition ; "..\\Script\\PetitionCategory.txt"
	g_HookManager.WriteRelativeAddress(0x75616C, 3, &w_PetitionCategory_File,0);		//                 lea     r9, aScriptPetition  ; "..\\Script\\PetitionCategory.txt"
	g_HookManager.WriteRelativeAddress(0x89E41D, 3, &w_vehicledata_File,0);			//                 lea     rdx, aScriptVehicled ; "..\\Script\\vehicledata.txt"
	g_HookManager.WriteRelativeAddress(0x8ADA9B, 3, &w_watch_list_File,0);			//                 lea     rdx, aScriptWatchLis ; "..\\Script\\watch_list.txt"
	g_HookManager.WriteRelativeAddress(0x8D672B, 3, &w_npcdata_File,0);				//                 lea     rcx, aScriptNpcdataT ; "..\\Script\\npcdata.txt"
	g_HookManager.WriteRelativeAddress(0x8D8BA9, 3, &w_itemdata_File,0);				//                 lea     rcx, aScriptItemdata ; "..\\Script\\itemdata.txt"
	g_HookManager.WriteRelativeAddress(0x8DC7AB, 3, &w_skilldata_File,0);				//                 lea     rcx, aScriptSkilldat ; "..\\Script\\skilldata.txt"
	g_HookManager.WriteRelativeAddress(0x8DCF6B, 3, &w_manordata_File,0);				//                 lea     rcx, aScriptManordat ; "..\\Script\\manordata.txt"
	g_HookManager.WriteRelativeAddress(0x8FF56B, 3, &w_PC_Parameter_File,0);			//                 lea     rcx, aScriptPcParame ; "..\\Script\\pc_parameter.txt"
}