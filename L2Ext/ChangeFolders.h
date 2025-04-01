#pragma once

class ChangeFolders
{
public:
	bool m_Enabled;


CHAR   m_Script_Ansi[260];

TCHAR   m_Script[260];
TCHAR   m_Html[260];
TCHAR   m_GeoData[260];

TCHAR   m_Html_cache[260];

TCHAR   w_map_bug[260];
TCHAR   w_BadGeoData[260];
TCHAR   w_geo_index[260];
TCHAR   w_pathnode_bin[260];
TCHAR   w_pathnode_idx[260];

CHAR   w_pathnode_idx_Ansi[260];

TCHAR   w_decodata_File[260];
TCHAR   w_AreaData_File[260];
TCHAR   w_BuilderCmdAlias_File[260];
TCHAR   w_categorydata_File[260];
TCHAR   w_doordata_File[260];
TCHAR   w_fishingdata_File[260];
TCHAR   w_eventdata_File[260];
TCHAR   w_Dyedata_File[260];
TCHAR   w_quest_pch2_File[260];
TCHAR   w_petdata_File[260];
TCHAR   w_manordata_File[260];
TCHAR   w_monrace_File[260];
TCHAR   w_MultiSell_File[260];
TCHAR   w_itemdata_File[260];
TCHAR   w_PC_Parameter_File[260];
TCHAR   w_PetitionCategory_File[260];
TCHAR   w_recipe_File[260];
TCHAR   w_castledata_File[260];
TCHAR   w_setting_File[260];
TCHAR   w_skilldata_File[260];
TCHAR   w_SkillAcquire_File[260];
TCHAR   w_skillenchantdata_File[260];
TCHAR   w_vehicledata_File[260];
TCHAR   w_watch_list_File[260];
TCHAR   w_npcdata_File[260];

CHAR   w_decodata_File_Ansi[260];
CHAR   w_AreaData_File_Ansi[260];
CHAR   w_BuilderCmdAlias_File_Ansi[260];
CHAR   w_categorydata_File_Ansi[260];
CHAR   w_doordata_File_Ansi[260];
CHAR   w_fishingdata_File_Ansi[260];
CHAR   w_eventdata_File_Ansi[260];
CHAR   w_Dyedata_File_Ansi[260];
CHAR   w_quest_pch2_File_Ansi[260];
CHAR   w_petdata_File_Ansi[260];
CHAR   w_manordata_File_Ansi[260];
CHAR   w_monrace_File_Ansi[260];
CHAR   w_MultiSell_File_Ansi[260];
CHAR   w_itemdata_File_Ansi[260];
CHAR   w_PC_Parameter_File_Ansi[260];
CHAR   w_PetitionCategory_File_Ansi[260];
CHAR   w_recipe_File_Ansi[260];
CHAR   w_castledata_File_Ansi[260];
CHAR   w_setting_File_Ansi[260];
CHAR   w_skilldata_File_Ansi[260];
CHAR   w_SkillAcquire_File_Ansi[260];
CHAR   w_skillenchantdata_File_Ansi[260];
CHAR   w_vehicledata_File_Ansi[260];
CHAR   w_watch_list_File_Ansi[260];
CHAR   w_npcdata_File_Ansi[260];
CHAR   w_geo_index_Ansi[260];
CHAR   w_map_bug_Ansi[260];



//Extender

wstring augmentation_name_txt;				//	wstring filew = ReadFileW(L"..\\Script\\augmentation_name.txt");
wstring MiningData_txt;				//	wstring filew = ReadFileW(L"..\\Script\\MiningData.txt");
wstring MultiSell_txt;				//	wstring filew = ReadFileW(L"..\\Script\\MultiSell.txt");
wstring Skill_Pch_txt;				//	wstring filew = ReadFileW(L"..\\Script\\Skill_Pch.txt");
wstring SkillAcquire_txt;				//	wstring filew = ReadFileW(L"..\\Script\\SkillAcquire.txt");
wstring SkillData_txt;				//	wstring filew = ReadFileW(L"..\\Script\\SkillData.txt");
wstring Setting_txt;				//	wstring filew = ReadFileW(L"..\\Script\\Setting.txt");
wstring item_pch_txt;				//	wstring filew = ReadFileW(L"..\\Script\\item_pch.txt");
wstring ItemsNotDropped_txt;				//	wstring filew = ReadFileW(L"..\\Script\\ItemsNotDropped.txt");
wstring ItemsDroppedAIMultiplier_txt;				//	wstring filew = ReadFileW(L"..\\Script\\ItemsNotDropped.txt");
wstring ItemAutoConsume_txt;				//	wstring filew = ReadFileW(L"..\\Script\\ItemAutoConsume.txt");	
	
wstring AIOData_txt;				//	wstringstream file(ReadFileW(L"..\\Script\\AIOData.txt"));	
wstring BuilderCmd_txt;				//	wstringstream file(ReadFileW(L"..\\Script\\BuilderCmd.txt"));
wstring PledgeSkillAcquire_txt;				//	wstringstream file(ReadFileW(L"..\\Script\\PledgeSkillAcquire.txt"));	
wstring ItemGrp_txt;				//	wstringstream file(ReadFileW(L"..\\Script\\ItemGrp.txt"));
wstring ItemName_txt;				//	wstringstream file(ReadFileW(L"..\\Script\\ItemName.txt"));
wstring CLogFilter_txt;				//	wstringstream file(ReadFileW(L"..\\script\\CLogFilter.txt"));
wstring ObsceneFilter_txt;				//	wstringstream file(ReadFileW(L"..\\Script\\ObsceneFilter.txt"));
wstring SkillName_txt;				//	wstringstream file(ReadFileW(L"..\\Script\\SkillName.txt"));
wstring SkillGrp_txt;				//	wstringstream file(ReadFileW(L"..\\Script\\SkillGrp.txt"));
wstring VisualArmor_txt;				//	wstringstream file(ReadFileW(L"..\\Script\\VisualArmor.txt"));
wstring SchemeBuffer_txt;				//	wstringstream file(ReadFileW(L"..\\Script\\SchemeBuffer.txt"));
wstring NpcName_txt;				//	wstringstream file(ReadFileW(L"..\\Script\\NpcName.txt"));
wstring NpcName2_txt;				//	wstringstream file(ReadFileW(L"..\\Script\\NpcName2.txt"));
wstring NpcData_txt;				//	wstringstream file(ReadFileW(L"..\\Script\\NpcData.txt"));
wstring ItemData_txt;				//	wstringstream file(ReadFileW(L"..\\Script\\ItemData.txt"));
wstring HerbData_txt;				//	wstringstream file(ReadFileW(L"..\\Script\\HerbData.txt"));
	
string SkillDataEx_txt;				//	ifstream file("..\\Script\\SkillDataEx.txt");
string TeleportData_txt;				//	ifstream file("..\\Script\\TeleportData.txt");
string CastleDataEx_txt;				//	ifstream file("..\\Script\\CastleDataEx.txt");
string NpcPosEx_txt;				//	ifstream file("..\\Script\\NpcPosEx.txt");
string DonateAugmentList_txt;				//	ifstream file("..\\Script\\DonateAugmentList.txt");
string DonateList_txt;				//	ifstream file("..\\Script\\DonateList.txt");
string ItemDataEx_txt;				//	ifstream file("..\\Script\\ItemDataEx.txt");
string ArmorPenaltyData_txt;				//	ifstream file("..\\Script\\ArmorPenaltyData.txt");
string augmentation_skill_txt;				//	ifstream file("..\\Script\\augmentation_skill.txt");
string augmentation_stat_txt;				//	ifstream file("..\\Script\\augmentation_stat.txt");
string NpcChampionData_txt;				//	ifstream file("..\\Script\\NpcChampionData.txt");
string NpcReputationData_txt;				//	ifstream file("..\\Script\\NpcReputationData.txt");	
	
string TerritoryData_txt;				//	ReadData("..\\Script\\TerritoryData.txt");
string EnchantedSetData_txt;				//	ReadData("..\\Script\\EnchantedSetData.txt");

wstring DoorData_txt;				//	UINT size = ReadFileBinary(L"..\\Script\\DoorData.txt", lpFile);
wstring ClassName_txt;				//	UINT size = ReadFileBinary(L"..\\Script\\ClassName.txt", lpFile);	
wstring SkillMaster_txt;				//	UINT size = ReadFileBinary(L"..\\Script\\SkillMaster.txt", lpFile);
wstring OlympiadSupport_txt;				//	UINT size = ReadFileBinary(L"..\\Script\\OlympiadSupport.txt", lpFile);
wstring Recipe_txt;				//	UINT size = ReadFileBinary(L"..\\Script\\Recipe.txt", lpFile);



	void Init();
	void LoadInI();
	void SetearRutasL2Server();
	void SetearRutasExtender();
};

extern ChangeFolders g_ChangeFolders;

