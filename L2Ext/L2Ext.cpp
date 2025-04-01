#include "StdAfx.h"
#include "Exploits.h"
#include "License.h"
#include "AdminCachedCommand.h"

using namespace License;

HANDLE hMutex;

DWORD g_ItemPacketReuse = 1000;
double g_MaxValidateLocationDiff = 0.0;
BOOL g_BlockSummonExp = FALSE;
BOOL g_SpiritShotExtension = FALSE;
BOOL g_NewShotSystem = FALSE;
BOOL g_ValidateAcquiredSkills = FALSE;
BOOL g_SubStackServer = FALSE;
BOOL g_ShowInventoryOnEnterWorld = TRUE;
BOOL g_ValidateStackableItems = FALSE;
BOOL g_DeleteInvalidStack = FALSE;
BOOL g_DisablePets = FALSE;
BOOL g_ShowEnterWorldHtml = FALSE;
BOOL m_BuilderSkills = FALSE;
INT32 g_MaxPartyLevelRange = 0;
BOOL g_BlockPartyInvite = 0;
wstring g_ExtReleaseVersion = L"1.0.0.0";
BOOL g_CustomAbnormalInfoPacket = FALSE;
BOOL g_GetLootFromPet = FALSE;
double g_PetExpRate = 1.0;
BOOL g_GlobalChat = FALSE;
BOOL g_GlobalChatTrade = FALSE;
INT32 g_ChatShoutLevel = 0;
BOOL g_PacketLog = FALSE;
TCHAR g_ConfigFile[260];
TCHAR l2server_ini[260];
TCHAR l2cache_ini[260];
UINT g_ServerStartTime = 0;
UINT g_SaveAbnormalsIntervalTime = 0;
UINT g_ShutdownTime = 30;
BOOL g_SaveInstancesOnDB = FALSE;

BOOL g_PetBlockGiveAllItemsToMaster = FALSE;
BOOL g_PetBlockTrade = FALSE;
vector<INT32> g_PetAllowedItems;

UINT g_MaxSlosChars = 0;
UINT g_MaxSlotsDwarfs = 0;

BOOL g_menu = FALSE;
BOOL g_offline_shop = FALSE;
BOOL g_vip = FALSE;
BOOL g_vote = FALSE;
BOOL g_exp = FALSE;
BOOL g_autoloot = FALSE;
BOOL g_rune = FALSE;
BOOL g_timeleft = FALSE;
BOOL g_restart = FALSE;
BOOL g_goldbar = FALSE;
BOOL g_varmor = FALSE;
BOOL g_engage = FALSE;
BOOL g_divorce = FALSE;
BOOL g_gotolove = FALSE;
BOOL g_ping = FALSE;
BOOL g_online = FALSE;
BOOL g_jointvt = FALSE;
BOOL g_checkvote = FALSE;
BOOL g_showvote = FALSE;
BOOL g_rebirth = FALSE;
BOOL g_captcha = FALSE;
BOOL g_faction = FALSE;
BOOL g_donate = FALSE;
BOOL g_hero = FALSE;
BOOL g_dressme = FALSE;
BOOL g_sellbuff = FALSE;
BOOL g_achiv = FALSE;
BOOL g_help = FALSE;
BOOL g_pvp = FALSE;
BOOL g_torneo = FALSE;
BOOL g_event = FALSE;
BOOL g_rank = FALSE;
BOOL g_nosleep = FALSE;

TCHAR g_LicenseName[256] = { 0 };

#pragma optimize("", off)

void L2Ext::BaseData()
{
	VIRTUALIZER_TIGER_WHITE_START;
	GetCurrentDirectory(MAX_PATH, g_ConfigFile);

	lstrcat(g_ConfigFile, m_ConfigsIlExt);

	lstrcat(g_ConfigFile, _T("\\IlExt.ini"));

	g_ServerStartTime = time(0);

	GetCurrentDirectory(MAX_PATH, l2server_ini);
	lstrcat(l2server_ini, L"\\l2server.ini");



	GetCurrentDirectory(MAX_PATH, l2cache_ini);
	lstrcat(l2cache_ini, L"\\..\\CacheD\\l2cache.ini");



	GetCurrentDirectory(MAX_PATH, g_CustomConfigFile);

	lstrcat(g_CustomConfigFile, m_ConfigsIlExt);

	lstrcat(g_CustomConfigFile, _T("\\Customs.ini"));


	const WCHAR altUserName[] = { L'A', L'L', L'T', L'U', L'S', L'E', L'R', L'N', L'A', L'M', L'E', 0 };

	GetEnvironmentVariable(altUserName, g_LicenseName, 255);

	CLicense::GetInstance().Init();


	g_AdminCachedCommand.Init();

	UINT npcPort = GetPrivateProfileInt(L"Setting", L"NpcServerPort", 2002, l2server_ini);
	g_HookManager.WriteMemoryDWORD(0x643A63, npcPort);



	if(GetPrivateProfileInt(_T("L2SERVER"), _T("DisableSkillEnchantData"), FALSE, g_CustomConfigFile))
	{
		g_HookManager.WriteMemoryBYTES(0x7A2531, "90 90 90 90 90");		//arreglo SkillEnchantData que crashea el Load cada 2 por 3

		g_HookManager.WriteMemoryBYTES(0x6CECF6, "90 90 90 90 90");		//User__SendEnchantSkillList
		g_HookManager.WriteMemoryBYTES(0x7A00C7, "90 90 90 90 90");		//User__SendEnchantSkillList

	}


	g_Config.ReadData();
	//ShowMessage("Offset", "Offset addr[%p]", offsetof(CreatureSharedData, CreatureSharedData::OfflineShop));
	g_PetBlockTrade = GetPrivateProfileInt(_T("L2Server"), _T("PetBlockTrade"), FALSE, g_ConfigFile);
	g_PetBlockGiveAllItemsToMaster = GetPrivateProfileInt(_T("L2Server"), _T("PetBlockGiveAllItemsToMaster"), FALSE, g_ConfigFile);
	g_SaveAbnormalsIntervalTime = GetPrivateProfileInt(_T("L2Server"), _T("SaveAbnormalsIntervalTime"), 0, g_ConfigFile);
	g_SaveInstancesOnDB = GetPrivateProfileInt(_T("L2Server"), _T("SaveInstancesOnDB"), 0, g_ConfigFile);
	g_ShutdownTime = GetPrivateProfileInt(_T("L2Server"), _T("ShutdownTime"), 30, g_ConfigFile);
	g_HookManager.WriteMemoryDWORD(0x6270AE, g_ShutdownTime);

	TCHAR temp[8190] = { 0 };
	if(GetPrivateProfileString(_T("L2Server"), _T("PetAllowedItems"), 0, temp, 8190, g_ConfigFile))
	{
		wstringstream itemStream;
		itemStream << temp;
		int itemId = 0;
		while(itemStream >> itemId)
		{
			g_PetAllowedItems.push_back(itemId);
		}
	}
	g_GlobalChat = GetPrivateProfileInt(_T("L2Server"), _T("GlobalChat"), FALSE, g_ConfigFile);
	g_GlobalChatTrade = GetPrivateProfileInt(_T("L2Server"), _T("GlobalChatTrade"), FALSE, g_ConfigFile);
	g_ChatShoutLevel = GetPrivateProfileInt(_T("L2Server"), _T("ChatShoutLevel"), 0, g_ConfigFile);
	g_PacketLog = GetPrivateProfileInt(_T("L2Server"), _T("PacketLog"), FALSE, g_ConfigFile);
	g_ItemPacketReuse = GetPrivateProfileInt(_T("L2Server"), _T("ItemPacketReuse"), 800, g_ConfigFile);
	g_MaxValidateLocationDiff = GetPrivateProfileDouble(_T("L2Server"), _T("MaxValidateLocationDiff"), 0, g_ConfigFile);
	g_BlockSummonExp = GetPrivateProfileInt(_T("L2Server"), _T("BlockSummonExp"), 0, g_ConfigFile);
	g_SpiritShotExtension = GetPrivateProfileInt(_T("L2Server"), _T("SpiritShotExtension"), 0, g_ConfigFile);
	g_NewShotSystem = GetPrivateProfileInt(_T("L2Server"), _T("NewShotSystem"), 1, g_ConfigFile);
	g_ValidateAcquiredSkills = GetPrivateProfileInt(_T("L2Server"), _T("ValidateAcquiredSkills"), 0, g_ConfigFile);
	g_SubStackServer = GetPrivateProfileInt(_T("L2Server"), _T("SubStackServer"), 0, g_ConfigFile);
	g_ShowInventoryOnEnterWorld = GetPrivateProfileInt(_T("L2Server"), _T("ShowInventoryOnEnterWorld"), TRUE, g_ConfigFile);
	g_ValidateStackableItems = GetPrivateProfileInt(_T("L2Server"), _T("ValidateStackableItems"), FALSE, g_ConfigFile);
	g_DeleteInvalidStack = GetPrivateProfileInt(_T("L2Server"), _T("DeleteInvalidStack"), FALSE, g_ConfigFile);
	g_DisablePets = GetPrivateProfileInt(_T("L2Server"), _T("DisablePets"), FALSE, g_ConfigFile);
	g_ShowEnterWorldHtml = GetPrivateProfileInt(_T("L2Server"), _T("ShowEnterWorldHtml"), 0, g_ConfigFile);
	g_MaxPartyLevelRange = GetPrivateProfileInt(_T("L2Server"), _T("MaxPartyLevelRange"), 0, g_ConfigFile);
	g_BlockPartyInvite = GetPrivateProfileInt(_T("L2Server"), _T("BlockPartyInvite"), 0, g_ConfigFile);
	g_CustomAbnormalInfoPacket = GetPrivateProfileInt(_T("L2Server"), _T("CustomAbnormalInfoPacket"), 0, g_ConfigFile);
	g_GetLootFromPet = GetPrivateProfileInt(_T("L2Server"), _T("GetLootFromPet"), 0, g_ConfigFile);
	g_PetExpRate = GetPrivateProfileDouble(_T("L2Server"), _T("PetExpRate"), 1.0, g_ConfigFile);
	INT maxIOThread = GetPrivateProfileInt(_T("L2Server"), _T("MaxIOThread"), 8, g_ConfigFile);

	m_BuilderSkills = GetPrivateProfileInt(_T("L2Server"), _T("BuilderSkills"), 0, g_ConfigFile);
	//Max Slots
	g_MaxSlosChars = GetPrivateProfileInt(_T("L2Server"), _T("BaseSlotsChars"), 80, g_ConfigFile);
	g_MaxSlotsDwarfs = GetPrivateProfileInt(_T("L2Server"), _T("BaseSlotsDwarfs"), 100, g_ConfigFile);

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


	if(maxIOThread > 8)
		maxIOThread = 8;
	g_HookManager.WriteMemoryDWORD(0x61CFF4, maxIOThread);

	if(GetPrivateProfileInt(_T("L2Server"), _T("DisableSellItemPrice"), 0, g_ConfigFile))
	{
		g_HookManager.NopMemory(0x87A84F, 5);
	}

	VIRTUALIZER_TIGER_WHITE_END;

	MovLogFiles("LinErrBak");
	hMutex = CreateMutex(NULL, false, _T("Global\\IlExt"));
	if(GetLastError() == ERROR_ALREADY_EXISTS)
	{
		MessageBox(NULL, _T("Lineage II server is already running!"), _T("Interlude Extension"), MB_OK);
		ExitProcess(-1);
		return;
	}
	
//	CAntiDebugger::Init();
	CAntiExploit::Init();
	CTurboBoost::Init();
	string protocol = g_Config.Protocol.GetProtocolVersionS();
	g_HookManager.WriteMemory(0x9BA9B3, protocol.c_str(), protocol.size());

	//AbnormalStatus packet
	g_HookManager.WriteMemoryBYTE(0x82801F, 40);
	//Mail Report
	g_HookManager.NopMemory(0x5B8F87, 5);
	g_HookManager.NopMemory(0x5B9540, 5);

	//henna id is invalid
	g_HookManager.NopMemory(0x86985B, 5);

	g_HookManager.WriteMemoryBYTE(0x4010C0, 0xC3);	//invalid log func fix
	g_HookManager.NopMemory(0x4010C1, 14);
	
	//g_HookManager.WriteJump( 0x6432F6, (PVOID)0x643307, 0);	//win2k8 crash fix
	g_HookManager.WriteJump( 0x6432F6, (PVOID)0x643307, 2);	//win2k8 crash fix

	//Pvp Flag Time
	g_HookManager.WriteMemoryDWORD(0x846036, g_Config.L2ServerConfig.GetPvpFlagTimeShort());
	g_HookManager.WriteMemoryDWORD(0x84603B, g_Config.L2ServerConfig.GetPvpFlagTimeLong());

	//Timer Dispath fix
	g_HookManager.WriteCall(0x62311A, L2Server::TimerDispatchFix , 0);
	g_HookManager.NopMemory(0x626227, 5);	//call stack

	//Spoil Fix (when chance got over 100 l2server decreases it to lower value (ex 120% -> 20%))
	if(g_Config.L2ServerConfig.GetSpoilFix() == 2)
	{
		g_HookManager.WriteJump(0x7D0962, OldSpoilFix, 1);
	}else if(g_Config.L2ServerConfig.GetSpoilFix() == 1)
	{
		g_HookManager.WriteJump(0x7D0944, (PVOID)0x7D0968, 31);
		g_HookManager.WriteJump(0x7D0972, SpoilFixEx, 24);
		//g_HookManager.WriteJump(0x7D0962, (DWORD)SpoilFix, 1);
	}

	g_HookManager.NopMemory(0x4FAC20, 5);	//SYS msg
	g_HookManager.NopMemory(0x4FAC6E, 5);	//SYS msg
	
	g_HookManager.WriteMemoryDWORD(0x6F1F74, 5); //Fix for fast loading npc
	g_HookManager.WriteMemoryBYTE(0x6F1E28, 0xFF);	//Se agrego para la carga mas rapida que antes de npc

	//Seven Sign system message 1263 change
//	int nMsgID = 2443;
//	g_HookManager.WriteMemoryDWORD(0x0084D9E5, nMsgID);
	//Disable health on lvl up
//	g_HookManager.NopMemory(0x515E80, 63);


	g_HookManager.NopMemory(0x588589, 5);	//[%S][%d] already set close timer. [%d], [%d][%s]
	g_HookManager.NopMemory(0x5883EE, 5);	//[%S][%d] already set close timer. [%d], [%d][%s]

	g_HookManager.NopMemory(0x5883A6, 5);	//Auth Kick (%d)(%d)(%s)
	g_HookManager.NopMemory(0x588362, 5);	//Auth Kick (%d)(%d)(%s)
	g_HookManager.NopMemory(0x588654, 5);	//Auth Kick (%d)(%d)(%s)




	//AGRANDAR CResidenceDB
//	g_HookManager.WriteMemoryDWORD(0x779083, 0xA6C0*2);
//	g_HookManager.WriteMemoryDWORD(0x656853, 0xF6C0*2);
//	g_HookManager.WriteMemoryDWORD(0x779680, 0xF6C0*2);		//NUEVO
//	g_HookManager.WriteMemoryDWORD(0x7796E3, 0xF6C0*2);		//NUEVO
//	g_HookManager.WriteMemoryDWORD(0x7791A9, 0xF6C0*2);		//NUEVO
//	g_HookManager.WriteMemoryBYTE(0x77961B, 0x1F);
//	g_HookManager.WriteMemoryBYTE(0x779620, 0x05);
//	g_HookManager.WriteMemoryBYTE(0x779149, 0x1F);
//	g_HookManager.WriteMemoryBYTE(0x77914E, 0x05);
//	g_HookManager.WriteMemoryBYTE(0x658624, 0x1F);
//	g_HookManager.WriteMemoryBYTE(0x65862B, 0x1F);
//	g_HookManager.WriteMemoryBYTE(0x658630, 0x05);




	//Hook PARA interceptar archivos de script y desencriptarlos, 
//	g_HookManager.WriteCall(0x8DC7B2, L2Ext::DecryptFiles, 0);		

}



//LoadBinaryAbsolute
char * L2Ext::DecryptFiles(const char *filename, __int64 var2)
{
	char* encryptedFile;

	typedef char*(*f)(const char*, __int64);
	encryptedFile = f(0x899CF0L)(filename, var2);


    for (int i = 0; encryptedFile[i] != '\0'; ++i) {
        // Aplicar la operación XOR con 14 a cada carácter
        encryptedFile[i] ^= 14;
		encryptedFile[i] ^= 7;
		encryptedFile[i] ^= 22;
		encryptedFile[i] ^= 28;
		encryptedFile[i] ^= 40;
    }


   // Abrir el archivo de entrada en modo lectura
    std::ifstream inputFile("..\\Script\\skilldata.txt");

    // Abrir un archivo de salida para escribir el contenido cifrado
    std::ofstream outputFile("encrypted_skilldata.txt");

    const std::string header = "//L2SERVERS.COM.AR\n";
    outputFile.write(header.c_str(), header.size());

    // Leer el contenido del archivo de entrada y aplicar la operación XOR
    char ch;
    while (inputFile.get(ch)) {

		ch ^= 40;
        ch ^= 28;
        ch ^= 22;
        ch ^= 7;
        ch ^= 14;

        outputFile.put(ch);
    }

    // Cerrar los archivos
    inputFile.close();
    outputFile.close();



	return encryptedFile;
}


void L2Ext::ReloadEnterworldHtml()
{
	g_ShowEnterWorldHtml = GetPrivateProfileInt(_T("L2Server"), _T("ShowEnterWorldHtml"), 0, g_ConfigFile);
}
#pragma optimize("", on)

void L2Ext::EtcHook()
{
	//Not active user try to save bla bla useless log
	g_HookManager.NopMemory(0x53A37C, 5);
	//Chrono weapon fix
	g_HookManager.WriteJump( 0x517A8D, ChronoWeaponFix1, 1);
	g_HookManager.WriteJump( 0x8B86A4, ChronoWeaponFix2, 2);

	//Item distribution fix - for herbs/zariche
	g_HookManager.WriteJump( 0x8BF783, ItemDistribution, 0);
}

WCHAR g_ItemHtmlData[30000][260];
bool g_IsRegisteredNpc[40000] = { 0 };
UINT g_SpecialNpcArray[1040000] = { 0 };

void L2Ext::FixNPCnItemID()
{
	//.text:0000000000642EBA mov     r8d, 5200000
	g_HookManager.WriteMemoryDWORD(0x642EBC, sizeof(g_ItemHtmlData));
	//.text:0000000000642EC0 lea     rcx, cs:39A8730h                ; void *
	g_HookManager.WriteRelativeAddress(0x642EC0, 3, g_ItemHtmlData, 0);
	//.text:000000000062CC3F lea     rax, cs:39A8730h
	g_HookManager.WriteRelativeAddress(0x62CC3F, 3, g_ItemHtmlData, 0);
	//.text:00000000004FAFDE lea     r12, cs:39A8730h
	g_HookManager.WriteRelativeAddress(0x4FAFDE, 3, g_ItemHtmlData, 0);

	g_HookManager.WriteMemoryDWORD(0x95F574, 30000);	//new item count
	g_HookManager.WriteMemoryDWORD(0xBF71C4, 30000);	//Max loaded items

	g_HookManager.WriteMemoryDWORD(0x95F5AA, 1000000);
	g_HookManager.WriteMemoryDWORD(0x95F5A4, 1040000);

	//reallocate register array
	//.text:00000000004659A7 lea     r14, cs:7D557F0h
	g_HookManager.WriteMemoryDWORD(0x4659AA, ((UINT)&g_IsRegisteredNpc[0] - 0x4659AE));
	//.text:0000000000465AF0 cmp     r13d, 1015000
	g_HookManager.WriteMemoryDWORD(0x465AF3, 1040000);
	//.text:00000000006BFF44 lea     rbx, cs:7D557F1h
	g_HookManager.WriteMemoryDWORD(0x6BFF47, ((UINT)&g_IsRegisteredNpc[1] - 0x6BFF4B));
	//.text:00000000006BFFBD lea     rsi, cs:7D557F1h
	g_HookManager.WriteMemoryDWORD(0x6BFFC0, ((UINT)&g_IsRegisteredNpc[1] - 0x6BFFC4));
	//.text:00000000006FCB26 mov     byte ptr [rax+r15+79557F0h], 1
	g_HookManager.WriteMemoryDWORD(0x6FCB2A, ((UINT)&g_IsRegisteredNpc[0] - 0x400000));
	//.text:000000000046569E cmp     byte ptr [rax+r14+79557F0h], 0
	g_HookManager.WriteMemoryDWORD(0x4656A2, ((UINT)&g_IsRegisteredNpc[0] - 0x400000));

	//teleport_to_npc
	//.text:0000000000453DBC cmp     eax, 15000
	g_HookManager.WriteMemoryDWORD(0x453DBD, 1040000);
	//.text:0000000000453DC5 mov     ecx, [rsi+rax*4+7959290h]
	g_HookManager.WriteMemoryDWORD(0x453DC8, ((UINT)&g_SpecialNpcArray[0] - 0x400000));

	//CNPC::OnCreate
	//.text:00000000006C890A mov     [rsi+rcx*4+7959290h], eax
	g_HookManager.WriteMemoryDWORD(0x6C890D, ((UINT)&g_SpecialNpcArray[0] - 0x400000));
	//CNPC::Delete
	//.text:00000000006C8CAC mov     [rbp+rax*4+7959290h], edi
	g_HookManager.WriteMemoryDWORD(0x6C8CAF, ((UINT)&g_SpecialNpcArray[0] - 0x400000));
}