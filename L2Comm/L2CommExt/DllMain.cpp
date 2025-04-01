#include "DllMain.h"

TCHAR   connStrBBS[80];
TCHAR   connStrClanBBS[80];

TCHAR   lin_GetKeyword[260];
TCHAR   lin_GetLocation[260];
TCHAR   lin_GetAnnounce[260];
TCHAR   lin_GetAnnounceList[260];
TCHAR   lin_DelFavorite[260];
TCHAR   lin_SetFavorite[260];
TCHAR   lin_GetFavorite[260];
TCHAR   lin_GetBoardTree[260];
TCHAR   lin_Delete[260];
TCHAR   lin_SearchArticle[260];
TCHAR   lin_GetBoardRights[260];
TCHAR   lin_GetBoardPage[260];
TCHAR   lin_WriteComment[260];
TCHAR   lin_ReadComment[260];
TCHAR   lin_ReadArticleThread[260];
TCHAR   lin_ModArticle[260];
TCHAR   lin_GetArticleList[260];
TCHAR   lin_ReadArticle[260];
TCHAR   lin_WriteArticle[260];
TCHAR   lin_DelBoard[260];
TCHAR   lin_ModBoard[260];
TCHAR   lin_GetBoardAdmin[260];
TCHAR   lin_GetBoardList[260];
TCHAR   lin_MakeBoard[260];

TCHAR   lin_GetKeyword2[260];
TCHAR   lin_GetLocation2[260];
TCHAR   lin_GetAnnounce2[260];
TCHAR   lin_GetAnnounceList2[260];
TCHAR   lin_DelFavorite2[260];
TCHAR   lin_SetFavorite2[260];
TCHAR   lin_GetFavorite2[260];
TCHAR   lin_GetBoardTree2[260];
TCHAR   lin_Delete2[260];
TCHAR   lin_SearchArticle2[260];
TCHAR   lin_GetBoardRights2[260];
TCHAR   lin_GetBoardPage2[260];
TCHAR   lin_WriteComment2[260];
TCHAR   lin_ReadComment2[260];
TCHAR   lin_ReadArticleThread2[260];
TCHAR   lin_ModArticle2[260];
TCHAR   lin_GetArticleList2[260];
TCHAR   lin_ReadArticle2[260];
TCHAR   lin_WriteArticle2[260];
TCHAR   lin_DelBoard2[260];
TCHAR   lin_ModBoard2[260];
TCHAR   lin_GetBoardAdmin2[260];
TCHAR   lin_GetBoardList2[260];
TCHAR   lin_MakeBoard2[260];

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved )
{
	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
			Initialize();
			break;

		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}
    
	return TRUE;
}

void Initialize()
{
			TCHAR File[MAX_PATH];
			GetCurrentDirectory(MAX_PATH,File);
			lstrcat(File, L"\\l2comm.ini");
			GetPrivateProfileStringW(_T("Mi_Custom"), _T("connStrBBS"),L"connStrBBS",connStrBBS, 80, File);
			Utils::WriteMemoryDWORD(0x4056C7, (DWORD)connStrBBS);
			Utils::WriteMemoryDWORD(0x405BB4, (DWORD)connStrBBS);
			GetPrivateProfileStringW(_T("Mi_Custom"), _T("connStrClanBBS"),L"connStrClanBBS",connStrClanBBS, 80, File);
			Utils::WriteMemoryDWORD(0x405857, (DWORD)connStrClanBBS);
			Utils::WriteMemoryDWORD(0x405BF9, (DWORD)connStrClanBBS);

			UINT Port = GetPrivateProfileInt(_T("Mi_Custom"), _T("Puerto2010"), 2010, File);
			Utils::WriteMemoryDWORD(0x40FC4C, Port);

			lstrcat(lin_GetKeyword, L"EXEC ");
			lstrcat(lin_GetLocation, L"EXEC ");
			lstrcat(lin_GetAnnounce, L"EXEC ");
			lstrcat(lin_GetAnnounceList, L"EXEC ");
			lstrcat(lin_DelFavorite, L"EXEC ");
			lstrcat(lin_SetFavorite, L"EXEC ");
			lstrcat(lin_GetFavorite, L"EXEC ");
			lstrcat(lin_GetBoardTree, L"EXEC ");
			lstrcat(lin_Delete, L"EXEC ");
			lstrcat(lin_SearchArticle, L"EXEC ");
			lstrcat(lin_GetBoardRights, L"EXEC ");
			lstrcat(lin_GetBoardPage, L"EXEC ");
			lstrcat(lin_WriteComment, L"EXEC ");
			lstrcat(lin_ReadComment, L"EXEC ");
			lstrcat(lin_ReadArticleThread, L"EXEC ");
			lstrcat(lin_ModArticle, L"EXEC ");
			lstrcat(lin_GetArticleList, L"EXEC ");
			lstrcat(lin_ReadArticle, L"EXEC ");
			lstrcat(lin_WriteArticle, L"EXEC ");
			lstrcat(lin_DelBoard, L"EXEC ");
			lstrcat(lin_ModBoard, L"EXEC ");
			lstrcat(lin_GetBoardAdmin, L"EXEC ");
			lstrcat(lin_GetBoardList, L"EXEC ");
			lstrcat(lin_MakeBoard, L"EXEC ");
			
			GetPrivateProfileStringW(_T("Mi_Custom"), _T("AliasDB"),L"",lin_GetLocation2, 260, File);
			GetPrivateProfileStringW(_T("Mi_Custom"), _T("AliasDB"),L"",lin_GetAnnounce2, 260, File);
			GetPrivateProfileStringW(_T("Mi_Custom"), _T("AliasDB"),L"",lin_GetAnnounceList2, 260, File);
			GetPrivateProfileStringW(_T("Mi_Custom"), _T("AliasDB"),L"",lin_DelFavorite2, 260, File);
			GetPrivateProfileStringW(_T("Mi_Custom"), _T("AliasDB"),L"",lin_SetFavorite2, 260, File);
			GetPrivateProfileStringW(_T("Mi_Custom"), _T("AliasDB"),L"",lin_GetFavorite2, 260, File);
			GetPrivateProfileStringW(_T("Mi_Custom"), _T("AliasDB"),L"",lin_GetBoardTree2, 260, File);
			GetPrivateProfileStringW(_T("Mi_Custom"), _T("AliasDB"),L"",lin_Delete2, 260, File);
			GetPrivateProfileStringW(_T("Mi_Custom"), _T("AliasDB"),L"",lin_SearchArticle2, 260, File);
			GetPrivateProfileStringW(_T("Mi_Custom"), _T("AliasDB"),L"",lin_GetBoardRights2, 260, File);
			GetPrivateProfileStringW(_T("Mi_Custom"), _T("AliasDB"),L"",lin_GetBoardPage2, 260, File);
			GetPrivateProfileStringW(_T("Mi_Custom"), _T("AliasDB"),L"",lin_WriteComment2, 260, File);
			GetPrivateProfileStringW(_T("Mi_Custom"), _T("AliasDB"),L"",lin_ReadComment2, 260, File);
			GetPrivateProfileStringW(_T("Mi_Custom"), _T("AliasDB"),L"",lin_ReadArticleThread2, 260, File);
			GetPrivateProfileStringW(_T("Mi_Custom"), _T("AliasDB"),L"",lin_ModArticle2, 260, File);
			GetPrivateProfileStringW(_T("Mi_Custom"), _T("AliasDB"),L"",lin_GetArticleList2, 260, File);
			GetPrivateProfileStringW(_T("Mi_Custom"), _T("AliasDB"),L"",lin_ReadArticle2, 260, File);
			GetPrivateProfileStringW(_T("Mi_Custom"), _T("AliasDB"),L"",lin_WriteArticle2, 260, File);
			GetPrivateProfileStringW(_T("Mi_Custom"), _T("AliasDB"),L"",lin_DelBoard2, 260, File);
			GetPrivateProfileStringW(_T("Mi_Custom"), _T("AliasDB"),L"",lin_ModBoard2, 260, File);
			GetPrivateProfileStringW(_T("Mi_Custom"), _T("AliasDB"),L"",lin_GetBoardAdmin2, 260, File);
			GetPrivateProfileStringW(_T("Mi_Custom"), _T("AliasDB"),L"",lin_GetBoardList2, 260, File);
			GetPrivateProfileStringW(_T("Mi_Custom"), _T("AliasDB"),L"",lin_MakeBoard2, 260, File);

			lstrcat(lin_GetKeyword, lin_GetKeyword2);
			lstrcat(lin_GetLocation, lin_GetLocation2);
			lstrcat(lin_GetAnnounce, lin_GetAnnounce2);
			lstrcat(lin_GetAnnounceList, lin_GetAnnounceList2);
			lstrcat(lin_DelFavorite, lin_DelFavorite2);
			lstrcat(lin_SetFavorite, lin_SetFavorite2);
			lstrcat(lin_GetFavorite, lin_GetFavorite2);
			lstrcat(lin_GetBoardTree, lin_GetBoardTree2);
			lstrcat(lin_Delete, lin_Delete2);
			lstrcat(lin_SearchArticle, lin_SearchArticle2);
			lstrcat(lin_GetBoardRights, lin_GetBoardRights2);
			lstrcat(lin_GetBoardPage, lin_GetBoardPage2);
			lstrcat(lin_WriteComment, lin_WriteComment2);
			lstrcat(lin_ReadComment, lin_ReadComment2);
			lstrcat(lin_ReadArticleThread, lin_ReadArticleThread2);
			lstrcat(lin_ModArticle, lin_ModArticle2);
			lstrcat(lin_GetArticleList, lin_GetArticleList2);
			lstrcat(lin_ReadArticle, lin_ReadArticle2);
			lstrcat(lin_WriteArticle, lin_WriteArticle2);
			lstrcat(lin_DelBoard, lin_DelBoard2);
			lstrcat(lin_ModBoard, lin_ModBoard2);
			lstrcat(lin_GetBoardAdmin, lin_GetBoardAdmin2);
			lstrcat(lin_GetBoardList, lin_GetBoardList2);
			lstrcat(lin_MakeBoard, lin_MakeBoard2);

			lstrcat(lin_GetKeyword, L"lin2comm.dbo.lin_GetKeyword %d ");																//.rdata:0043D4E0	00000048	C (16 bits)	EXEC lin2comm.dbo.lin_GetKeyword %d
			lstrcat(lin_GetLocation, L"lin2comm.dbo.lin_GetLocation %d, %d ");															//.rdata:0043D528	00000052	C (16 bits)	EXEC lin2comm.dbo.lin_GetLocation %d, %d
			lstrcat(lin_GetAnnounce, L"lin2comm.dbo.lin_GetAnnounce %d  ");																//.rdata:0043D580	0000004C	C (16 bits)	EXEC lin2comm.dbo.lin_GetAnnounce %d 
			lstrcat(lin_GetAnnounceList, L"lin2comm.dbo.lin_GetAnnounceList %d ");														//.rdata:0043D5D0	00000054	C (16 bits)	EXEC lin2comm.dbo.lin_GetAnnounceList %d 
			lstrcat(lin_DelFavorite, L"lin2comm.dbo.lin_DelFavorite %d, %d ");															//.rdata:0043D628	00000054	C (16 bits)	EXEC lin2comm.dbo.lin_DelFavorite %d, %d 
			lstrcat(lin_SetFavorite, L"lin2comm.dbo.lin_SetFavorite %d, %d, N'%s', N'%s', %d, %d, %d, %d, %d, N'%s' ");					//.rdata:0043D680	000000A6	C (16 bits)	EXEC lin2comm.dbo.lin_SetFavorite %d, %d, N'%s', N'%s', %d, %d, %d, %d, %d, N'%s' 
			lstrcat(lin_GetFavorite, L"lin2comm.dbo.lin_GetFavorite %d, %d ");															//.rdata:0043D728	00000052	C (16 bits)	EXEC lin2comm.dbo.lin_GetFavorite %d, %d
			lstrcat(lin_GetBoardTree, L"lin2comm.dbo.lin_GetBoardTree %d  ");															//.rdata:0043D780	00000050	C (16 bits)	EXEC lin2comm.dbo.lin_GetBoardTree %d  
			lstrcat(lin_Delete, L"lin2comm.dbo.lin_Delete %d, %d, %d, %d ");															//.rdata:0043D7D0	0000005A	C (16 bits)	EXEC lin2comm.dbo.lin_Delete %d, %d, %d, %d 
			lstrcat(lin_SearchArticle, L"lin2comm.dbo.lin_SearchArticle %d, %d, %d, N'%s' ");											//.rdata:0043D830	0000006E	C (16 bits)	EXEC lin2comm.dbo.lin_SearchArticle %d, %d, %d, N'%s' 
			lstrcat(lin_GetBoardRights, L"lin2comm.dbo.lin_GetBoardRights %d, %d, %d, %d ");											//.rdata:0043D8A0	0000006A	C (16 bits)	EXEC lin2comm.dbo.lin_GetBoardRights %d, %d, %d, %d 
			lstrcat(lin_GetBoardPage, L"lin2comm.dbo.lin_GetBoardPage %d ");															//.rdata:0043D910	0000004C	C (16 bits)	EXEC lin2comm.dbo.lin_GetBoardPage %d
			lstrcat(lin_WriteComment, L"lin2comm.dbo.lin_WriteComment %d, %d, %d, N'%s', %d, N'%s', %d, N'%s' ");						//.rdata:0043D960	00000098	C (16 bits)	EXEC lin2comm.dbo.lin_WriteComment %d, %d, %d, N'%s', %d, N'%s', %d, N'%s'  
			lstrcat(lin_ReadComment, L"lin2comm.dbo.lin_ReadComment %d, %d, %d ");														//.rdata:0043D9F8	0000005C	C (16 bits)	EXEC lin2comm.dbo.lin_ReadComment %d, %d, %d 
			lstrcat(lin_ReadArticleThread, L"lin2comm.dbo.lin_ReadArticleThread %d, %d, %d, %d, %d ");									//.rdata:0043DA58	00000078	C (16 bits)	EXEC lin2comm.dbo.lin_ReadArticleThread %d, %d, %d, %d, %d 
			lstrcat(lin_ModArticle, L"lin2comm.dbo.lin_ModArticle %d, %d, N'%s', N'%s', N'%s' ");										//.rdata:0043DAD0	0000007C	C (16 bits)	EXEC lin2comm.dbo.lin_ModArticle %d, %d, N'%s', N'%s', N'%s' 
			lstrcat(lin_GetArticleList, L"lin2comm.dbo.lin_GetArticleList %d, %d ");													//.rdata:0043DB50	0000005A	C (16 bits)	EXEC lin2comm.dbo.lin_GetArticleList %d, %d 
			lstrcat(lin_ReadArticle, L"lin2comm.dbo.lin_ReadArticle %d, %d, %d, %d, %d ");												//.rdata:0043DBB0	0000006C	C (16 bits)	EXEC lin2comm.dbo.lin_ReadArticle %d, %d, %d, %d, %d 
			lstrcat(lin_WriteArticle, L"lin2comm.dbo.lin_WriteArticle %d, %d, %d, N'%s', %d, N'%s', %d, N'%s', N'%s', N'%s', N'%s' ");	//.rdata:0043DC20	000000C2	C (16 bits)	EXEC lin2comm.dbo.lin_WriteArticle %d, %d, %d, N'%s', %d, N'%s', %d, N'%s', N'%s', N'%s', N'%s' 
			lstrcat(lin_DelBoard, L"lin2comm.dbo.lin_DelBoard %d, %d ");																//.rdata:0043DCE8	0000004E	C (16 bits)	EXEC lin2comm.dbo.lin_DelBoard %d, %d 
			lstrcat(lin_ModBoard, L"lin2comm.dbo.lin_ModBoard %d, %d, N'%s', N'%s', N'%s', %d, %d, %d, %d, %d, %d, %d ");				//.rdata:0043DD38	000000B0	C (16 bits)	EXEC lin2comm.dbo.lin_ModBoard %d, %d, N'%s', N'%s', N'%s', %d, %d, %d, %d, %d, %d, %d 
			lstrcat(lin_GetBoardAdmin, L"lin2comm.dbo.lin_GetBoardAdmin %d, %d ");														//.rdata:0043DDE8	00000058	C (16 bits)	EXEC lin2comm.dbo.lin_GetBoardAdmin %d, %d 
			lstrcat(lin_GetBoardList, L"lin2comm.dbo.lin_GetBoardList %d, %d, %d, %d ");												//.rdata:0043DE40	00000066	C (16 bits)	EXEC lin2comm.dbo.lin_GetBoardList %d, %d, %d, %d 
			lstrcat(lin_MakeBoard, L"lin2comm.dbo.lin_MakeBoard %d, N'%s', %d, %d, N'%s', %d, %d, %d, %d, %d ");						//.rdata:0043DEA8	0000009C	C (16 bits)	EXEC lin2comm.dbo.lin_MakeBoard %d, N'%s', %d, %d, N'%s', %d, %d, %d, %d, %d 

			Utils::WriteMemoryDWORD(0x44D0D0, (DWORD)lin_GetKeyword);
			Utils::WriteMemoryDWORD(0x44D0CC, (DWORD)lin_GetLocation);
			Utils::WriteMemoryDWORD(0x44D0C8, (DWORD)lin_GetAnnounce);
			Utils::WriteMemoryDWORD(0x44D0C4, (DWORD)lin_GetAnnounceList);
			Utils::WriteMemoryDWORD(0x44D0C0, (DWORD)lin_DelFavorite);
			Utils::WriteMemoryDWORD(0x44D0BC, (DWORD)lin_SetFavorite);
			Utils::WriteMemoryDWORD(0x44D0B8, (DWORD)lin_GetFavorite);
			Utils::WriteMemoryDWORD(0x44D0B4, (DWORD)lin_GetBoardTree);
			Utils::WriteMemoryDWORD(0x44D0B0, (DWORD)lin_Delete);
			Utils::WriteMemoryDWORD(0x44D0AC, (DWORD)lin_SearchArticle);
			Utils::WriteMemoryDWORD(0x44D0A8, (DWORD)lin_GetBoardRights);
			Utils::WriteMemoryDWORD(0x44D0A4, (DWORD)lin_GetBoardPage);
			Utils::WriteMemoryDWORD(0x44D0A0, (DWORD)lin_WriteComment);
			Utils::WriteMemoryDWORD(0x44D09C, (DWORD)lin_ReadComment);
			Utils::WriteMemoryDWORD(0x44D098, (DWORD)lin_ReadArticleThread);
			Utils::WriteMemoryDWORD(0x44D094, (DWORD)lin_ModArticle);
			Utils::WriteMemoryDWORD(0x44D090, (DWORD)lin_GetArticleList);
			Utils::WriteMemoryDWORD(0x44D08C, (DWORD)lin_ReadArticle);
			Utils::WriteMemoryDWORD(0x44D088, (DWORD)lin_WriteArticle);
			Utils::WriteMemoryDWORD(0x44D084, (DWORD)lin_DelBoard);
			Utils::WriteMemoryDWORD(0x44D080, (DWORD)lin_ModBoard);
			Utils::WriteMemoryDWORD(0x44D07C, (DWORD)lin_GetBoardAdmin);
			Utils::WriteMemoryDWORD(0x44D078, (DWORD)lin_GetBoardList);
			Utils::WriteMemoryDWORD(0x44D074, (DWORD)lin_MakeBoard);
}
