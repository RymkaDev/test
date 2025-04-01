#include "DllMain.h"

TCHAR   connStr[80];
TCHAR   connStrBBS[80];
const WCHAR* linworld = L"lin2log";


TCHAR   aLin2log_dbo_l0[260];
TCHAR   aLin2log_dbo__0[260];
TCHAR   aLin2log_dbo__1[260];



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
	lstrcat(File, L"\\L2logD.ini");
	GetPrivateProfileStringW(_T("Mi_Custom"), _T("connstr"),L"connStr",connStr, 80, File);
	Utils::WriteMemoryDWORD(0x401C0D, (DWORD)connStr);
	Utils::WriteMemoryDWORD(0x401A06, (DWORD)connStr);
	GetPrivateProfileStringW(_T("Mi_Custom"), _T("connStrBBS"),L"connStrBBS",connStrBBS, 80, File);
	Utils::WriteMemoryDWORD(0x401B66, (DWORD)connStrBBS);
	Utils::WriteMemoryDWORD(0x401C58, (DWORD)connStrBBS);
	Utils::WriteMemoryDWORD(0x42D7B8, (DWORD)linworld);

	if(GetPrivateProfileInt(_T("Mi_Custom"), _T("DisableCSQLQueueExecSQL"), 0, File))
		NOPMemory(0x403D75, 5);	

	UINT Port = GetPrivateProfileInt(_T("LogD"), _T("port"), 3999, File);
	Utils::WriteMemoryDWORD(0x403CB1, Port);



	GetPrivateProfileStringW(_T("Mi_Custom"), _T("AliasDB"),L"",aLin2log_dbo_l0, 260, File);
	GetPrivateProfileStringW(_T("Mi_Custom"), _T("AliasDB"),L"",aLin2log_dbo__0, 260, File);
	GetPrivateProfileStringW(_T("Mi_Custom"), _T("AliasDB"),L"",aLin2log_dbo__1, 260, File);


	lstrcat(aLin2log_dbo_l0, L"lin2log.dbo.L%04d_%02d_%02d_log_data2_%d");
	lstrcat(aLin2log_dbo__0, L"lin2log.dbo.L%04d_%02d_%02d_log_data_%d");
	lstrcat(aLin2log_dbo__1, L"lin2log.dbo.L%04d_%02d_%02d_log_chat_%d");


	Utils::WriteMemoryDWORD(0x407EC6+1, (DWORD)aLin2log_dbo_l0);
	Utils::WriteMemoryDWORD(0x407EA3+1, (DWORD)aLin2log_dbo__0);
	Utils::WriteMemoryDWORD(0x407E79+1, (DWORD)aLin2log_dbo__1);



	NOPMemory(0x410044, 5);		//CServerSocket::CheckLogTimeTable %s, %d






}