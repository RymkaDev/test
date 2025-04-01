#include "DllMain.h"
#include "BuffSlot.h"
#include "Augmentation.h"
#include "Hair2SlotCache.h"

TCHAR   connStr[80];
TCHAR   connStrBBS[80];
TCHAR   connStrClanBBS[80];
const WCHAR* linworld = L"lin2world";

DllExport BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpvReserved)
{
	switch (dwReason)
	{
		case DLL_PROCESS_ATTACH:
		{

			TCHAR File[MAX_PATH];
			GetCurrentDirectory(MAX_PATH,File);
			lstrcat(File, L"\\l2cache.ini");

			if(!GetPrivateProfileInt(_T("Mi_Custom"), _T("SetThreadAffinityMask"), TRUE, File))
			{
				//NOPMemory(0x441C27, 6);			//SE CAE EL L2CACHED AL ARRANCAR, NO FUNCIONA POR AHORA
			}

			CIOBufferExt::Init();
			CachedExt::Initialize();
			CBuffSlot::Init();
			CAugmentation::Init();
			const char* cachedVersion = "$Revision: 453 $";
			CachedExt::WriteMemoryBYTES(0x528E48, (LPVOID)cachedVersion, 16);

			Hair2Slot::Initialize();




			
			CachedExt::WriteMemoryBYTE(0x0041CF17, 0xEB);	//METER SALTO EN ChangeCharacterNamePacket PARA CAMBIAR AUNQUE TODAVIA FIGURE EL PJ ONLINE



			GetPrivateProfileStringW(_T("Mi_Custom"), _T("connstr"),L"connStr",connStr, 80, File);
			CachedExt::WriteMemoryDWORD(0x42972E, (DWORD)connStr);
			CachedExt::WriteMemoryDWORD(0x429BE2, (DWORD)connStr);
			GetPrivateProfileStringW(_T("Mi_Custom"), _T("connStrBBS"),L"connStrBBS",connStrBBS, 80, File);
			CachedExt::WriteMemoryDWORD(0x4298FE, (DWORD)connStrBBS);
			CachedExt::WriteMemoryDWORD(0x429C36, (DWORD)connStrBBS);
			GetPrivateProfileStringW(_T("Mi_Custom"), _T("connStrClanBBS"),L"connStrClanBBS",connStrClanBBS, 80, File);
			CachedExt::WriteMemoryDWORD(0x429C7A, (DWORD)connStrClanBBS);
			CachedExt::WriteMemoryDWORD(0x429ACE, (DWORD)connStrClanBBS);
			CachedExt::WriteMemoryDWORD(0x561B5C, (DWORD)linworld);

			TCHAR g_ConfigFileCUSTOMS[260];
			GetCurrentDirectory(MAX_PATH, g_ConfigFileCUSTOMS);
			lstrcat(g_ConfigFileCUSTOMS, _T("\\..\\L2Server\\Customs.ini"));

			BYTE g_ItemBidAuctioner = GetPrivateProfileInt(_T("CLANHALL"), _T("ItemBidAuctioner"), 57, g_ConfigFileCUSTOMS);
			CachedExt::WriteMemoryBYTE(0x4BAE44+2, (BYTE)g_ItemBidAuctioner);

			break;
		}

		case DLL_PROCESS_DETACH:
		{

			break;
		}
	}

	return true;
}