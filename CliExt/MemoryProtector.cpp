#include "StdAfx.h"
#include "MemoryProtector.h"
#include "NetworkHandler.h"
#include "HWID.h"

CMemoryProtector g_MemoryProtector;

extern HMODULE g_CliExt;
extern HMODULE g_Engine;

unsigned char g_BotData1[41] = {
	0x25, 0x00, 0x73, 0x00, 0x5C, 0x00, 0x4D, 0x00, 0x41, 0x00, 0x50, 0x00, 0x53, 0x00, 0x5C, 0x00,
	0x25, 0x00, 0x64, 0x00, 0x5F, 0x00, 0x25, 0x00, 0x64, 0x00, 0x5F, 0x00, 0x25, 0x00, 0x64, 0x00,
	0x2E, 0x00, 0x44, 0x00, 0x41, 0x00, 0x54, 0x00, 0x00
};

unsigned char g_BotData2[77] = {
	0x46, 0x00, 0x6F, 0x00, 0x75, 0x00, 0x6E, 0x00, 0x64, 0x00, 0x20, 0x00, 0x50, 0x00, 0x6C, 0x00,
	0x61, 0x00, 0x79, 0x00, 0x65, 0x00, 0x72, 0x00, 0x20, 0x00, 0x25, 0x00, 0x73, 0x00, 0x20, 0x00,
	0x2C, 0x00, 0x20, 0x00, 0x4C, 0x00, 0x6F, 0x00, 0x67, 0x00, 0x6F, 0x00, 0x75, 0x00, 0x74, 0x00,
	0x2C, 0x00, 0x20, 0x00, 0x44, 0x00, 0x69, 0x00, 0x73, 0x00, 0x74, 0x00, 0x61, 0x00, 0x6E, 0x00,
	0x63, 0x00, 0x65, 0x00, 0x20, 0x00, 0x25, 0x00, 0x64, 0x00, 0x2E, 0x00, 0x00
};

unsigned char g_BotData3[54] = {
	0x4C, 0x00, 0x56, 0x00, 0x3A, 0x00, 0x25, 0x00, 0x64, 0x00, 0x0A, 0x00, 0x48, 0x00, 0x50, 0x00,
	0x3A, 0x00, 0x25, 0x00, 0x34, 0x00, 0x64, 0x00, 0x2F, 0x00, 0x25, 0x00, 0x34, 0x00, 0x64, 0x00,
	0x0A, 0x00, 0x4D, 0x00, 0x50, 0x00, 0x3A, 0x00, 0x25, 0x00, 0x34, 0x00, 0x64, 0x00, 0x2F, 0x00,
	0x25, 0x00, 0x34, 0x00, 0x64, 0x00
};

extern HMODULE g_Engine;
extern HANDLE g_HardwareIdSM;
extern LPBYTE g_lpHardwareIdSM;

#pragma optimize("", off)

void CMemoryProtector::Init()
{
	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;
	srand(GetTickCount());
	m_EngineAddressStart = m_EngineAddressEnd = m_EngineSize = 0;
	m_ValidateModulesTimeout = 0;
	m_ScanAddress = 0;
	m_ScanAddressEnd = 0;
	m_CliExtAddress = 0;
	m_CliExtSize = 0;
	m_ScanTick = GetTickCount();
	m_ModuleIndex = 0;

	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;
}

void CMemoryProtector::InitCliExt()
{
	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;

	MODULEINFO mi = { 0 };
	WCHAR cliExtdll[14] = { L'L', L'2', L'S', L'e', L'r', L'v', L'e', L'r', L's', L'.', L'd', L'l', L'l', 0 };
	bool isSet = false;
	HMODULE mod = GetModuleHandle(cliExtdll);
	if(!mod)
	{
		mod = g_CliExt;
	}
	if(mod)
	{
		if(GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi)))
		{
			isSet = true;
			m_CliExtAddress = reinterpret_cast<UINT>(mi.lpBaseOfDll);
			m_CliExtSize = mi.SizeOfImage;
		}
	}
	if(!isSet)
	{
		m_CliExtAddress = reinterpret_cast<UINT>(mod);
		m_CliExtSize = 900000;
	}

	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;
}

void SaveLibrary(PSTR moduleName, PSTR expr)
{
	//	ofstream lib("client.log");
	//	lib << moduleName << endl << expr << endl;
	//	lib.close();
}

string ModuleNameExtractor(string name)
{
	size_t lastPos = 0;
	size_t temp = name.find("\\");
	while(temp != string::npos)
	{
		lastPos = temp;
		temp = name.find("\\", lastPos+1);
	}
	if(lastPos > 0 && lastPos < name.size())
	{
		name = name.substr(lastPos+1);
	}
	return name;
}


BOOL CALLBACK CMemoryProtector::EnumerateLoadedModulesProc( PSTR moduleName, ULONG moduleBase, ULONG moduleSize, PVOID userContext )
{
	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;
	WCHAR moduleNameW[260];
	memset(moduleNameW, 0, sizeof(moduleNameW));
	/*
	string name(moduleName);
	name = ModuleNameExtractor(name);
	if(moduleName)
	{
	transform(name.begin(), name.end(), name.begin(), tolower);
	}
	*/
	for(UINT n=0;n<259;n++)
	{
		moduleNameW[n] = moduleName[n];
		if(moduleName[n] == 0)
		{
			break;
		}
	}

	ModuleInfo mi;
	mi.moduleBase = moduleBase;
	mi.moduleName = moduleNameW;
	mi.moduleSize = moduleSize;

	g_MemoryProtector.m_Modules.push_back(mi);

	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;
	return TRUE;
}

LPBYTE CMemoryProtector::FindMemory(LPBYTE lpMemory, UINT memorySize, LPBYTE lpData, UINT dataSize, bool& invalid)
{
	bool found = false;
	try
	{
		UINT correctData = 0;
		for(UINT n=0;n<memorySize;n++)
		{
			if(lpMemory[n] == lpData[correctData])
			{
				correctData++;
			}else
			{
				correctData = 0;
			}
			if(correctData == dataSize)
			{
				return &lpMemory[n-dataSize];
			}
		}
	}catch(...)
	{
		invalid = true;
	}

	return 0;
};


UINT g_EstamosAlTanto = 0;

vector<DWORD> g_ProcessToValidate;
vector<pair<DWORD, DCReasonType>> g_ProcessToDC;

BOOL CMemoryProtector::EnumWindowsCallback(HWND hWnd, LPARAM lParam)
{
	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;

	TCHAR text[260] = { 0 };
	GetWindowText(hWnd, text, 260);
	TCHAR className[260] = { 0 };
	GetClassName(hWnd, className, 260);
	if(wcslen(text) > 0)
	{
		DWORD procId = 0;
		GetWindowThreadProcessId(hWnd, &procId);
		if(/*!g_MemoryProtector.IsValidatedProcess(procId)*/ true)
		{
            //WCHAR cpTrack[] = L"CPTrack";
            //WCHAR l2quickTools[] = L"L2quickTools";
            WCHAR tApplication[] = L"TApplication";
            //WCHAR fraps[] = L"Fraps";
            //WCHAR tfmMain[] = L"TfmMain";
            //WCHAR uoPilot[] = L"UoPilot";
            //WCHAR tfmMainDll[] = L"TfmMainDll";
            //WCHAR autoIt[] = L"AutoIt";
            //WCHAR zagryzka[] = L"Загрузка";
            //WCHAR tForm6[] = L"TForm6";
            //WCHAR thunderRT6FormDC[] = L"ThunderRT6FormDC";
            WCHAR thunderRT6Main[] = L"ThunderRT6Main";
            //WCHAR l2Point[] = L"L2Point";
            WCHAR netBroadcastEventWindow[] = L".NET-BroadcastEventWindow.4.0.0.2bf8098.0";
            WCHAR loader[] = L"Loader";
            WCHAR adrenalin[] = L"Adrenalin v";
            WCHAR l2ext[] = L"l2ext";
            //WCHAR controlPanel[] = L"Control Panel";
            //WCHAR clickermann[] = L"Clickermann";
            //WCHAR windowsForms10[] = L"WindowsForms10";
            //WCHAR extremeInjector[] = L"Extreme Injector";


			if(!wcscmp(loader, text) && !wcscmp(className, tApplication))
			{
				g_ProcessToDC.push_back(pair<DWORD, DCReasonType>(procId, DCReasonAdrenaline));
			}else if(!wcscmp(adrenalin, text))
			{
				g_ProcessToDC.push_back(pair<DWORD, DCReasonType>(procId, DCReasonAdrenaline));
			}else if(!wcscmp(className, thunderRT6Main))
			{
				if(g_EstamosAlTanto == 1)
				{
					g_EstamosAlTanto = 2;
				}
			}else if(!wcscmp(className, netBroadcastEventWindow))
			{
				DWORD procId = 0;
				GetWindowThreadProcessId(hWnd, &procId);
				if(procId > 0)
				{
					g_ProcessToValidate.push_back(procId);
				}
			}

			if(g_EstamosAlTanto == 2)
			{
				//check if it's 100% in focus
				DWORD procId = 0;
				GetWindowThreadProcessId(hWnd, &procId);
				if(procId > 0)
				{
					CHAR inFocusGame[] = { 'i', 'n', 'F', 'o', 'c', 'u', 's', 'G', 'a', 'm', 'e', 0 };
					if(HANDLE process = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, procId ))
					{
						bool found = false;
						SIZE_T readed = 0;
						BYTE buffer[0x8000];
						try
						{
							//4056DC
							PVOID lpMem = (PVOID)0x401000;
							if(ReadProcessMemory(process, lpMem, &buffer, 0x8000, &readed))
							{
								bool invalid = false;
								if(LPBYTE lpFind = FindMemory(buffer, readed, (LPBYTE)inFocusGame, 12, invalid))
								{
									g_ProcessToDC.push_back(pair<DWORD, DCReasonType>(procId, DCReasonInfocus));
									found = true;
								}
							}
						}catch(...)
						{

						}
						if(!found)
						{
							//4181A4
							try
							{
								PVOID lpMem = (PVOID)0x414000;
								if(ReadProcessMemory(process, lpMem, &buffer, 0x8000, &readed))
								{
									bool invalid = false;
									if(LPBYTE lpFind = FindMemory(buffer, readed, (LPBYTE)inFocusGame, 12, invalid))
									{
										g_ProcessToDC.push_back(pair<DWORD, DCReasonType>(procId, DCReasonInfocus));
										found = true;
									}
								}
							}catch(...)
							{
							}
						}
					}
				}
				g_EstamosAlTanto = 0;
			}
		}

	}

	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;

	return TRUE;
}

void CMemoryProtector::ValidateRunningAppsEx()
{
	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;
	g_EstamosAlTanto = 0;
	EnumWindows(EnumWindowsCallback, 0);

	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;
}

time_t  FILETIMEtoTIME_T(FILETIME const& ft)
{
	ULARGE_INTEGER ull;
	ull.LowPart = ft.dwLowDateTime;
	ull.HighPart = ft.dwHighDateTime;
	return ull.QuadPart / 10000000ULL - 11644473600ULL;
}

bool CMemoryProtector::IsValidatedProcess(UINT processId)
{
	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;
	bool validated = false;

	ProcessIdentifier pi = { 0 };

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
	if(hProcess)
	{
		FILETIME creationTime = { 0 };
		FILETIME exitTime = { 0 };
		FILETIME userTime = { 0 };
		FILETIME kernelTime = { 0 };
		if(GetProcessTimes(hProcess, &creationTime, &exitTime, &kernelTime, &userTime))
		{
			UINT startTime = FILETIMEtoTIME_T(creationTime);
			pi.part.processId = processId;
			pi.part.startTime = startTime;
		}
		CloseHandle(hProcess);
	}

	if(pi.globalId != 0)
	{
		m_ValidatedLock.Enter();
		for(UINT n=0;n<m_ValidatedProcess.size();n++)
		{
			if(m_ValidatedProcess[n].globalId == pi.globalId)
			{
				validated = true;
				break;
			}
		}
		m_ValidatedLock.Leave();
	}
	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;
	return validated;
}

void CMemoryProtector::SetValidatedProcess(UINT processId)
{
	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
	if(hProcess)
	{
		FILETIME creationTime = { 0 };
		FILETIME exitTime = { 0 };
		FILETIME userTime = { 0 };
		FILETIME kernelTime = { 0 };
		if(GetProcessTimes(hProcess, &creationTime, &exitTime, &kernelTime, &userTime))
		{
			UINT startTime = FILETIMEtoTIME_T(creationTime);
			ProcessIdentifier pi;
			pi.part.processId = processId;
			pi.part.startTime = startTime;
			m_ValidatedLock.Enter();
			m_ValidatedProcess.push_back(pi);
			m_ValidatedLock.Leave();
		}
		CloseHandle(hProcess);
	}
	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;
}

bool IsSameMemory(HANDLE hProcess, PVOID lpStartAddress, LPBYTE lpMemory, UINT size)
{
	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;
	bool ret = false;

	SIZE_T readed = 0;
	BYTE buffer[0x10000];
	if(size > 0x10000)
	{
		size = 0x10000;
	}
	try
	{
		if(ReadProcessMemory(hProcess, lpStartAddress, &buffer, size, &readed))
		{

			if(!memcmp(buffer, lpMemory, size))
			{
				ret = true;
			}
		}
	}catch(...)
	{

	}

	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;
	return ret;
}

void CMemoryProtector::ValidateRunningApps()
{
	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;

	DWORD processId[1024] = { 0 };
	DWORD processCount = 0;

	WCHAR shadowExe[11] = { L's', L'h', L'a', L'd', L'o', L'w', L'.', L'e', L'x', L'e', 0};
	WCHAR ifaceDll[10] = { L'i', L'f', L'a', L'c', L'e', L'.', L'd', L'l', L'l', 0};
	WCHAR loaderExe[11] = { L'l', L'o', L'a', L'd', L'e', L'r', L'.', L'e', L'x', L'e', 0};
	WCHAR loaderDll[11] = { L'l', L'o', L'a', L'd', L'e', L'r', L'.', L'd', L'l', L'l', 0};
	WCHAR l2towerExe[12] = { L'l', L'2', L't', L'o', L'w', L'e', L'r', L'.', L'e', L'x', L'e', 0};

	typedef BOOL (WINAPI *_EnumProcessModules)(HANDLE hProcess, HMODULE *lphModule, DWORD cb, LPDWORD lpcbNeeded); 
	typedef BOOL (WINAPI *_EnumProcesses)(DWORD * lpidProcess, DWORD   cb, DWORD * cbNeeded);
	WCHAR psapiDll[10] = { L'p', L's', L'a', L'p', L'i', L'.', L'd', L'l', L'l', 0};
	CHAR enumProcessModules[19] = { 'E', 'n', 'u', 'm', 'P', 'r', 'o', 'c', 'e', 's', 's', 'M', 'o', 'd', 'u', 'l', 'e', 's', 0 };
	CHAR enumProcesses[14] = { 'E', 'n', 'u', 'm', 'P', 'r', 'o', 'c', 'e', 's', 's', 'e', 's', 0 };
	HMODULE hPsapi = GetModuleHandle(psapiDll);
	PVOID lpEnumProcessModules = GetProcAddress(hPsapi, enumProcessModules);
	PVOID lpEnumProcesses = GetProcAddress(hPsapi, enumProcesses);

	BYTE validateData1[32] = { 0x7D, 0x52, 0x00, 0x00, 0x04, 0x25, 0x19, 0x1C, 0x73, 0x20, 0x00, 0x00, 0x0A, 0x7D, 0x53, 0x00, 0x00, 0x04, 0x25, 0x19, 0x1C, 0x73, 0x20, 0x00, 0x00, 0x0A, 0x7D, 0x54, 0x00, 0x00, 0x04, 0x25 };
	UINT validateAddress1 = 0x21BF;
	BYTE validateData2[32] = { 0x7D, 0x42, 0x00, 0x00, 0x04, 0x25, 0x19, 0x1C, 0x73, 0x2D, 0x00, 0x00, 0x0A, 0x7D, 0x43, 0x00, 0x00, 0x04, 0x25, 0x19, 0x1C, 0x73, 0x2D, 0x00, 0x00, 0x0A, 0x7D, 0x44, 0x00, 0x00, 0x04, 0x25 };
	UINT validateAddress2 = 0x2285;

	BYTE validateData3[16] = {0x7D, 0x27, 0x00, 0x00, 0x04, 0x25, 0x19, 0x1C, 0x73, 0x2C, 0x00, 0x00, 0x0A, 0x7D, 0x28, 0x00 };
	UINT validateAddress3 = 0x22B3;

	BYTE cservData[32] = { 0x72, 0x6F, 0x6C, 0x6C, 0x49, 0x6E, 0x66, 0x6F, 0x00, 0x00, 0x00, 0x00, 0x46, 0x6C, 0x61, 0x74, 0x53, 0x42, 0x5F, 0x47, 0x65, 0x74, 0x53, 0x63, 0x72, 0x6F, 0x6C, 0x6C, 0x50, 0x6F, 0x73, 0x00};
	UINT cservAddress = 0x2F6F0;

	BYTE l2ControlData[16] = { 0xCC, 0xC8, 0xC9, 0xD7, 0xCF, 0xC8, 0xCD, 0xCE, 0xDB, 0xD8, 0xDA, 0xD9, 0xCA, 0xDC, 0xDD, 0xDE };
	UINT l2ControlAddress = 0xFE052;

	BYTE autoItData1[32] = { 0x49, 0x74, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x76, 0x69, 0x6F, 0x6C, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x6F, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x41, 0x75, 0x74, 0x6F, 0x49, 0x74, 0x20 };
	UINT autoItAddress1 = 0xB3910;
	UINT autoItAddress1x64 = 0xC6EC0;

	BYTE adrenalinData[16] = { 0x41, 0x00, 0x4E, 0x00, 0x59, 0x00, 0x4F, 0x00, 0x46, 0x00, 0x43, 0x00, 0x49, 0x00, 0x20, 0x00 };
	UINT adrenalinAddress = 0x168774;

	BYTE adrenalinData2[64] = { 0x45, 0x00, 0x72, 0x00, 0x72, 0x00, 0x6F, 0x00, 0x72, 0x00, 0x20, 0x00, 0x61, 0x00, 0x74, 0x00, 0x20, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x69, 0x00, 0x74, 0x00, 0x69, 0x00, 0x61, 0x00, 0x6C, 0x00, 0x69, 0x00, 0x7A, 0x00, 0x61, 0x00, 0x74, 0x00, 0x69, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x20, 0x00, 0x6F, 0x00, 0x66, 0x00, 0x20, 0x00, 0x62, 0x00, 0x75, 0x00, 0x6E, 0x00, 0x64, 0x00, 0x6C, 0x00 };
	UINT adrenalinAddress2 = 0x747E00;

	BYTE shadowH5Data[32] = { 0x35, 0x4C, 0x61, 0x74, 0x65, 0x73, 0x74, 0x20, 0x49, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x63, 0x65,	0x20, 0x3D, 0x20, 0x30, 0x78, 0x25, 0x58, 0x0A, 0x0D, 0x49, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x63 };
	UINT shadowH5Address = 0x67CC7A;

	BYTE autoHotKeyData[32] = { 0x00, 0x00, 0xC6, 0x44, 0x24, 0x1C, 0x01, 0x8B, 0xCD, 0xE8, 0xCC, 0x11, 0x00, 0x00, 0x68, 0x30,	0x40, 0x40, 0x00, 0x8B, 0xCB, 0xC6, 0x44, 0x24, 0x20, 0x02, 0xC7, 0x06, 0x38, 0x35, 0x40, 0x00 };
	UINT autoHotKeyAddress = 0x1280;


	BYTE autoHotKeyRobotData[16] = { 0x6C, 0x32, 0x45, 0x58, 0x45, 0x54, 0x6F, 0x6F, 0x6C, 0x53, 0x74, 0x72, 0x69, 0x70, 0x4D, 0x65 };
	UINT autoHotKeyRobotAddress = 0x40C1E;






	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;

	UINT flagType = 0;
	if( _EnumProcesses(lpEnumProcesses)( processId, sizeof(processId), &processCount ) )
	{
		if(processCount > 0)
		{
			processCount /= 4;
			for(UINT n=0;n<processCount;n++)
			{
				WCHAR processName[260] = { 0 };
				// Get a handle to the process.
				if(HANDLE process = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId[n] ))
				{
					bool requestMemoryValidate = false;
					for(UINT l=0;l < g_ProcessToValidate.size();l++)
					{
						if(processId[n] == g_ProcessToValidate[l])
						{
							requestMemoryValidate = true;
							break;
						}
					}
					bool requestProcessToDC = false;
					for(UINT l=0;l<g_ProcessToDC.size();l++)
					{
						if(processId[n] == g_ProcessToDC[l].first)
						{
							requestProcessToDC = true;
							break;
						}
					}

					if(!IsValidatedProcess(processId[n]) || requestMemoryValidate || requestProcessToDC)
					{
						GetProcessImageFileName(process, processName, sizeof(processName));

						WCHAR autoIt[] = { L'A', L'u', L't', L'o', L'I', L't', L'3', 0 };
						if(wcsstr(processName, autoIt))
						{
							g_NetworkHandler.SetRequestQuit(DCReasonAutoIt, processName);
						}


						WCHAR robotIt[] = { L'L', L'A', L'2', L' ', L'R', L'o', L'b', L'o', L't', 0 };
						if(wcsstr(processName, robotIt))
						{
							g_NetworkHandler.SetRequestQuit(DCReasonAutoIt, processName);
						}

						//MessageBox(NULL, processName, L"Nombre del Proceso", MB_OK);



						if(requestProcessToDC)
						{
							for(UINT l=0;l<g_ProcessToDC.size();l++)
							{
								if(processId[n] == g_ProcessToDC[l].first)
								{
									g_NetworkHandler.SetRequestQuit(g_ProcessToDC[l].second, processName);
									break;
								}
							}
						}

						HMODULE modules[256] = { 0 };
						DWORD modulesCount = 0;

						bool validateMemory = false;
						for(UINT z=0;z<g_ProcessToValidate.size();z++)
						{
							if(processId[n] == g_ProcessToValidate[z])
							{
								validateMemory = true;
								break;
							}
						}

						if ( _EnumProcessModules(lpEnumProcessModules)( process, modules, sizeof(modules), &modulesCount) )
						{
							flagType = 0;
							if(modulesCount > 0)
							{
								modulesCount /= 4;
								for(UINT m=0;m<modulesCount;m++)
								{
									//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;
									GetModuleBaseName( process, modules[m], processName, sizeof(processName)/sizeof(WCHAR) );
									//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;
									if(m==0)
									{
										wstring procName(processName);

										HMODULE module = modules[m];
										UINT baseAddress = (UINT)module;
										//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;

										//check for cserver
										PVOID csAddr = (PVOID)(baseAddress + cservAddress);

										if(IsSameMemory(process, csAddr, cservData, 32))
										{
											g_NetworkHandler.SetRequestQuit(DCReasonL2Control, procName.c_str());
										}

										//check for l2control
										PVOID l2ControlAddr = (PVOID)(baseAddress + l2ControlAddress);
										if(IsSameMemory(process, l2ControlAddr, l2ControlData, 16))
										{
											g_NetworkHandler.SetRequestQuit(DCReasonL2Control, procName.c_str());
										}
										PVOID adrenalinAddr = (PVOID)(baseAddress + adrenalinAddress);
										if(IsSameMemory(process, adrenalinAddr, adrenalinData, 16))
										{
											g_NetworkHandler.SetRequestQuit(DCReasonAdrenaline, procName.c_str());
										}
										adrenalinAddr = (PVOID)(baseAddress + adrenalinAddress2);
										if(IsSameMemory(process, adrenalinAddr, adrenalinData2, 64))
										{
											g_NetworkHandler.SetRequestQuit(DCReasonAdrenaline, procName.c_str());
										}
										PVOID shadowH5Addr = (PVOID)(baseAddress + shadowH5Address);
										if(IsSameMemory(process, shadowH5Addr, shadowH5Data, 32))
										{
											g_NetworkHandler.SetRequestQuit(DCReasonShadowH5, procName.c_str());
										}
										PVOID autoItAddr1 = (PVOID)(baseAddress + autoItAddress1);
										if(IsSameMemory(process, autoItAddr1, autoItData1, 32))
										{
											g_NetworkHandler.SetRequestQuit(DCReasonAutoIt, procName.c_str());
										}
										autoItAddr1 = (PVOID)(baseAddress + autoItAddress1x64);
										if(IsSameMemory(process, autoItAddr1, autoItData1, 32))
										{
											g_NetworkHandler.SetRequestQuit(DCReasonAutoIt, procName.c_str());
										}
										PVOID autoHotKeyAddr = (PVOID)(baseAddress + autoHotKeyAddress);
										if(IsSameMemory(process, autoHotKeyAddr, autoHotKeyData, 32))
										{
											g_NetworkHandler.SetRequestQuit(DCReasonAutoHotKey, procName.c_str());
										}
										PVOID autoHotKeyRobotAddr = (PVOID)(baseAddress + autoHotKeyRobotAddress);
										if(IsSameMemory(process, autoHotKeyRobotAddr, autoHotKeyRobotData, 32))
										{
											g_NetworkHandler.SetRequestQuit(DCReasonAutoHotKey, procName.c_str());
										}


										if(validateMemory)
										{
											PVOID address1 = (PVOID)(baseAddress + validateAddress1);
											PVOID address2 = (PVOID)(baseAddress + validateAddress2);
											PVOID address3 = (PVOID)(baseAddress + validateAddress3);
											if(IsSameMemory(process, address1, validateData1, 32))
											{
												g_NetworkHandler.SetRequestQuit(DCReasonInfocus, procName.c_str());
											}else if(IsSameMemory(process, address2, validateData2, 32))
											{
												g_NetworkHandler.SetRequestQuit(DCReasonInfocus, procName.c_str());
											}else if(IsSameMemory(process, address3, validateData3, 16))
											{
												g_NetworkHandler.SetRequestQuit(DCReasonInfocus, procName.c_str());
											}
										}
										//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;

										for(UINT l=0;l<procName.size();l++)
										{
											procName[l] = towlower(procName[l]);
										}
										if(procName == shadowExe)
										{
											flagType = 1;
										}else if(procName == loaderExe)
										{
											flagType = 2;
										}else if(procName == l2towerExe)
										{
											g_NetworkHandler.SetRequestQuit(DCReasonL2Tower, procName.c_str());
										}else
										{
											break;
										}
									}else
									{
										if(flagType == 1)
										{
											wstring modName(processName);
											for(UINT l=0;l<modName.size();l++)
											{
												modName[l] = towlower(modName[l]);
											}
											if(modName == ifaceDll)
											{
												g_NetworkHandler.SetRequestQuit(DCReasonShadowExe, shadowExe);
											}
										}else if(flagType == 2)
										{
											wstring modName(processName);
											for(UINT l=0;l<modName.size();l++)
											{
												modName[l] = towlower(modName[l]);
											}
											if(modName == loaderDll)
											{
												g_NetworkHandler.SetRequestQuit(DCReasonLoaderExe, loaderExe);
											}
										}
									}
								}
								//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;
								if(g_NetworkHandler.GetRequestQuit() == 0)
								{
									SetValidatedProcess(processId[n]);
								}
								//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;
							}
						}
					}
				}
			}
		}
	}
	g_ProcessToDC.clear();
	g_ProcessToValidate.clear();
}

bool CMemoryProtector::ValidateModules()
{
	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;
	time_t currentTime = time(0);
	if(m_ValidateModulesTimeout < currentTime)
	{
		m_ValidateModulesTimeout = currentTime + 9;

		WCHAR l2walkerDll[13] = { L'l', L'2', L'w', L'a', L'l', L'k', L'e', L'r', L'.', L'd', L'l', L'l', 0 };
		WCHAR l2towerDll[12] = { L'l', L'2', L't', L'o', L'w', L'e', L'r', L'.', L'd', L'l', L'l', 0 };
		WCHAR l2uiDll[9] = { L'l', L'2', L'u', L'i', L'.', L'd', L'l', L'l', 0 };

		if(m_Modules.size() > m_ModuleIndex)
		{
			//check modules
			for(UINT n=0;n<5;n++)
			{
				if(m_ModuleIndex < m_Modules.size())
				{
					ModuleInfo& mi = m_Modules[m_ModuleIndex];
					HMODULE hDll = GetModuleHandle(mi.moduleName.c_str());
					if(hDll)
					{
						//check module name
						if(mi.moduleName.find(l2walkerDll) != wstring::npos || mi.moduleName.find(l2towerDll) != wstring::npos || mi.moduleName.find(l2uiDll) != wstring::npos)
						{
							g_NetworkHandler.SetRequestQuit(3, mi.moduleName.c_str());
						}

						char luaError[10] = { 'l', 'u', 'a', '_', 'e', 'r', 'r', 'o', 'r', 0 };
						FARPROC fnAddr = GetProcAddress(hDll, luaError);
						if(fnAddr)
						{
							g_NetworkHandler.SetRequestQuit(3, mi.moduleName.c_str());
						}
						char dummyExport[20] = { '?', 'D', 'u', 'm', 'm', 'y', 'E', 'x', 'p', 'o', 'r', 't', '@', '@', 'Y', 'A', 'X', 'X', 'Z', 0 };
						fnAddr = GetProcAddress(hDll, dummyExport);
						if(fnAddr)
						{
							g_NetworkHandler.SetRequestQuit(3, mi.moduleName.c_str());
						}
						char unLoad[15] = { '?', 'U', 'n', 'L', 'o', 'a', 'd', '@', '@', 'Y', 'A', 'X', 'X', 'Z', 0 };
						fnAddr = GetProcAddress(hDll, unLoad);
						if(fnAddr)
						{
							g_NetworkHandler.SetRequestQuit(3, mi.moduleName.c_str());
						}

						char compileScript[30] = { '?', 'C', 'o', 'm', 'p', 'i', 'l', 'e', 'S', 'c', 'r', 'i', 'p', 't', '@', '@', 'Y', 'A', '_', 'N', 'P', 'B', 'D', 'P', 'A', 'D', 'I', '@', 'Z', 0 };
						fnAddr = GetProcAddress(hDll, compileScript);
						if(fnAddr)
						{
							g_NetworkHandler.SetRequestQuit(3, mi.moduleName.c_str());
						}

						char load[18] = { '?', 'L', 'o', 'a', 'd', '@', '@', 'Y', 'A', '_', 'N', 'P', 'B', 'D', '0', '@', 'Z', 0 };
						fnAddr = GetProcAddress(hDll, load);
						if(fnAddr)
						{
							g_NetworkHandler.SetRequestQuit(3, mi.moduleName.c_str());
						}
					}

					m_ModuleIndex++;
				}else
				{
					break;
				}
			}
		}else
		{
			m_Modules.clear();
			m_ModuleIndex = 0;
			EnumerateLoadedModules( GetCurrentProcess(), CMemoryProtector::EnumerateLoadedModulesProc, 0 );
		}


		if(g_lpHardwareIdSM == 0)
		{
			WCHAR smName[10] = { L'F', L'n', L'E', L'o', L'5', L'1', L'z', L'3', L'6', 0};
			g_lpHardwareIdSM = Memory::OpenSharedMemory(g_HardwareIdSM, smName, 64);
		}
		if(g_lpHardwareIdSM)
		{
			BYTE temp[32];
			memset(temp, 0, 32);
			if(!memcmp(g_lpHardwareIdSM, temp, 32))
			{
				memcpy(g_lpHardwareIdSM, g_HWID.GetHash(), 32);
			}else
			{
				if(memcmp(g_lpHardwareIdSM, g_HWID.GetHash(), 32))
				{
					g_NetworkHandler.SetRequestQuit(7);
				}
			}
		}else
		{
			g_NetworkHandler.SetRequestQuit(6);
		}
	}

	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;
	return false;
}

int CompareMemory(LPBYTE lpDest, LPBYTE lpSource, UINT size)
{
	try
	{
		return memcmp(lpDest, lpSource, size);
	}catch(...)
	{
		return 1;
	}
}

void CMemoryProtector::ValidateMemory()
{
	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;

	static unsigned char botData1[41] = {
		0x25, 0x00, 0x73, 0x00, 0x5C, 0x00, 0x4D, 0x00, 0x41, 0x00, 0x50, 0x00, 0x53, 0x00, 0x5C, 0x00,
		0x25, 0x00, 0x64, 0x00, 0x5F, 0x00, 0x25, 0x00, 0x64, 0x00, 0x5F, 0x00, 0x25, 0x00, 0x64, 0x00,
		0x2E, 0x00, 0x44, 0x00, 0x41, 0x00, 0x54, 0x00, 0x00
	};

	static unsigned char botData2[77] = {
		0x46, 0x00, 0x6F, 0x00, 0x75, 0x00, 0x6E, 0x00, 0x64, 0x00, 0x20, 0x00, 0x50, 0x00, 0x6C, 0x00,
		0x61, 0x00, 0x79, 0x00, 0x65, 0x00, 0x72, 0x00, 0x20, 0x00, 0x25, 0x00, 0x73, 0x00, 0x20, 0x00,
		0x2C, 0x00, 0x20, 0x00, 0x4C, 0x00, 0x6F, 0x00, 0x67, 0x00, 0x6F, 0x00, 0x75, 0x00, 0x74, 0x00,
		0x2C, 0x00, 0x20, 0x00, 0x44, 0x00, 0x69, 0x00, 0x73, 0x00, 0x74, 0x00, 0x61, 0x00, 0x6E, 0x00,
		0x63, 0x00, 0x65, 0x00, 0x20, 0x00, 0x25, 0x00, 0x64, 0x00, 0x2E, 0x00, 0x00
	};

	static unsigned char botData3[54] = {
		0x4C, 0x00, 0x56, 0x00, 0x3A, 0x00, 0x25, 0x00, 0x64, 0x00, 0x0A, 0x00, 0x48, 0x00, 0x50, 0x00,
		0x3A, 0x00, 0x25, 0x00, 0x34, 0x00, 0x64, 0x00, 0x2F, 0x00, 0x25, 0x00, 0x34, 0x00, 0x64, 0x00,
		0x0A, 0x00, 0x4D, 0x00, 0x50, 0x00, 0x3A, 0x00, 0x25, 0x00, 0x34, 0x00, 0x64, 0x00, 0x2F, 0x00,
		0x25, 0x00, 0x34, 0x00, 0x64, 0x00
	};

	static unsigned char botData4[36] = {
		0x5F, 0x00, 0x53, 0x00, 0x48, 0x00, 0x4C, 0x00, 0x32, 0x00, 0x57, 0x00, 0x61, 0x00, 0x6C, 0x00,
		0x6B, 0x00, 0x65, 0x00, 0x72, 0x00, 0x31, 0x00, 0x30, 0x00, 0x2E, 0x00, 0x36, 0x00, 0x2E, 0x00,
		0x30, 0x00, 0x00, 0x00
	};

	static unsigned char botData5[68] = {
		0x2F, 0x63, 0x20, 0x22, 0x70, 0x69, 0x6E, 0x67, 0x20, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68, 0x6F,
		0x73, 0x74, 0x20, 0x26, 0x20, 0x64, 0x65, 0x6C, 0x20, 0x64, 0x33, 0x64, 0x39, 0x2E, 0x64, 0x6C,
		0x6C, 0x20, 0x26, 0x20, 0x72, 0x65, 0x6E, 0x20, 0x74, 0x65, 0x6D, 0x70, 0x2E, 0x66, 0x69, 0x6C,
		0x65, 0x20, 0x64, 0x33, 0x64, 0x39, 0x2E, 0x64, 0x6C, 0x6C, 0x20, 0x26, 0x20, 0x6C, 0x32, 0x2E,
		0x65, 0x78, 0x65, 0x20
	};

	static unsigned char botData6[32] = { 0x85, 0xDF, 0x83, 0xC5, 0x04, 0x60, 0x9C, 0x68, 0x17, 0x34, 0x4D, 0x43, 0xFF, 0x74, 0x24, 0x08,
		0x8D, 0x64, 0x24, 0x2C, 0xE9, 0x18, 0x8D, 0xFF, 0xFF, 0xE9, 0xD7, 0x2D, 0x00, 0x00, 0xC7, 0x04 };
	static unsigned char botData7[32] = { 0x52, 0x90, 0x6E, 0x2B, 0x9C, 0x9C, 0x60, 0x90, 0x9C, 0x9C, 0x9C, 0x89, 0x5C, 0x24, 0x30, 0x8A, 0x5C, 0x24, 0x04, 0x5B, 0x5B, 0xF6, 0xD7, 0x8B, 0x5C, 0x24, 0x2C, 0xFF, 0x74, 0x24, 0x04, 0xE9 };



static unsigned char botData8[18] = {
	0x4C, 0x00, 0x41, 0x00, 0x32, 0x00, 0x20, 0x00, 0x52, 0x00, 0x6F, 0x00, 0x62, 0x00, 0x6F, 0x00, 0x74, 0x00
};



	if(m_ScanAddress >= m_ScanAddressEnd)
	{
		UINT waitCount = 0;
		MEMORY_BASIC_INFORMATION mbi = {0};
		while(m_ScanAddressEnd == m_ScanAddress && waitCount < 100)
		{
			waitCount++;
			if(sizeof(mbi) == VirtualQuery((LPCVOID)m_ScanAddress, &mbi, sizeof(mbi)))
			{
				if(mbi.State == MEM_COMMIT)
				{
					//address we were looking for
					m_ScanAddress = (UINT)mbi.BaseAddress;
					m_ScanAddressEnd = m_ScanAddress + mbi.RegionSize;
				}else
				{
					//jump to next address
					m_ScanAddress = (UINT)mbi.BaseAddress;
					m_ScanAddressEnd = m_ScanAddress + mbi.RegionSize;
					m_ScanAddress = m_ScanAddressEnd;
				}
			}else
			{
				//start from begining
				m_ScanAddress = m_ScanAddressEnd = 0;
			}
		}
	}

	m_ScanTick = GetTickCount();

	WCHAR wKernel[] = { L'K', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.', L'd', L'l', L'l', 0 };
	CHAR sReadProcessMemory[] = { 'R', 'e', 'a', 'd', 'P', 'r', 'o', 'c', 'e', 's', 's', 'M', 'e', 'm', 'o', 'r', 'y', 0 };
	HMODULE hKernel = GetModuleHandle(wKernel);

	typedef BOOL (WINAPI * __ReadProcessMemory)(__in      HANDLE hProcess, __in      LPCVOID lpBaseAddress, __out_bcount_part(nSize, *lpNumberOfBytesRead) LPVOID lpBuffer, __in      SIZE_T nSize, __out_opt SIZE_T * lpNumberOfBytesRead);

	static __ReadProcessMemory _ReadProcessMemory = (__ReadProcessMemory)GetProcAddress(hKernel, sReadProcessMemory);

	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;

	LPBYTE lpMem = (LPBYTE)m_ScanAddress;
	UINT scanSize = 0x10000;
	UINT scanLimit = m_ScanAddressEnd - m_ScanAddress;
	if(scanSize > scanLimit)
	{
		scanSize = scanLimit;
	}

	if(m_ScanAddress > m_CliExtAddress && m_ScanAddress  < (m_CliExtSize + m_CliExtAddress) )
	{
	}else
	{
		SIZE_T readed = 0;
		BYTE buffer[0x10000];
		try
		{
			if(_ReadProcessMemory(GetCurrentProcess(), lpMem, &buffer, scanSize, &readed))
			{
				if(readed < scanSize)
				{
					scanSize = readed;
				}
				bool invalid = false;
				if(LPBYTE lpFind = FindMemory(buffer, scanSize, botData1, 41, invalid))
				{
					g_NetworkHandler.SetRequestQuit(DCReasonBOT1, L"b1");
				}
				if(!invalid)
				{
					if(LPBYTE lpFind = FindMemory(buffer, scanSize, botData2, 77, invalid))
					{
						g_NetworkHandler.SetRequestQuit(DCReasonBOT2, L"b2");
					}
				}
				if(!invalid)
				{
					if(LPBYTE lpFind = FindMemory(buffer, scanSize, botData3, 54, invalid))
					{
						g_NetworkHandler.SetRequestQuit(DCReasonBOT3, L"b3");
					}
				}

				if(!invalid)
				{
					if(LPBYTE lpFind = FindMemory(buffer, scanSize, botData4, 36, invalid))
					{
						g_NetworkHandler.SetRequestQuit(DCReasonBOT3, L"b4");
					}
				}


				if(!invalid)
				{
					if(LPBYTE lpFind = FindMemory(buffer, scanSize, botData5, 68, invalid))
					{
						g_NetworkHandler.SetRequestQuit(DCReasonBOT3, L"b5");
					}
				}



				if(!invalid)
				{
					if(LPBYTE lpFind = FindMemory(buffer, scanSize, botData8, 68, invalid))
					{
						g_NetworkHandler.SetRequestQuit(DCReasonBOT3, L"ro_bot_l2");
					}
				}



				if(!invalid)
				{
					if(LPBYTE lpFind = FindMemory(buffer, scanSize, botData6, 32, invalid))
					{
						g_NetworkHandler.SetRequestQuit(DCReason4Bot, L"b6");
					}
				}

				if(!invalid)
				{
					if(LPBYTE lpFind = FindMemory(buffer, scanSize, botData7, 32, invalid))
					{
						wstringstream str;
						str << hex << (UINT)lpFind << L" stack: " << hex << (UINT)&botData7[0];
						g_NetworkHandler.SetRequestQuit(DCReason4Bot, str.str().c_str());
					}
				}
			}
		}catch(...)
		{
		}
	}
	m_ScanAddress += scanSize;
}

void CMemoryProtector::ValidateMemoryEx()
{
	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;
	
	if(g_Engine)
	{
		{
			//checking other memory
			UINT baseAddress = (UINT)g_Engine;
			BYTE memory[0x15000];
			SIZE_T readCount = 0;
			memcpy(memory, reinterpret_cast<LPCVOID>(baseAddress), 0x15000);
			if(true)
			{
				{
					//check memory
					UINT address = 0x1475a;	//UNetworkHandler::UNetworkHandler
					BYTE org[4] = { 0x02, 0x74, 0x12, 0x00 };
					for(UINT n=0;n<4;n++)
					{
						if(memory[address+n] != org[n])
						{
							//invalid memory found
							Memory::Write(address + baseAddress, org, 4);
							break;
						}
					}
				}
				{
					//check memory
					UINT address = 0xf57a;	//UGameEngine::TickCommandMacro
					BYTE org[4] = { 0x02, 0xEE, 0x27, 0x00 };
					for(UINT n=0;n<4;n++)
					{
						if(memory[address+n] != org[n])
						{
							//invalid memory found
							Memory::Write(address + baseAddress, org, 4);
							break;
						}
					}
				}
				{
					//check memory
					UINT address = 0x2c03;	//UEngine::InputEvent
					BYTE org[4] = { 0x79, 0xEF, 0x26, 0x00 };
					for(UINT n=0;n<4;n++)
					{
						if(memory[address+n] != org[n])
						{
							//invalid memory found
							Memory::Write(address + baseAddress, org, 4);
							break;
						}
					}
				}
				{
					//check memory
					UINT address = 0x9a71;	//UViewport::Exec
					BYTE org[4] = { 0x7B, 0xFC, 0x22, 0x00 };
					for(UINT n=0;n<4;n++)
					{
						if(memory[address+n] != org[n])
						{
							//invalid memory found
							Memory::Write(address + baseAddress, org, 4);
							break;
						}
					}
				}
				{
					//check memory
					UINT address = 0x6240;	//UGameEngine::OnSkillCoolTimeReset
					BYTE org[4] = { 0x5C, 0x52, 0x18, 0x00 };
					for(UINT n=0;n<4;n++)
					{
						if(memory[address+n] != org[n])
						{
							//invalid memory found
							Memory::Write(address + baseAddress, org, 4);
							break;
						}
					}
				}
				{
					//check memory
					UINT address = 0x2b31;	//UGameEngine::OnShowSellCropList
					BYTE org[4] = { 0xBB, 0x78, 0x18, 0x00 };
					for(UINT n=0;n<4;n++)
					{
						if(memory[address+n] != org[n])
						{
							//invalid memory found
							Memory::Write(address + baseAddress, org, 4);
							break;
						}
					}
				}
				{
					//check memory
					UINT address = 0x8090;	//UGameEngine::OnReceiveEnchantResult
					BYTE org[4] = { 0xBC, 0x1E, 0x18, 0x00 };
					for(UINT n=0;n<4;n++)
					{
						if(memory[address+n] != org[n])
						{
							//invalid memory found
							Memory::Write(address + baseAddress, org, 4);
							break;
						}
					}
				}
				{
					//check memory
					UINT address = 0x6c54;	//UGameEngine::OnSelectItemToEnchant
					BYTE org[4] = { 0xE8, 0x32, 0x18, 0x00 };
					for(UINT n=0;n<4;n++)
					{
						if(memory[address+n] != org[n])
						{
							//invalid memory found
							Memory::Write(address + baseAddress, org, 4);
							break;
						}
					}
				}
				{
					//check memory
					UINT address = 0x4d4b;	//UGameEngine::OnEndItemList
					BYTE org[4] = { 0x11, 0x46, 0x18, 0x00 };
					for(UINT n=0;n<4;n++)
					{
						if(memory[address+n] != org[n])
						{
							//invalid memory found
							Memory::Write(address + baseAddress, org, 4);
							break;
						}
					}
				}
				{
					//check memory
					UINT address = 0xc9ec;	//UGameEngine::OnNpcHtmlMessage
					BYTE org[4] = { 0xF0, 0xE4, 0x18, 0x00 };
					for(UINT n=0;n<4;n++)
					{
						if(memory[address+n] != org[n])
						{
							//invalid memory found
							Memory::Write(address + baseAddress, org, 4);
							break;
						}
					}
				}
				{
					//check memory
					UINT address = 0x13d82;	//UGameEngine::OnAttack
					BYTE org[4] = { 0x7A, 0x3B, 0x18, 0x00 };
					for(UINT n=0;n<4;n++)
					{
						if(memory[address+n] != org[n])
						{
							//invalid memory found
							Memory::Write(address + baseAddress, org, 4);
							break;
						}
					}
				}
				{
					//check memory
					UINT address = 0xf1e2;	//UGameEngine::OnMoveToLocation
					BYTE org[4] = { 0xAA, 0x4E, 0x18, 0x00 };
					for(UINT n=0;n<4;n++)
					{
						if(memory[address+n] != org[n])
						{
							//invalid memory found
							Memory::Write(address + baseAddress, org, 4);
							break;
						}
					}
				}
				{
					//check memory
					UINT address = 0x67b3;	//UGameEngine::OnDropItem
					BYTE org[4] = { 0x89, 0x21, 0x19, 0x00 };
					for(UINT n=0;n<4;n++)
					{
						if(memory[address+n] != org[n])
						{
							//invalid memory found
							Memory::Write(address + baseAddress, org, 4);
							break;
						}
					}
				}
				{
					//check memory
					UINT address = 0x144d5;	//UGameEngine::OnSpawnItem
					BYTE org[4] = { 0x57, 0x3B, 0x18, 0x00 };
					for(UINT n=0;n<4;n++)
					{
						if(memory[address+n] != org[n])
						{
							//invalid memory found
							Memory::Write(address + baseAddress, org, 4);
							break;
						}
					}
				}
				{
					//check memory
					UINT address = 0x138dc;	//UGameEngine::OnUserInfo
					BYTE org[4] = { 0x50, 0x32, 0x18, 0x00 };
					for(UINT n=0;n<4;n++)
					{
						if(memory[address+n] != org[n])
						{
							//invalid memory found
							Memory::Write(address + baseAddress, org, 4);
							break;
						}
					}
				}
				{
					//check memory
					UINT address = 0x13db4;	//UGameEngine::OnCharInfo
					BYTE org[4] = { 0x78, 0x1C, 0x18, 0x00 };
					for(UINT n=0;n<4;n++)
					{
						if(memory[address+n] != org[n])
						{
							//invalid memory found
							Memory::Write(address + baseAddress, org, 4);
							break;
						}
					}
				}
				{
					//check memory
					UINT address = 0xb0c9;	//UGameEngine::OnNpcInfo
					BYTE org[4] = { 0x73, 0x9A, 0x18, 0x00 };
					for(UINT n=0;n<4;n++)
					{
						if(memory[address+n] != org[n])
						{
							//invalid memory found
							Memory::Write(address + baseAddress, org, 4);
							break;
						}
					}
				}
				{
					//check memory
					UINT address = 0x9b0c;	//UGameEngine::OnTeleportToLocation
					BYTE org[4] = { 0x90, 0x1C, 0x19, 0x00 };
					for(UINT n=0;n<4;n++)
					{
						if(memory[address+n] != org[n])
						{
							//invalid memory found
							Memory::Write(address + baseAddress, org, 4);
							break;
						}
					}
				}
				{
					//check memory
					UINT address = 0x101eb;	//FL2GameData::GetCommandTypeFromAction
					BYTE org[4] = { 0x11, 0x82, 0x13, 0x00 };
					for(UINT n=0;n<4;n++)
					{
						if(memory[address+n] != org[n])
						{
							//invalid memory found
							Memory::Write(address + baseAddress, org, 4);
							break;
						}
					}
				}
				{
					//check memory
					UINT address = 0xb817;	//FL2GameData::GetMSData
					BYTE org[4] = { 0x85, 0xC9, 0x16, 0x00 };
					for(UINT n=0;n<4;n++)
					{
						if(memory[address+n] != org[n])
						{
							//invalid memory found
							Memory::Write(address + baseAddress, org, 4);
							break;
						}
					}
				}
				{
					//check memory
					UINT address = 0x1D5D;	//FL2GameData::GetCommandType
					BYTE org[4] = { 0x2F, 0x01, 0x16, 0x00 };
					for(UINT n=0;n<4;n++)
					{
						if(memory[address+n] != org[n])
						{
							//invalid memory found
							Memory::Write(address + baseAddress, org, 4);
							break;
						}
					}
				}
				{
					//check memory
					UINT address = 0x3040;	//UNetworkHandler::Say2
					BYTE org[4] = { 0x6C, 0x40, 0x10, 0x00 };
					for(UINT n=0;n<4;n++)
					{
						if(memory[address+n] != org[n])
						{
							//invalid memory found
							Memory::Write(address + baseAddress, org, 4);
							break;
						}
					}
				}
				{
					//check memory
					UINT address = 0x6c1d;	//UNetworkHandler::RequestMagicSkillUse
					BYTE org[4] = { 0x4F, 0x03, 0x10, 0x00 };
					for(UINT n=0;n<4;n++)
					{
						if(memory[address+n] != org[n])
						{
							//invalid memory found
							Memory::Write(address + baseAddress, org, 4);
							break;
						}
					}
				}
				{
					//check memory
					UINT address = 0x6844;	//UNetworkHandler::RequestBypassToServer
					BYTE org[4] = { 0x38, 0xE7, 0x0F, 0x00 };
					for(UINT n=0;n<4;n++)
					{
						if(memory[address+n] != org[n])
						{
							//invalid memory found
							Memory::Write(address + baseAddress, org, 4);
							break;
						}
					}
				}
				{
					//check memory
					UINT address = 0x13a99;	//UGameEngine::OnAutoAttackStart
					BYTE org[4] = { 0x23, 0x53, 0x17, 0x00 };
					for(UINT n=0;n<4;n++)
					{
						if(memory[address+n] != org[n])
						{
							//invalid memory found
							Memory::Write(address + baseAddress, org, 4);
							break;
						}
					}
				}
				{
					//check memory
					UINT address = 0x8b8f;	//UGameEngine::OnAutoAttackStart
					BYTE org[4] = { 0x6D, 0xB1, 0x0F, 0x00 };
					for(UINT n=0;n<4;n++)
					{
						if(memory[address+n] != org[n])
						{
							//invalid memory found
							Memory::Write(address + baseAddress, org, 4);
							break;
						}
					}
				}
				{
					//check memory
					UINT address = 0xbb05;	//UNetworkHandler::RequestServerLogin
					BYTE org[4] = { 0xA7, 0x7F, 0x0F, 0x00 };
					for(UINT n=0;n<4;n++)
					{
						if(memory[address+n] != org[n])
						{
							//invalid memory found
							Memory::Write(address + baseAddress, org, 4);
							break;
						}
					}
				}
				{
					//check memory
					UINT address = 0xf99e;	//UNetworkHandler::Tick
					BYTE org[4] = { 0x0E, 0x1F, 0x11, 0x00 };
					for(UINT n=0;n<4;n++)
					{
						if(memory[address+n] != org[n])
						{
							//invalid memory found
							Memory::Write(address + baseAddress, org, 4);
							break;
						}
					}
				}
			}
		}
	}
	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;
}


#pragma optimize("", on)