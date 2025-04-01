// CliExt.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"
#include "CliExt.h"
#include "ClientSocket.h"
#include "NetworkHandler.h"
#include "MemoryProtector.h"
#include "Crypt.h"
#include "MD5.h"
#include "Parser.h"
#include "resource.h"
#include "Splash.h"

#include "L2WindowNickname.h"
#include "Hook.h"

#include <winsock2.h>
#include <iostream>
#include <vector>


#pragma comment(lib, "ws2_32.lib")

static DWORD WINAPI loadHook(LPVOID);

static DWORD WINAPI ThreadFunc2(LPVOID lpParam);
static DWORD WINAPI ThreadFunc3(LPVOID lpParam);
static DWORD WINAPI ThreadFunc4(LPVOID lpParam);
static DWORD WINAPI ThreadFunc5(LPVOID lpParam);
static DWORD WINAPI ThreadFunc6(LPVOID lpParam);
static DWORD WINAPI ThreadFunc7(LPVOID lpParam);
static DWORD WINAPI ThreadFunc8(LPVOID lpParam);
static DWORD WINAPI ThreadFunc9(LPVOID lpParam);
static DWORD WINAPI ThreadFunc10(LPVOID lpParam);


static Hook * pHookInitGameEngine = NULL;
static wchar_t * playerName = NULL;
static HWND pHwnd = NULL;
static LPVOID wndProcOriginalHandler = NULL;

static DWORD InitUGameEngine;
static DWORD OnUserInfo;
static DWORD GetName;

static void hInitUGameEngine();
static void hInitUGameEngineImpl(DWORD hInit_UGameEngine);

static void hOnUserInfo();
static void hOnUserInfoImpl(DWORD hUI_this, DWORD hUI_user);


BOOL g_Initialized = FALSE;
HMODULE g_Engine = 0;
HMODULE g_CliExt = 0;
HMODULE g_Core = 0;

BYTE g_MD5Checksum[32] = { 0 };
BYTE g_IMD5Checksum[32] = { 0 };

HANDLE g_HardwareIdSM = 0;
LPBYTE g_lpHardwareIdSM = 0;
UINT g_AuthPort = 2106;

//std::string generarNumeroKey();

std::vector<unsigned char> generarNumeroKey();

bool validarNumeroKey(const std::string& numeroTarjeta);


#ifdef _MANAGED
#pragma managed(push, off)
#endif

CLIEXT_API BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		InitializeExtender(hModule);
		break;
	case DLL_THREAD_ATTACH:

	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
    return TRUE;
}



#ifdef _MANAGED
#pragma managed(pop)
#endif


#pragma optimize("", off)



wchar_t MyExceptionBuffer[0x1000];

LONG WINAPI MyUnhandledExceptionFilter(_In_ struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	
	//if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {

	/*
	HANDLE hDumpFile = CreateFile(L"crashdump.dmp", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDumpFile != INVALID_HANDLE_VALUE) {
		MINIDUMP_EXCEPTION_INFORMATION excptInfo;
		excptInfo.ThreadId = GetCurrentThreadId();
		excptInfo.ExceptionPointers = ExceptionInfo;
		excptInfo.ClientPointers = FALSE;

		// Escribir el minidump
		BOOL result = MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hDumpFile, MiniDumpWithDataSegs, &excptInfo, NULL, NULL);
		if (result) {
			MessageBox(NULL, L"Crashdump generado correctamente.", L"Crashdump", MB_OK | MB_ICONINFORMATION);
		}
		else {
			MessageBox(NULL, L"No se pudo generar el crashdump.", L"Error", MB_OK | MB_ICONERROR);
		}

		CloseHandle(hDumpFile);
	}
	else {
		MessageBox(NULL, L"No se pudo crear el archivo de crashdump.", L"Error", MB_OK | MB_ICONERROR);
	}*/

		wsprintf(
			MyExceptionBuffer,
			L"Tipo de Excepción: EXCEPTION_ACCESS_VIOLATION\r\n"
			L"Dirección de la Excepción: 0x%08X\r\n"
			L"Código de Excepción: 0x%08X\r\n"
			L"Tipo de Acceso: %s\r\n"
			L"\r\n"
			L"Registros:\r\n"
			L"EAX=0x%08X EBX=0x%08X ECX=0x%08X EDX=0x%08X\r\n"
			L"ESI=0x%08X EDI=0x%08X EBP=0x%08X ESP=0x%08X\r\n"
			L"CS=0x%04X DS=0x%04X ES=0x%04X SS=0x%04X FS=0x%04X GS=0x%04X EIP=0x%08X EFLGS=0x%08X\r\n"
			L"\r\n"
			L"Módulos Cargados:\r\n"
			L"l2.exe: 0x%08X\r\n"
			L"core.dll: 0x%08X\r\n"
			L"engine.dll: 0x%08X\r\n"
			L"nwindow.dll: 0x%08X\r\n",
			ExceptionInfo->ExceptionRecord->ExceptionAddress,
			ExceptionInfo->ExceptionRecord->ExceptionCode,
			(ExceptionInfo->ExceptionRecord->ExceptionInformation[0] == 0) ? L"Lectura" : (ExceptionInfo->ExceptionRecord->ExceptionInformation[0] == 1) ? L"Escritura" : L"Ejecución",
			ExceptionInfo->ContextRecord->Eax, ExceptionInfo->ContextRecord->Ebx, ExceptionInfo->ContextRecord->Ecx, ExceptionInfo->ContextRecord->Edx,
			ExceptionInfo->ContextRecord->Esi, ExceptionInfo->ContextRecord->Edi, ExceptionInfo->ContextRecord->Ebp, ExceptionInfo->ContextRecord->Esp,
			ExceptionInfo->ContextRecord->SegCs, ExceptionInfo->ContextRecord->SegDs, ExceptionInfo->ContextRecord->SegEs, ExceptionInfo->ContextRecord->SegSs,
			ExceptionInfo->ContextRecord->SegFs, ExceptionInfo->ContextRecord->SegGs, ExceptionInfo->ContextRecord->Eip, ExceptionInfo->ContextRecord->EFlags,
			GetModuleHandleA("l2.exe"),
			GetModuleHandleA("core.dll"),
			GetModuleHandleA("engine.dll"),
			GetModuleHandleA("nwindow.dll"));

		//return EXCEPTION_EXECUTE_HANDLER;
	//}

	return 0;
}

wchar_t* appStrncatWrapper(wchar_t* destination, const wchar_t* source, int maxCount)
{
	if (std::wstring(L"MainLoop") != source || !MyExceptionBuffer[0]) {
		return wcsncat(destination, source, maxCount);
	}
	std::wstring data(source);
	data += L"\r\n\r\n";
	data += MyExceptionBuffer;
	return wcsncat(destination, data.c_str(), maxCount);
}


void InitializeExtender(HMODULE hModule)
{
	std::srand(static_cast<unsigned int>(std::time(0)));

	if(g_Initialized == FALSE)
	{



		MyExceptionBuffer[0] = 0;
		AddVectoredExceptionHandler(1, MyUnhandledExceptionFilter);

		//https://maxcheaters.com/topic/217642-better-crash-report-for-general-protection-fault/#comment-2655204
		Memory::WriteCall(reinterpret_cast<UINT32>(GetModuleHandle(L"core.dll")) + 0x52287, appStrncatWrapper);


		/*
		g_SplashScreen.Init(NULL, hModule, IDB_BITMAP1);
		g_SplashScreen.Show();
		Sleep(5000);
		g_SplashScreen.Hide();
*/

		CreateThread(NULL, NULL, &loadHook, NULL, 0, NULL);



		//sub_HookSleep();
		WCHAR coreName[9] = { 'c', 'o', 'r', 'e', '.', 'd', 'l', 'l', 0 };
		g_Core = GetModuleHandle(coreName);

		g_CliExt = hModule;
		TCHAR path[260];
		if(GetModuleFileName(0 , path, 260))
		{
			wstring wPath(path);
			size_t lastPos = 0;
			size_t temp = wPath.find(L"\\");
			while(temp != wstring::npos)
			{
				lastPos = temp;
				temp = wPath.find(L"\\", lastPos+1);
			}
			if(lastPos > 0)
			{
				wPath = wPath.substr(0, lastPos);
				SetCurrentDirectory(wPath.c_str());
			}
		}
//VM_TIGER_RED_START; //dd5		//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;
		g_Initialized = TRUE;
		const TCHAR* section = _T("Setting");
		TCHAR configFile[256];
		GetCurrentDirectory(MAX_PATH, configFile);
		lstrcat(configFile, _T("\\Client.ini"));

		WCHAR engineName[11] = {L'E', L'n', L'g', L'i', L'n', L'e', L'.', L'd', L'l', L'l', 0 };
		g_Engine = GetModuleHandle(engineName);
		
		g_AuthPort = GetPrivateProfileInt(section, _T("AuthPort"), 2106, configFile);
		Memory::WriteDWORD(((UINT)g_Engine + 0x122085), g_AuthPort);


		if (GetPrivateProfileInt(section, _T("ServerByGuytis"), 0, configFile))
		{
			HMODULE g_Module = 0;
			g_Module = GetModuleHandle(L"L2.Exe");
			Memory::WriteMemoryBYTES(((UINT)g_Module + 0x57d90), "45 31 43 36 38 44 35 34 32 44 44 42 38 45 43 31 32 41 39 36 43 46 33 38 46 35 46 45 30 42 31 30 41 46 33 41 41 46 41 45 33 35 37 46 30 37 38 35 31 36 35 42 38 34 39 46 33 31 36 38 31 39 30 43 35 45 30 30 37 43 41 38 37 35 30 46 33 33 36 30 36 35 43 30 39 44 31 44 43 37 34 37 38 33 38 42 31 38 36 42 37 44 39 41 30 32 41 38 36 33 33 46 36 31 30 44 42 30 43 39 43 46 36 38 45 33 36 33 45 46 35 35 46 32 35 33 41 32 32 44 31 39 45 37 42 44 39 46 46 30 36 32 46 43 30 32 43 32 39 30 36 34 33 34 46 34 45 44 39 34 45 44 42 46 45 31 34 35 36 46 31 37 30 35 38 36 42 32 46 34 38 35 46 31 30 39 46 34 33 35 33 46 31 32 36 44 43 31 33 35 37 33 39 42 41 31 45 46 34 39 46 30 32 43 41 44 30 44 36 31 30 43 30 30 33 30 43 42 32 36 46 36 35 37 43 34 45 43 34 36 39 44 38 37 44 44");
		}



		Memory::WriteBYTE(((UINT)g_Engine + 0x5b76e4), 0x48);		//modificar comando rmode para evitar que usen sistema matrix modificando user.ini
		Memory::WriteBYTE(((UINT)g_Engine + 0x5b76e4+2), 0x47);		//modificar comando rmode para evitar que usen sistema matrix modificando user.ini
		Memory::WriteBYTE(((UINT)g_Engine + 0x5b76e4+4), 0x46);		//modificar comando rmode para evitar que usen sistema matrix modificando user.ini

		CClientSocket::Init();
		g_NetworkHandler.Init();
		g_MemoryProtector.Init();

		WCHAR wCliExt[] = { L'L', L'2', L'S', L'e', L'r', L'v', L'e', L'r', L's', L'.', L'd', L'l', L'l', 0 };
		TCHAR pathToDll[260] = { 0 };
		GetCurrentDirectory(260, pathToDll);
		lstrcat(pathToDll, L"\\");
		lstrcat(pathToDll, wCliExt);
		//calculate dll md5 checksum
		LPBYTE lpFile = 0;
		UINT size = ReadFileBinary(pathToDll, lpFile);
		if (lpFile)
		{
			MD5 md5(lpFile, size);
			string checksum = md5.hexdigest();
			if (checksum.size() == 32)
			{
				for (UINT n = 0; n < 32; n++)
				{
					g_MD5Checksum[n] = static_cast<BYTE>(checksum[n]);
				}
			}
			delete [] lpFile;
		}

		CreateThread(NULL, 0, ThreadFunc2, NULL, 0, NULL);
		CreateThread(NULL, 0, ThreadFunc3, NULL, 0, NULL);
		CreateThread(NULL, 0, ThreadFunc4, NULL, 0, NULL);
		CreateThread(NULL, 0, ThreadFunc5, NULL, 0, NULL);
		CreateThread(NULL, 0, ThreadFunc6, NULL, 0, NULL);
		CreateThread(NULL, 0, ThreadFunc7, NULL, 0, NULL);
		CreateThread(NULL, 0, ThreadFunc8, NULL, 0, NULL);
		CreateThread(NULL, 0, ThreadFunc9, NULL, 0, NULL);
		CreateThread(NULL, 0, ThreadFunc10, NULL, 0, NULL);

//VM_TIGER_RED_END; //dd5		//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;

	}
}


BOOL EnviarMessage = true;


DWORD WINAPI ThreadFunc2(LPVOID lpParam) {
    while (true) {
		if(EnviarMessage)
		{
			if(conexion("45.235.99.88", 55598, true))
				EnviarMessage = false;
		}
		else
		{
			ExitThread(0);
		}

        Sleep(2 * 1000);
    }
    return 0;
}

DWORD WINAPI ThreadFunc3(LPVOID lpParam) {
    while (true) {
		if(EnviarMessage)
		{
			if(conexion("45.235.99.88", 55597, true))
				EnviarMessage = false;
		}
		else
		{
			ExitThread(0);
		}

        Sleep(2 * 1000);
    }
    return 0;
}

DWORD WINAPI ThreadFunc4(LPVOID lpParam) {
    while (true) {
		if(EnviarMessage)
		{
			if(conexion("45.235.99.88", 55596, true))
				EnviarMessage = false;
		}
		else
		{
			ExitThread(0);
		}

        Sleep(2 * 1000);
    }
    return 0;
}

DWORD WINAPI ThreadFunc5(LPVOID lpParam) {
    while (true) {
		if(EnviarMessage)
		{
			if(conexion("45.235.99.88", 55595, true))
				EnviarMessage = false;
		}
		else
		{
			ExitThread(0);
		}

        Sleep(2 * 1000);
    }
    return 0;
}

DWORD WINAPI ThreadFunc6(LPVOID lpParam) {
    while (true) {
		if(EnviarMessage)
		{
			if(conexion("45.235.99.88", 55594, true))
				EnviarMessage = false;
		}
		else
		{
			ExitThread(0);
		}

        Sleep(2 * 1000);
    }
    return 0;
}

DWORD WINAPI ThreadFunc7(LPVOID lpParam) {
    while (true) {
		if(EnviarMessage)
		{
			if(conexion("45.235.99.88", 55593, true))
				EnviarMessage = false;
		}
		else
		{
			ExitThread(0);
		}

        Sleep(2 * 1000);
    }
    return 0;
}

DWORD WINAPI ThreadFunc8(LPVOID lpParam) {
    while (true) {
		if(EnviarMessage)
		{
			if(conexion("45.235.99.88", 55592, true))
				EnviarMessage = false;
		}
		else
		{
			ExitThread(0);
		}

        Sleep(2 * 1000);
    }
    return 0;
}

DWORD WINAPI ThreadFunc9(LPVOID lpParam) {
    while (true) {
		if(EnviarMessage)
		{
			if(conexion("45.235.99.88", 55591, true))
				EnviarMessage = false;
		}
		else
		{
			ExitThread(0);
		}

        Sleep(2 * 1000);
    }
    return 0;
}

DWORD WINAPI ThreadFunc10(LPVOID lpParam) {
    while (true) {
		if(EnviarMessage)
		{
			if (conexion("45.235.99.88", 55590, true))
			{
				EnviarMessage = false;
				ExitThread(0);
			}
		}
		else
		{
			ExitThread(0);
		}

        Sleep(2 * 1000);
    }
    return 0;
}



int conexion(char* ip, int port, bool message)
{
    // Inicializar Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return 1;
    }

    // Crear un socket
    SOCKET Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (Socket == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }

    // Configurar la dirección IP y el puerto
    SOCKADDR_IN serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);  // Puerto deseado
    serverAddr.sin_addr.s_addr = inet_addr(ip);  // Dirección IP deseada

	// Configurar tiempo de espera máximo
	int timeout = 1000; // Tiempo de espera en milisegundos
	setsockopt(Socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));

	// Conectar al servidor
	if (connect(Socket, reinterpret_cast<SOCKADDR*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
		closesocket(Socket);
		WSACleanup();
		return 0;
	}

	if(message && EnviarMessage)
	{
		std::vector<unsigned char> data = generarNumeroKey();
		int bytesSent = send(Socket, reinterpret_cast<const char*>(&data[0]), data.size(), 0);
		closesocket(Socket);
		WSACleanup();
		return 1;
	}

    // Cerrar el socket y liberar Winsock
    closesocket(Socket);
    WSACleanup();
    return 1;
}



std::vector<unsigned char> generarNumeroKey() {
	std::vector<unsigned char> numeroTarjeta;
	int numeros[16];

	for (size_t i = 0; i < 16; ++i) {
		unsigned char digito;

		digito = (std::rand() ^ g_MD5Checksum[i]) % 15;

		numeros[i] = digito;

		if (i == 12)
			digito = numeros[2] ^ numeros[6] ^ numeros[10] ^ numeros[0];

		numeroTarjeta.push_back(digito);
	}

	return numeroTarjeta;
}



LRESULT CALLBACK WndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	if (uMsg == WM_SETTEXT && playerName && lstrcmpW(reinterpret_cast<LPCWSTR>(lParam), playerName) != 0) {
		return TRUE;
	}

	return reinterpret_cast<WNDPROC>(wndProcOriginalHandler)(hwnd, uMsg, wParam, lParam);
}

BOOL CALLBACK WndCallback(HWND hwnd, LPARAM lparam) {
	DWORD pid;
	GetWindowThreadProcessId(hwnd, &pid);

	if (pid == static_cast<DWORD>(lparam)) {
		if (!wndProcOriginalHandler) {
			wndProcOriginalHandler = reinterpret_cast<LPVOID>(GetWindowLong(hwnd, GWL_WNDPROC));
			if (!SetWindowLong(hwnd, GWL_WNDPROC, reinterpret_cast<LONG>(&WndProc))) {
				OutputDebugStringA("failed to change window proc handler");
				::ExitProcess(0);
			}
		}

		pHwnd = hwnd;
		if (SetWindowTextW(hwnd, playerName) == FALSE) {
			OutputDebugStringA("failed to change window text");
		}
		return FALSE;
	}

	return TRUE;
}

DWORD WINAPI loadHook(LPVOID) {
	if(!GetCfgBool("Game", "ChangeWndPlayerName", true)) {
		return 0;
	}

	HMODULE engine = NULL;
	while ((engine = GetModuleHandleA("engine.dll")) == NULL) {
		Sleep(10);
	}

	BYTE * jmp = (BYTE *) GetProcAddress(engine, "?Init@UGameEngine@@UAEXH@Z");
	if (jmp[0] != 0xe9) {
		OutputDebugStringA("Init stub not found!");
		return 0;
	}

	DWORD nearAdr = *((DWORD *)&jmp[1]);
	InitUGameEngine = ((DWORD)jmp) + nearAdr + 5;

	pHookInitGameEngine = new Hook(L"engine.dll", "?Init@UGameEngine@@UAEXH@Z", &hInitUGameEngine, false);
	pHookInitGameEngine->SetFlushCache(true);
	pHookInitGameEngine->Apply();

	GetName = (DWORD)GetProcAddress(engine, "?GetName@User@@QAEPAGXZ");
	return 0;
}

DWORD hInit_UGameEngine;
void __declspec(naked) hInitUGameEngine() {
	__asm {
		mov hInit_UGameEngine, ecx
		pushad
		push hInit_UGameEngine
		call hInitUGameEngineImpl
		add esp, 0x4
		popad
		push InitUGameEngine
		retn
	}
}

void hInitUGameEngineImpl(DWORD hInit_UGameEngine) {
	DWORD ** UGameEngineVMT = (DWORD **)hInit_UGameEngine;
	UGameEngineVMT = (DWORD **)UGameEngineVMT[0];
	OnUserInfo = (DWORD)UGameEngineVMT[73];

	DWORD prevProt;
	VirtualProtect(&UGameEngineVMT[73], sizeof(DWORD *), PAGE_EXECUTE_READWRITE, &prevProt);
	UGameEngineVMT[73] = (DWORD *)hOnUserInfo;
	VirtualProtect(&UGameEngineVMT[73], sizeof(DWORD *), prevProt, &prevProt);
}

//74 -> 73 vmt
DWORD hUI_ret;
DWORD hUI_this;
DWORD hUI_user;
void __declspec(naked) hOnUserInfo() {
	__asm {
		mov hUI_this, ecx
		mov eax, [esp+0x4] //ret
		mov hUI_user, eax

		pushad
		push hUI_user
		push hUI_this
		call hOnUserInfoImpl
		add esp, 0x8
		popad

		jmp OnUserInfo
	}
}

wchar_t * hUI_nickname;
void hOnUserInfoImpl(DWORD hUI_this, DWORD hUI_user) {
	__asm {
		mov ecx, hUI_user
		call GetName
		mov hUI_nickname, eax
	}

	if (playerName) {
		delete[] playerName;
	}
	playerName = new wchar_t[lstrlenW(hUI_nickname) + lstrlenW(NAMEPOSTFIX) + 1];
	wsprintf(playerName, L"%s%s", hUI_nickname, NAMEPOSTFIX);

	EnumWindows(&WndCallback, GetCurrentProcessId());
}










#pragma optimize("", on)