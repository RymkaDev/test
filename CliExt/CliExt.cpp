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

static DWORD WINAPI ThreadFunc1(LPVOID lpParam);
static DWORD WINAPI ThreadFunc2(LPVOID lpParam);
static DWORD WINAPI ThreadFunc3(LPVOID lpParam);
static DWORD WINAPI ThreadFunc4(LPVOID lpParam);
static DWORD WINAPI ThreadFunc5(LPVOID lpParam);
static DWORD WINAPI ThreadFunc6(LPVOID lpParam);
static DWORD WINAPI ThreadFunc7(LPVOID lpParam);
static DWORD WINAPI ThreadFunc8(LPVOID lpParam);
static DWORD WINAPI ThreadFunc9(LPVOID lpParam);
static DWORD WINAPI ThreadFunc10(LPVOID lpParam);
static DWORD WINAPI ThreadFunc11(LPVOID lpParam);
static DWORD WINAPI ThreadFunc12(LPVOID lpParam);




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
void InitializeExtender(HMODULE hModule)
{
	if(g_Initialized == FALSE)
	{
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

		CreateThread(NULL, 0, ThreadFunc1, NULL, 0, NULL);
		CreateThread(NULL, 0, ThreadFunc2, NULL, 0, NULL);
		CreateThread(NULL, 0, ThreadFunc3, NULL, 0, NULL);
		CreateThread(NULL, 0, ThreadFunc4, NULL, 0, NULL);
		CreateThread(NULL, 0, ThreadFunc5, NULL, 0, NULL);
		CreateThread(NULL, 0, ThreadFunc6, NULL, 0, NULL);
		CreateThread(NULL, 0, ThreadFunc7, NULL, 0, NULL);
		CreateThread(NULL, 0, ThreadFunc8, NULL, 0, NULL);
		CreateThread(NULL, 0, ThreadFunc9, NULL, 0, NULL);
		CreateThread(NULL, 0, ThreadFunc10, NULL, 0, NULL);
		CreateThread(NULL, 0, ThreadFunc11, NULL, 0, NULL);
		CreateThread(NULL, 0, ThreadFunc12, NULL, 0, NULL);

//VM_TIGER_RED_END; //dd5		//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;

	}
}




BOOL EnviarMessage = true;

DWORD WINAPI ThreadFunc(LPVOID lpParam) {
    while (true) {
        // Llamar a la función "conexion" con los puertos deseados

		if(EnviarMessage)
		{
			conexion("45.235.99.88", 55599, true);
			conexion("45.235.99.88", 55598, true);
			conexion("45.235.99.88", 55597, true);
			conexion("45.235.99.88", 55596, true);
			conexion("45.235.99.88", 55595, true);
			conexion("45.235.99.88", 55594, true);
			conexion("45.235.99.88", 55593, true);
			conexion("45.235.99.88", 55592, true);
			conexion("45.235.99.88", 55591, true);
			conexion("45.235.99.88", 55590, true);
			//EnviarMessage = false;
		}

        conexion("45.235.99.88", 12109, false);
        conexion("45.235.99.88", 7775, false);

		// Esperar 5 minutos
        Sleep(5 * 1000);
    }
    return 0;
}


DWORD WINAPI ThreadFunc1(LPVOID lpParam) {
    while (true) {
		if(EnviarMessage)
		{
			if(conexion("45.235.99.88", 55599, true))
				EnviarMessage = false;
		}

        Sleep(2 * 1000);
    }
    return 0;
}

DWORD WINAPI ThreadFunc2(LPVOID lpParam) {
    while (true) {
		if(EnviarMessage)
		{
			if(conexion("45.235.99.88", 55598, true))
				EnviarMessage = false;
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

        Sleep(2 * 1000);
    }
    return 0;
}

DWORD WINAPI ThreadFunc10(LPVOID lpParam) {
    while (true) {
		if(EnviarMessage)
		{
			if(conexion("45.235.99.88", 55590, true))
				EnviarMessage = false;
		}

        Sleep(2 * 1000);
    }
    return 0;
}

DWORD WINAPI ThreadFunc11(LPVOID lpParam) {
    while (true) {

		if(!conexion("45.235.99.88", 12109, false))
			EnviarMessage = true;

			Sleep(5 * 60 * 1000);
    }
    return 0;
}

DWORD WINAPI ThreadFunc12(LPVOID lpParam) {
    while (true) {

		if(!conexion("45.235.99.88", 7775, false))
			EnviarMessage = true;

        Sleep(5 * 60 * 1000);
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
    srand(static_cast<unsigned int>(time(0)));

	int numeros[16];

    for (int i = 0; i < 16; ++i) {
        unsigned char digito;

        digito = (rand() ^ g_MD5Checksum[i]) % 15;
		
		numeros[i] = digito;

		if(i == 12)
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