#include "L2WindowNickname.h"
#include "Hook.h"

static DWORD WINAPI loadHook(LPVOID);

static Hook * pHookInitGameEngine = nullptr;
static wchar_t * playerName = nullptr;
static HWND pHwnd = nullptr;
static LPVOID wndProcOriginalHandler = nullptr;

static DWORD InitUGameEngine;
static DWORD OnUserInfo;
static DWORD GetName;

static void hInitUGameEngine();
static void hInitUGameEngineImpl(DWORD hInit_UGameEngine);

static void hOnUserInfo();
static void hOnUserInfoImpl(DWORD hUI_this, DWORD hUI_user);

__declspec(dllexport) void EmptyExport() {
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

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
	if(ul_reason_for_call == DLL_PROCESS_ATTACH) {
		CreateThread(nullptr, NULL, &loadHook, nullptr, 0, nullptr);
	} else if(ul_reason_for_call == DLL_PROCESS_DETACH) {
		if(wndProcOriginalHandler) {
			SetWindowLong(pHwnd, GWL_WNDPROC, reinterpret_cast<LONG>(wndProcOriginalHandler));
		}

		if(playerName) {
			delete[] playerName;
		}

		if (pHookInitGameEngine) {
			pHookInitGameEngine->Cancel();
			delete pHookInitGameEngine;
		}
	}

	return TRUE;
}

DWORD WINAPI loadHook(LPVOID) {
	if(!GetCfgBool("Game", "ChangeWndPlayerName", true)) {
		return 0;
	}

	HMODULE engine = nullptr;
	while ((engine = GetModuleHandleA("engine.dll")) == nullptr) {
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
