#include "stdafx.h"
#include "Hook.h"

#pragma region Clear functions
#ifdef HOOK_USE_CLEAR_FUNC

DWORD virtualProtectAdr = reinterpret_cast<DWORD>(::GetProcAddress(::LoadLibrary(L"kernel32.dll"), "VirtualProtect"));
BOOL _declspec(naked) WINAPI clearVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
	_asm {
		push ebp
		mov ebp, esp
		
		lea eax, virtualProtectAdr
		mov eax, DWORD PTR [eax]
		add eax, 5
		jmp eax
	}
}
#define VirtProtect(fAddr,size,pageAccess,oldProtect) clearVirtualProtect(fAddr,size,pageAccess,oldProtect)

DWORD readProcessMemoryAdr = reinterpret_cast<DWORD>(::GetProcAddress(::LoadLibrary(L"kernel32.dll"), "ReadProcessMemory"));
BOOL _declspec(naked) WINAPI clearReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesRead) {
	_asm {
		push ebp
		mov ebp, esp
		
		lea eax, readProcessMemoryAdr
		mov eax, DWORD PTR [eax]
		add eax, 5
		jmp eax
	}
}
#define ReadMem(fAddr,saved,size) clearReadProcessMemory(::GetCurrentProcess(), fAddr, saved, size, NULL)

#else
#define VirtProtect(fAddr,size,pageAccess,oldProtect) VirtualProtect(fAddr,size,pageAccess,oldProtect)
#define ReadMem(fAddr,saved,size) ReadProcessMemory(::GetCurrentProcess(), fAddr, saved, size, NULL)
#endif
#pragma endregion 

Hook::Hook(wstring const & dll, string const & func, LPVOID addr, bool allowRecalculate):
	dll(dll),
	func(func),
	addr(addr),
	hooked(false),
	flushCache(false)
{
	HMODULE library = ::GetModuleHandle(dll.c_str());
	if(!library) {
		library = ::LoadLibrary(dll.c_str());
	}

	fAddr = static_cast<LPVOID>(::GetProcAddress(library, func.c_str()));
	if(!fAddr) {
		::ExitProcess(0);
	}
	
	if(!ReadMem(fAddr, saved, 5)) {
		::ExitProcess(0);
	}

	if(allowRecalculate && saved[0] == 0xE9) { //always hooked or debug build for profiling application
		//read new address from JMP [ADDR]
		fAddr = reinterpret_cast<LPVOID>(reinterpret_cast<DWORD>(fAddr) + (*((DWORD*)&saved[1])) + 5);
		if(!ReadMem(fAddr, saved, 5)) {
			::ExitProcess(0);
		}
	}

	DWORD nearAddr = reinterpret_cast<DWORD>(addr) - reinterpret_cast<DWORD>(fAddr) - 5;
	jump[0] = 0xe9;
	memcpy(&jump[1], &nearAddr, 4);
}

Hook::Hook(wstring const & dll, string const & funcName, LPVOID func, LPVOID addr):
	dll(dll),
	func(funcName),
	addr(addr),
	fAddr(func),
	hooked(false),
	flushCache(false)
{
	if(!ReadMem(fAddr, saved, 5)) {
		::ExitProcess(0);
	}
	
	DWORD nearAddr = reinterpret_cast<DWORD>(addr) - reinterpret_cast<DWORD>(fAddr) - 5;
	jump[0] = 0xe9;
	memcpy(&jump[1], &nearAddr, 4);
}


Hook::~Hook()
{
	Cancel();
}

bool Hook::Apply()
{
	if(hooked) {
		return false;
	}
	hooked = true;

	return WriteProcMem(fAddr, jump, 5, flushCache);
}

bool Hook::Cancel()
{
	if(!hooked) {
		return false;
	}
	hooked = false;

	return WriteProcMem(fAddr, saved, 5, flushCache);
}

bool Hook::WriteProcMem(LPVOID fAddr, PBYTE raw, SIZE_T size, bool flushCache)
{
	DWORD oldProtect;
	
	if(!VirtProtect(fAddr, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		return false;
	}
	
	memcpy(fAddr, raw, size);

	if(!VirtProtect(fAddr, size, oldProtect, &oldProtect)) {
		return false;
	}

	if(flushCache) {
		::FlushInstructionCache(::GetCurrentProcess(), NULL, 0);
	}
	return true;
}
