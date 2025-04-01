#include "Utils.h"



void NOPMemory(INT32 Address, INT32 len)
{
	BYTE Byte = 0x90;
	DWORD OLDPROTECT;
	SIZE_T BW;
	HANDLE Server = OpenProcess(MAXIMUM_ALLOWED, false, GetCurrentProcessId());		//con este funciona en el server 2003
	//HANDLE Server = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_VM_READ | PROCESS_VM_WRITE, false, GetCurrentProcessId());
	if ( Server )
	{
		for ( int i = 0 ; i < len ; i++ )
		{
			INT32 ADDR = Address+i;
			VirtualProtectEx(Server, (LPVOID)ADDR, 1, PAGE_WRITECOPY, &OLDPROTECT);
			WriteProcessMemory(Server,(LPVOID)ADDR,&Byte,1,&BW);
			VirtualProtectEx(Server, (LPVOID)ADDR, 1, OLDPROTECT, &OLDPROTECT);
		}
	}
	CloseHandle(Server);
}



void Utils::WriteMemoryBYTES(DWORD Address, VOID *bytes, int len)
{
	DWORD OLDPROTECT;
	SIZE_T BW;
	HANDLE Server = OpenProcess(MAXIMUM_ALLOWED, false, GetCurrentProcessId());		//con este funciona en el server 2003
	//HANDLE Server = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_VM_READ | PROCESS_VM_WRITE, false, GetCurrentProcessId());
	if ( Server )
	{
		VirtualProtectEx(Server, (LPVOID)Address, len, PAGE_WRITECOPY, &OLDPROTECT);
		WriteProcessMemory(Server,(LPVOID)Address,bytes,len,&BW);
		VirtualProtectEx(Server, (LPVOID)Address, len, OLDPROTECT, &OLDPROTECT);
	}
	CloseHandle(Server);
}



bool WriteMemory(DWORD dwDestAddress, LPVOID pData, DWORD dwSize)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, GetCurrentProcessId());
	if(hProcess)
	{
		DWORD dwOldProtect = 0;
		if(VirtualProtect((LPVOID)dwDestAddress, dwSize, PAGE_WRITECOPY, &dwOldProtect))
		{
			DWORD dwWritten = 0;
			WriteProcessMemory(hProcess, (LPVOID)dwDestAddress, pData, dwSize, &dwWritten);
			VirtualProtect((LPVOID)dwDestAddress, dwSize, dwOldProtect, &dwOldProtect);
		}
		CloseHandle(hProcess);
		return true;
	}else
	{
		MessageBox(NULL, _T("Cannot get process handle!"), _T("CacheD Extension"), MB_OK);
	}
	return false;
}


void Utils::WriteMemoryQWORD(DWORD Address, INT64 value)     { WriteMemoryBYTES(Address, &value, 8); }
void Utils::WriteMemoryDWORD(DWORD Address, DWORD value)     { WriteMemoryBYTES(Address, &value, 4); }
void Utils::WriteMemoryWORD(DWORD Address, WORD value)      { WriteMemoryBYTES(Address, &value, 2); }
void Utils::WriteMemoryBYTE(DWORD Address, BYTE value)       { WriteMemoryBYTES(Address, &value, 1); }
