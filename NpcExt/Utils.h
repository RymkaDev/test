#pragma once

class CSLock
{
	CRITICAL_SECTION m_lock;
	UINT m_lockCount;
public:
	CSLock() { InitializeCriticalSection(&m_lock); };
	~CSLock() { DeleteCriticalSection(&m_lock); };
	inline void Enter() { EnterCriticalSection(&m_lock); m_lockCount++; };
	inline void Leave() { LeaveCriticalSection(&m_lock); m_lockCount--; };
};

int Assemble(PCHAR buf, int bufLen, const char *format, ...);
const unsigned char* Disassemble(const unsigned char* packet, const char* format, ...);


inline void WriteMemoryBYTES(uintptr_t addr, const void* data, size_t len)
{
	DWORD OLDPROTECT;
	SIZE_T BW;
	HANDLE Server = OpenProcess(MAXIMUM_ALLOWED, false, GetCurrentProcessId());		//con este funciona en el server 2003
	//HANDLE Server = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_VM_READ | PROCESS_VM_WRITE, false, GetCurrentProcessId());
	if ( Server )
	{
		VirtualProtectEx(Server, (LPVOID)addr, len, PAGE_WRITECOPY, &OLDPROTECT);
		WriteProcessMemory(Server,(LPVOID)addr, data, len, &BW);
		VirtualProtectEx(Server, (LPVOID)addr, len, OLDPROTECT, &OLDPROTECT);
	}
	CloseHandle(Server);
}

inline void WriteMemoryDWORD(unsigned int address, unsigned int value)
{
    WriteMemoryBYTES(address, &value, sizeof(unsigned int));
}

inline void WriteAddress(unsigned int uAddress, UINT32 absAddr)
{
	WriteMemoryDWORD(uAddress, absAddr - (uAddress + 4));
}


inline std::basic_string<wchar_t> Widen(const std::string &s)
{
	std::wstring result;
	std::copy(s.begin(), s.end(), std::back_inserter(result));
	return result;
}

inline std::string Narrow(const std::basic_string<wchar_t> &s)
{
	std::string result;
	for (size_t i = 0 ; i < s.size() ; ++i) {
		result.push_back(static_cast<char>(s[i]));
	}
	return result;
}


inline void WriteInstructionJmp(unsigned int address, unsigned int uDestination)
{
	unsigned char execLine[5];
	execLine[0] = 0xE9;
	*((int*)(execLine + 1)) = (((int)uDestination) - (((int)address) + 5));
	WriteMemoryBYTES(address, execLine, 5);
}


inline void WriteInstructionCall(unsigned int address, unsigned int uDestination)
{
	unsigned char execLine[5];
	execLine[0] = 0xE8;
	*((int*)(execLine + 1)) = (((int)uDestination) - (((int)address) + 5));
	WriteMemoryBYTES(address, execLine, 5);
}



inline void WriteMemory(UINT64 baseAddress, LPCVOID lpMemory, SIZE_T size)
{
	LPBYTE lpBase = (LPBYTE)baseAddress;
	LPBYTE lpData = (LPBYTE)lpMemory;
	DWORD priv = 0;
	if(VirtualProtect(lpBase, size, PAGE_EXECUTE_READWRITE, &priv))
	{
		for(int n=0;n<size;n++)
		{
			lpBase[n] = lpData[n];
		}
		DWORD old = 0;
		VirtualProtect(lpBase, size, priv, &old);
	}
}

inline void WriteNOP(UINT64 baseAddress, SIZE_T count)
{
	LPBYTE lpBase = (LPBYTE)baseAddress;
	DWORD priv = 0;
	if(VirtualProtect(lpBase, count, PAGE_EXECUTE_READWRITE, &priv))
	{
		for(SIZE_T n = 0; n < count ; n++)
		{
			lpBase[n] = 0x90;
		}
		DWORD old = 0;
		VirtualProtect(lpBase, count, priv, &old);
	}
}

inline void WriteBYTE(UINT64 baseAddress, BYTE value)
{
	LPBYTE lpBase = (LPBYTE)baseAddress;
	DWORD priv = 0;
	if(VirtualProtect(lpBase, 1, PAGE_EXECUTE_READWRITE, &priv))
	{
		(*lpBase) = value;
		DWORD old = 0;
		VirtualProtect(lpBase, 1, priv, &old);
	}
}

inline void WriteDWORD(UINT64 baseAddress, DWORD value)
{
	LPDWORD lpBase = (LPDWORD)baseAddress;
	DWORD priv = 0;
	if(VirtualProtect(lpBase, 4, PAGE_EXECUTE_READWRITE, &priv))
	{
		(*lpBase) = value;
		DWORD old = 0;
		VirtualProtect(lpBase, 4, priv, &old);
	}
}

inline void WriteQWORD(UINT64 baseAddress, INT64 value)
{
	PINT64 lpBase = (PINT64)baseAddress;
	DWORD priv = 0;
	if(VirtualProtect(lpBase, 8, PAGE_EXECUTE_READWRITE, &priv))
	{
		(*lpBase) = value;
		DWORD old = 0;
		VirtualProtect(lpBase, 8, priv, &old);
	}
}

inline void WriteDOUBLE(UINT64 baseAddress, double value)
{
	double* lpBase = (double*)baseAddress;
	DWORD priv = 0;
	if(VirtualProtect(lpBase, 8, PAGE_EXECUTE_READWRITE, &priv))
	{
		(*lpBase) = value;
		DWORD old = 0;
		VirtualProtect(lpBase, 8, priv, &old);
	}
}

inline void WriteCall(UINT64 baseAddress, LPVOID function, SIZE_T nop = 0)
{
	LPBYTE lpBase = (LPBYTE)baseAddress;
	HookMem mem;
	mem.full.opCode = 0xE8;	//CALL
	UINT64 fundAddr = (UINT64)function;
	fundAddr -= (baseAddress + 5);
	mem.full.addr = (DWORD)fundAddr;

	DWORD priv = 0;
	if(VirtualProtect(lpBase, (5+nop), PAGE_EXECUTE_READWRITE, &priv))
	{
		for(SIZE_T n = 0; n < (5 + nop) ; n++)
		{
			if(n < 5)
			{
				lpBase[n] = mem.byte.p[n];
			}else
			{
				lpBase[n] = 0x90;
			}
		}
		DWORD old = 0;
		VirtualProtect(lpBase, (5+nop), priv, &old);
	}
}

inline void WriteToVMT(UINT64 vmtAddress, INT32 offset, LPVOID function)
{
	PINT64 lpVMT = (PINT64)vmtAddress;
	offset /= 8;
	DWORD priv = 0;
	if(VirtualProtect(&lpVMT[offset], 8, PAGE_EXECUTE_READWRITE, &priv))
	{
		lpVMT[offset] = (INT64)function;
		DWORD old = 0;
		VirtualProtect(&lpVMT[offset], 8, priv, &old);
	}
}

inline void WriteJump(UINT64 baseAddress, UINT64 func, SIZE_T nop = 0)
{
	LPBYTE lpBase = (LPBYTE)baseAddress;
	HookMem mem;
	mem.full.opCode = 0xE9;	//Jump
	func -= (baseAddress + 5);
	mem.full.addr = (DWORD)func;

	DWORD priv = 0;
	if(VirtualProtect(lpBase, (5+nop), PAGE_EXECUTE_READWRITE, &priv))
	{
		for(SIZE_T n = 0; n < (5 + nop) ; n++)
		{
			if(n < 5)
			{
				lpBase[n] = mem.byte.p[n];
			}else
			{
				lpBase[n] = 0x90;
			}
		}
		DWORD old = 0;
		VirtualProtect(lpBase, (5+nop), priv, &old);
	}
}

inline void WriteRelative(UINT64 baseAddr, LPVOID lpObject)
{
	DWORD relative = (DWORD)((INT64)lpObject - (baseAddr + 4));
	DWORD priv = 0;
	if(VirtualProtect((LPVOID)baseAddr, 4, PAGE_EXECUTE_READWRITE, &priv))
	{
		(*(LPDWORD)baseAddr) = relative;
		DWORD old = 0;
		VirtualProtect((LPVOID)baseAddr, 4, priv, &old);
	}
}

void MovLogFiles(LPCTSTR sLogDir);
std::wstring StringToWString(const std::string& s);
std::string WStringToString(const std::wstring& s);
double GetPrivateProfileDouble(LPCTSTR lpAppName, LPCTSTR lpKeyName, double Default, LPCTSTR lpFileName);

namespace Parser
{
	INT32 GetBypassValueInt(const WCHAR* wBypass, const WCHAR* wName, int defaultValue = 0);
	INT32 ParseOptionInt(string line, string option, INT32 defaultValue = 0);
	INT32 ParseOptionInt(wstring line, wstring option, INT32 defaultValue = 0);
	double ParseOptionDouble(wstring line, wstring option, double defaultValue = 0);
	double ParseOptionDouble(string line, string option, double defaultValue = 0);
	string ParseOptionString(string line, string option, string sDefault = "");
	wstring ParseOptionString(wstring line, wstring option, wstring sDefault = L"");
	wstring Replace(wstring str, wchar_t sign, wchar_t new_sign);
	string Replace(string str, char sign, char new_sign);
	vector<wstring> Split(wstring line, wstring separators);
	vector<string> Split(string line, string separators);
};



static HRESULT _UnicodeToAnsi(LPCWSTR pszW, LPSTR ppszA)
{

    ULONG cbAnsi, cCharacters;
    DWORD dwError;

    // If input is null then just return the same.
    if (pszW == NULL)
    {
        *ppszA = NULL;
        return NOERROR;
    }

    cCharacters = (ULONG)wcslen(pszW)+1;
    // Determine number of bytes to be allocated for ANSI string. An
    // ANSI string can have at most 2 bytes per character (for Double
    // Byte Character Strings.)
    cbAnsi = cCharacters*2;

    if (NULL == ppszA)
        return E_OUTOFMEMORY;

    // Convert to ANSI.
    if (0 == WideCharToMultiByte(CP_ACP, 0, pszW, cCharacters, ppszA,
                  cbAnsi, NULL, NULL))
    {
        dwError = GetLastError();
        return HRESULT_FROM_WIN32(dwError);
    }
    return NOERROR;

}

UINT64 WriteRelativeAddress(UINT64 nOrgAddress, UINT64 nWriteFrom, VOID *pArray, UINT64 nOffsetIndex);



static wstring ReadFileW(wstring wName)
{
	UINT64 FileSize = 0;
	_WIN32_FIND_DATAW FileData;
	PWCHAR wStr = NULL;
	wstring str;
	HANDLE hFile = FindFirstFileW(wName.c_str(), &FileData);
	if(hFile != INVALID_HANDLE_VALUE)
	{
		FileSize = MAXDWORD;
		FileSize += 1;
		FileSize *= FileData.nFileSizeHigh;
		FileSize += FileData.nFileSizeLow;
	}
	FindClose(hFile);
	hFile = CreateFileW(wName.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile != INVALID_HANDLE_VALUE)
	{
		BYTE *pBuffer = new BYTE[FileSize];
		memset(pBuffer, 0, FileSize);
		DWORD Readed = NULL;
		if(ReadFile(hFile, pBuffer, (DWORD)FileSize, &Readed, NULL))
		{
			WaitForSingleObject(hFile, INFINITE);
			wStr = (PWCHAR)(pBuffer+2);
			if(Readed > 2)
				str.insert(0, (wchar_t*)wStr, ((Readed / 2) -1));
		}		
		delete [] pBuffer;
	}
	CloseHandle(hFile);
	return str;
}