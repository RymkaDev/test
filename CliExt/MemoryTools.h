#pragma once

class CMemoryTools
{
	
public:
	static LPBYTE FindMemory(LPBYTE lpMemory, UINT memorySize, LPBYTE lpData, UINT dataSize, bool& invalid);
	static LPBYTE FindMemoryEnc(LPBYTE lpMemory, UINT memorySize, LPBYTE lpData, UINT dataSize, bool& invalid);
	static bool FindMemoryEnc2(LPBYTE lpMemory, UINT memorySize, LPBYTE lpData, UINT dataSize, bool& invalid);
	bool FindMemory(vector<char> lpMemory, UINT memorySize, LPBYTE lpData, UINT dataSize);
	bool FindMemory(vector<BYTE> lpMemory, UINT memorySize, LPBYTE lpData, UINT dataSize);
	bool FindMemoryEnc(vector<BYTE> lpMemory, LPBYTE lpData, UINT dataSize);
	//int FindMemory3(vector<char> lpMemory, UINT memorySize, vector<char> lpData,  vector<char> lpData2,  vector<char> lpData3,  vector<char> lpData4, vector<char> lpData5, UINT dataSize, UINT dataSize2, UINT dataSize3, UINT dataSize4, UINT dataSize5);
	//vector<BOOL> FindMemoryEnc2(vector<BYTE> lpMemory, vector<BYTE> lpData, vector<BYTE> lpData2, vector<BYTE> lpData3, vector<BYTE> lpData4, vector<BYTE> lpData5 );
	vector<BOOL> CMemoryTools::FindMemoryEnc2(vector<BYTE> lpMemory, vector<BYTE> lpData, vector<BYTE> lpData2, vector<BYTE> lpData3, vector<BYTE> lpData4, vector<BYTE> lpData5, vector<BYTE> lpData6, vector<BYTE> lpData7, vector<BYTE> lpData8, vector<BYTE> lpData9, vector<BYTE> lpData10 );
	BYTE GetIt(UINT pos);
	bool IsSameMemory(HANDLE hProcess, PVOID lpStartAddress, LPBYTE lpMemory, UINT size);
	int CompareMemory(LPBYTE lpDest, LPBYTE lpSource, UINT size);
	BOOL GetAddressOfData(DWORD pid, const char *data, size_t len);
	time_t FILETIMEtoTIME_T(FILETIME const& ft);
	void SaveLibrary(PSTR moduleName, PSTR expr);
	string ModuleNameExtractor(string name);
	static void PrintData();
};

extern CMemoryTools g_MemoryTools;