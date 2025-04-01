#pragma once

enum DCReasonType
{
	DCReasonNone = 0,
	DCReasonProcessTick = 1,
	DCReasonBOT1 = 2,
	DCReasonBOT2 = 3,
	DCReasonBOT3 = 4,
	DCReasonShadowExe = 5,
	DCReasonLoaderExe = 6,
	DCReasonL2Tower = 7,
	DCReasonL2UI = 8,
	DCReasonL2Walker = 9,
	DCReasonCPTracker = 10,
	DCReasonL2QuickTools = 11,
	DCReasonUoPilot = 12,
	DCReasonAutoIt = 13,
	DCReasonPointMacro = 14,
	DCReasonInfocus = 15,
	DCReasonL2Control = 16,
	DCReasonAdrenaline = 17,
	DCReason4Bot = 18,
	DCReasonShadowH5 = 19,
	DCReasonL2Ext = 20,
	DCReasonCPanel = 21,
	DCReasonClickermann = 22,
	DCExtremeInjector = 23,
	DCReasonAutoHotKey = 24,
	DCReasonAdrenaline2 = 25
};

struct ModuleInfo
{
	wstring moduleName;
	UINT moduleBase;
	UINT moduleSize;
};

struct OpenProcesses
{
	HANDLE hProc;
	wstring hProcName;
	DWORD pid;
	wstring hProcFullPath;
};

struct BotsToClose
{
	wstring Classname;
	int Reason;
	int RamType;
};

struct BotsToCloseChild
{
	wstring Classname;
	int Reason;
	int RamType;
};

struct BotsException
{
	wstring Classname;
};

struct CharName
{
	wstring Classname;
};

union ProcessIdentifier
{
	UINT64 globalId;
	struct
	{
		UINT processId;
		UINT startTime;
	}part;
};

class CMemoryProtector
{
	UINT m_EngineSize;
	UINT m_EngineAddressStart;
	UINT m_EngineAddressEnd;
	time_t m_ValidateModulesTimeout;
	UINT m_ScanAddress;
	UINT m_ScanAddressEnd;
	UINT m_ScanTick;
	UINT m_CliExtAddress;
	UINT m_CliExtSize;
	UINT m_ModuleIndex;

	UINT m_ScanAddress2;
	UINT m_ScanAddressEnd2;
	BYTE bufferTotal[20480];
	UINT m_LastPosition;

	vector<ModuleInfo> m_Modules;
	CSLock m_ValidatedLock;
	CSLock m_ProcessesLock;
	CSLock m_Processes2Lock;
	vector<ProcessIdentifier> m_ValidatedProcess;
	vector<ProcessIdentifier> m_ValidatedWindows;
	DWORD CurrentProcessID;
	WCHAR CurrentProcessName[MAX_PATH +1];
	
public:
	vector<OpenProcesses> m_OpenedProcesses;
	vector<OpenProcesses> m_OpenedProcesses2;
	vector<char> FirstCheck;
	vector<char> SecondCheck;
	vector<char> ThirdCheck;
	vector<char> ForthCheck;
	vector<char> FifthCheck;
	UINT nCorrectStrings;
	//unsigned char* FirstCheck;
	//unsigned char* SecondCheck;

	void Init();
	void InitCliExt();
	void SetValidatedProcess(UINT processId);
	bool IsValidatedProcess(UINT processId);
	void SetValidatedWindows(UINT processId);
	bool IsValidatedWindows(UINT processId);
	static LPBYTE FindMemory(LPBYTE lpMemory, UINT memorySize, LPBYTE lpData, UINT dataSize, bool& invalid);
	bool FindMemory(vector<char> lpMemory, UINT memorySize, LPBYTE lpData, UINT dataSize);
	bool ValidateModules();
	void ValidateRunningApps();
	void CheckForBotsRam(vector<char> lpMemory, UINT memorySize);
	void ValidateRunningAppsEx();
	void ValidateMemory();
	void ClearProcesses();
	static BOOL CALLBACK enumWindowCallback(HWND hWnd, LPARAM lparam);
	void GetOpenProcesses();
	bool ValidateMemoryOther();
	void ValidateMemoryEx();
	wstring CheckProccessPath(DWORD procId);
	static BOOL CALLBACK EnumerateLoadedModulesProc( PSTR moduleName, ULONG moduleBase, ULONG moduleSize, PVOID userContext );
	static BOOL CALLBACK EnumWindowsCallback(HWND hWnd, LPARAM lParam);
	static BOOL CALLBACK EnumChildWindowsCallback(HWND hWnd, LPARAM lParam);
	inline time_t GetValidateModulesTimeout() { return m_ValidateModulesTimeout; };
	inline UINT GetScanTick() { return m_ScanTick; };
	void AddBotToCheck(wstring ClassName, int Reason, int RamType, bool b_child);
	void AddExceptions(wstring ClassName);
	void AddCharName(wstring ClassName);
	void CleanBotToCheckList();
	BOOL GetAddressOfData(DWORD pid, const char *data, size_t len);
	BOOL CheckForExcpetions(wstring path);
	wstring GetCurrentProcessName() { return std::wstring(CurrentProcessName); }
	static void AddStringBytes(UINT string, UINT place, BYTE data);
	static void SetFoundStrings(UINT nStringsCount);
	static void PrintData();
	bool ValidateMemoryServerFirst();
	bool ValidateMemoryServerSecond();
	bool FindMemory2(vector<char> lpMemory, UINT memorySize, vector<char> lpData, UINT dataSize);
	bool ValidateMemoryServerNewVersion();
	int FindMemory3(vector<char> lpMemory, UINT memorySize, vector<char> lpData,  vector<char> lpData2,  vector<char> lpData3,  vector<char> lpData4, vector<char> lpData5, UINT dataSize, UINT dataSize2, UINT dataSize3, UINT dataSize4, UINT dataSize5);
};

extern CMemoryProtector g_MemoryProtector;