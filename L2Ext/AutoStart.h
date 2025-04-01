#pragma once

struct AutoStartData
{
	TCHAR dir[260];
	TCHAR exeName[260];
};

class CAutoStart
{
	BOOL m_enabled;
	list<AutoStartData> m_app;
	void LoadINI();
public:
	CAutoStart();
	~CAutoStart();
	void Init();
	void StartApps();
	static void NpcDie(UINT64 pLog, int type, const WCHAR *format);
};

extern CAutoStart g_AutoStart;