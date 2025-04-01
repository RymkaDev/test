#pragma once

class CLog
{
	LPVOID m_lpOrgInstance;
public:
	CLog();
	~CLog();
	void Add(LogType type, const CHAR* format, ...);
	void Add(LogType type, const WCHAR* format, ...);
	void AddV(const int type, const wchar_t *format, va_list va);
};

extern CLog g_Log;