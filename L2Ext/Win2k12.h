#pragma once

class CWin2k12
{
	BOOL m_Enabled;
	BOOL m_Done;
	void LoadINI();
public:
	void Init();
	void TimerExpired();
	static void AddToStatusWindow(LPVOID pWindow, int nLine, PWCHAR format, int nCount1, int nCount2, int nCount3, int nCount4);
	inline void SetTimeStartedDone(BOOL done) { m_Done = done; }
};

extern CWin2k12 g_Win2k12;