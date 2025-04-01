#pragma once

class CFirewall
{
	enum ACTION_TYPE
	{
		ACTION_TYPE_NOTHING = 0,
		ACTION_TYPE_LOG = 1,
		ACTION_TYPE_DROP = 2,
		ACTION_TYPE_LOG_DROP = 3,
		ACTION_TYPE_KICK = 4,
		ACTION_TYPE_LOG_KICK = 5
	};

	BOOL enabled;
	DWORD minTimestamp[256];	 /* minimum timestamp */
	INT32 actionType[256];	/* action type */

	INT32 m_banDuration; /* ban timestamp */

	CSLock m_Lock;

	HANDLE hFile;
	void LoadINI();
	void AddLog(wstring log);
public:
	CFirewall();
	void Init();
	void OnPacketRecv(CUserSocket *pSocket, BYTE opCode, bool& drop, bool& kick);
	~CFirewall();
};

extern CFirewall g_Firewall;