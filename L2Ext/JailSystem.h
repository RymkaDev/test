#pragma once

class CJailSystem
{
	BOOL m_Enabled;
	int JKickX, JKickY, JKickZ;
	int JailX, JailY, JailZ;
	CSLock m_Lock;

public:
	CJailSystem();
	~CJailSystem();
	void Init();
	void LoadINI();
	inline bool IsEnabled() { return m_Enabled; };
	inline int JailPosX() { return JailX; };
	inline int JailPosY() { return JailY; };
	inline int JailPosZ() { return JailZ; };
	inline int JKickPosX() { return JKickX; };
	inline int JKickPosY() { return JKickY; };
	inline int JKickPosZ() { return JKickZ; };
	void SendPlayerJail(User *pUser,UINT time);
	void RemovePlayerJail(User *pUser, bool sendcaptcha);
};

extern CJailSystem g_Jail;