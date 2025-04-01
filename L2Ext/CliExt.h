#pragma once

typedef bool (*CPHandler)(CUserSocket*, const unsigned char*);

struct BannedHardwareId
{
	BYTE hash[32];
	wstring accountName;
	wstring GMName;
	UINT timeout;
	UINT times;
	BannedHardwareId() : timeout(0), times(0) { memset(hash, 0, sizeof(hash)); };
};


class CCliExt
{
	BOOL m_Enabled;
	BOOL m_DisablePingPacket;
	UINT m_Version;
	INT32 m_BoxLimit;
	WCHAR m_BoxLimitHTML[0x4000];
	WCHAR m_BannedHWIDHTML[0x4000];
	WCHAR m_LockedCharacterHTML[0x4000];
	WCHAR m_LockedAccountHTML[0x4000];
	CPHandler m_CustomHandler[256];
	vector<HWID> m_AllowedHWID;
	WCHAR m_AllowedHWIDHtml[0x4000];
	UINT m_AutoBanHWID;
	//BYTE m_MD5Checksum[32];
	WCHAR m_OutdatedClientHTML[0x4000];


	WCHAR m_BloquearLoginHTML[0x4000];




	CSLock m_BannedLock;
	vector<BannedHardwareId> m_Banned;


	vector<HWID> m_MD5Checksum;
	


	map<wstring,vector<HWID>> m_MD5ChecksumFiles;
public:

	vector<wstring> m_ListaBlancaExe;

	BOOL m_EnabledAntiAdrenaline;
	WCHAR m_PatternName[0x4000];
	WCHAR m_PatternMask[0x4000];
	BOOL m_VerificarThreadMuerto;

	WCHAR m_PatternName2[0x4000];
	WCHAR m_PatternMask2[0x4000];

	WCHAR m_PatternName3[0x4000];
	WCHAR m_PatternMask3[0x4000];


	BOOL m_Enabled_files;
	BOOL m_MostrarMensajesConsola;

	BOOL m_BloquearLogin;

	void LoadINI();
	void Init();
	void Bind(UINT id, CPHandler func);
	inline WCHAR* GetBannedHtml() { return m_BannedHWIDHTML; };
	inline WCHAR* GetBoxLimitHtml() { return m_BoxLimitHTML; };
	inline WCHAR* GetLockedCharacterHtml() { return m_LockedCharacterHTML; };
	inline WCHAR* GetLockedAccountHtml() { return m_LockedAccountHTML; };
	inline INT32 GetBoxLimit() { return m_BoxLimit; };
	inline void SetBoxLimit(int value) { m_BoxLimit = value; };
	void OnBanDBLoad(LPBYTE lpHwid, wstring account, wstring gmName, UINT timeout, UINT times);
	bool IsBanned(LPBYTE lpHwid);
	bool IsAllowed(LPBYTE lpHwid);
	bool IsAllowedMD5(LPBYTE lpHwid);
	bool IsAllowedMD5File(wstring file,LPBYTE lpHwid);
	bool UnBan(LPBYTE lpHWID, wstring gmName);
	void Ban(LPBYTE lpHWID, wstring account, wstring gmName, UINT timeout);
	void HandleCheckSum(CUserSocket *pSocket, const unsigned char* packet, UINT packetSize);
	void DecryptPacket(CUserSocket *pSocket, unsigned char* packet, UINT packetSize);
	bool HandleCustomPacket(CUserSocket *pSocket, const unsigned char* packet);
	void TimerExpired(CUserSocket *pSocket);
	void GetAllowedHWIDHtml(HWID& hwid, WCHAR* wHtml);
	inline UINT IsAutoBanHWID() { return m_AutoBanHWID; };
	inline BOOL IsEnabled() { return m_Enabled; };
	inline UINT GetVersion() { return m_Version; };
//	inline const LPBYTE GetMD5CHecksum() { return m_MD5Checksum; };
	inline const WCHAR* GetOutdatedClientHtml() { return m_OutdatedClientHTML; };

	inline const WCHAR* GetBloquearLoginHtml() { return m_BloquearLoginHTML; };

	inline const WCHAR* GetPatternName() { return m_PatternName; };
	inline const WCHAR* GetPatternMask() { return m_PatternMask; };
	inline const WCHAR* GetPatternName2() { return m_PatternName2; };
	inline const WCHAR* GetPatternMask2() { return m_PatternMask2; };
	inline const WCHAR* GetPatternName3() { return m_PatternName3; };
	inline const WCHAR* GetPatternMask3() { return m_PatternMask3; };

	
};

bool CPHDummyPacket(CUserSocket *pSocket, const unsigned char* pacekt);
bool CPHPingExPacket(CUserSocket *pSocket, const unsigned char* packet);
bool CPHHWIDPacket(CUserSocket *pSocket, const unsigned char* packet);
bool CPHPingPacket(CUserSocket *pSocket, const unsigned char* packet);
bool CPHReplyL2NetworkVoteTime(CUserSocket *pSocket, const unsigned char* packet);
bool CPHReplyJobPacket(CUserSocket *pSocket, const unsigned char* packet);
bool CPHReplyMD5Packet(CUserSocket *pSocket, const unsigned char* packet);
bool CPHReplyMD5FilesPacket(CUserSocket *pSocket, const unsigned char* packet);
bool CPHReplyProcessPacket(CUserSocket *pSocket, const unsigned char* packet);
bool CPHReplyGetImagePacket(CUserSocket *pSocket, const unsigned char* packet);




extern CCliExt g_CliExt;