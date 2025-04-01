#pragma once

class CCaptcha
{
	BOOL m_Enabled;
	INT32 m_MobsKilled;
	INT32 m_MobsKilledPole;
	INT32 m_Chance;
	INT32 m_Captcha_Mode;
	INT32 m_RewardActive;
	INT32 m_RewardID;
	INT32 m_RewardQuanity;
	INT32 m_DoubleJail;
	UINT m_TimeoutTime;
	UINT m_TimeoutTimeRecaptcha;
	UINT m_JailTime;
	int m_skillId;
	INT32 m_Times_Village;
	INT32 m_Times_Jail;
	int VKickX, VKickY, VKickZ;
	WCHAR m_TemplateLink[260];
	BOOL m_Enabled_Recaptcha;
	BOOL m_Enabled_Recaptcha_Only;
	BOOL m_ReplaceETC;
	CSLock m_Lock;

public:
	CCaptcha();
	~CCaptcha();
	inline int GetSkillId() { return m_skillId; };
	inline wstring GetTemplateLink() { return std::wstring(m_TemplateLink); };
	void Init();
	void LoadINI();
	inline BOOL IsEnabled() { return m_Enabled; };
	inline BOOL EtcBuffStatusReplace() { return m_ReplaceETC; };
	void ActivateTimer(User *pUser,bool recaptcha=false);
	void DoPunishment(User *pUser, bool timeoff);
	void EnterWorld(User *pUser);
	void OnDie(CCreature *pKiller, CNPC *pNPC);
	void DoCaptcha(User *pUser, bool timeoff, bool recaptcha = false);
	void Validate(User *pUser, wstring answer, bool recaptcha);
	void ReleasePlayer(User *pUser);
	int PickNumber(int max, int unwanted);
	int PickNumber2(int max, int unwanted1, int unwanted2);
	int PickNumber3(int max, int unwanted1, int unwanted2, int unwanted3);
	void DoReport(User *pUser, User *pTarget);
	wstring PickColor(int numberPick);
};

extern CCaptcha g_Captcha;