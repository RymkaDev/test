#pragma once

class CFactionCounter : public CThreadSafe
{
	CSLock m_InsLock;
	INT32 m_RedTeamCount;
	INT32 m_GreenTeamCount;
public:
	void Init();
	void IncreaseRedTeam() ;
	void IncreaseGreenTeam();
	void DecreaseRedTeam();
	void DecreaseGreenTeam();
	void SetRedTeamCount(int nCount) { m_RedTeamCount = nCount; };
	void SetGreenTeamCount(int nCount) { m_GreenTeamCount = nCount; };
	INT32 GetRedTeamCount() { return m_RedTeamCount; };
	INT32 GetGreenTeamCount() { return m_GreenTeamCount; };

};

extern CFactionCounter g_FactionCounter;