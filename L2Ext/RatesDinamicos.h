#pragma once




class RatesDinamicos : public CThreadSafe
{
	enum EventState
	{
		StateDetenido = 0,
		StateMensajeInit = 1,
		StateIniciado = 2,
		StateMensajeFin = 3,
	};

	struct Evento
	{
		bool enabled;
		bool dayFlag[7];
		INT32 startHour;
		INT32 startMinute;
		INT32 endHour;
		INT32 endMinute;
		EventState estado;
		wstring m_AnnounceInitMsg;
		wstring m_AnnounceEndMsg;
		INT32 m_AnnounceInitMsgId;
		INT32 m_AnnounceEndMsgId;



		double nAdenaRate;
		double nExpRate;
		double nAncientAdenaRate;
		double nSpoilRate;
		double nSpoilCount;
		double nRaidBossItemChance;
		double nItemCountsChance;
	};

private:
	BOOL m_enabled;
	list<Evento*> m_eventInfo;
	void LoadINI();
	Evento* m_lpEvent;

public:
	void Init();
	void TimerExpired();

	double GetExpRate();
	double GetAdenaRate();
	double GetAncientAdenaRate();
	double GetSpoilRate();
	double GetSpoilCount();
	double GetRaidBossItemChance();
	double GetItemCountsChance();

	void EnterWorld(User* pUser);
};

extern RatesDinamicos g_RatesDinamicos;