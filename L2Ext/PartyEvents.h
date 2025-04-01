#pragma once

	enum PartyEventsState
	{
		PartyEventStateNone = 0,
		PartyEventStatePreparation = 1,
		PartyEventStateCountDown = 2,
		PartyEventStateFight = 3,
		PartyEventStateFinish = 4,
		PartyEventStateDelete = 5
	};


	enum PartyEquipoState
	{
		None = 0,
		Espera = 1,
		Preparacion = 2,
		Peleando = 3,
		Finalizado = 4
	};

	struct PartyEquipo
	{
		PartyEquipoState m_state;
		INT32 m_Cantidad;
		INT32 m_ApuestaId;
		INT32 m_ApuestaTotal;
		UINT m_ObjectID;
		wstring n_PartyLeader;
	};


	struct PartyEventsInfo
	{
		INT32 id;
		PartyEventsState m_state;

		IVector bluePos[100];
		IVector redPos[100];

		IVector kickOutPos;
		time_t m_stateTime;


		INT32 BufferNpcClassId;
		IVector buffer1_Pos;
		IVector buffer2_Pos;


		PartyEquipo m_Party1;
		PartyEquipo m_Party2;
		INT32 m_PremioId;
		INT32 m_PremioTotal;

		wstring fightStartRemindMsg;
		wstring fightStartRemindMsg2;
		UINT m_managerServerId;
		UINT m_managerServerId2;

		PartyEventsInfo()
		{
			Clear();
		}
		inline void Clear()
		{
			m_Party1.m_ApuestaId = 0;
			m_Party1.m_ApuestaTotal = 0;
			m_Party1.m_Cantidad = 0;
			m_Party1.m_ObjectID = 0;
			m_Party1.m_state = None;
			m_Party1.n_PartyLeader = L"";

			m_Party2.m_ApuestaId = 0;
			m_Party2.m_ApuestaTotal = 0;
			m_Party2.m_Cantidad = 0;
			m_Party2.m_ObjectID = 0;
			m_Party2.m_state = None;
			m_Party2.n_PartyLeader = L"";

			m_PremioId = 0;
			m_PremioTotal = 0;

			m_managerServerId = 0;
			m_managerServerId2 = 0;
		}
	};



class PartyEvents : public CThreadSafe
{
	CSLock m_Lock;

	BOOL m_Enable;
	vector<PartyEventsInfo> m_Info;
	vector<PartyEquipo> m_Partys;
	time_t m_stateTime;

public:
	void Init();
	void LoadINI();
	void TimerExpired();

	void MandarAPelear(PartyEquipo party1, PartyEquipo party2);
	void SendMessageDist(PartyEventsInfo partyevent, const WCHAR* wAnnounce);

	static bool CustomsBypass(User* pUser, wstring wBypass);

};

extern PartyEvents g_PartyEvents;