#pragma once

#include "DBSocket.h"
#include "TerritoryData.h"

const int MAX_EQUIPMENT_SLOTS = 18;

enum PvPState
{
	StatePrepare = 0,
	StateRegistration = 1,
	StatePrepararInicioTorneo = 2,
	StateCountDown = 3,
	StateFight = 4,
	StateFinish = 5,
	StateDelete = 6,
	StateGenerarFixture = 7,
	StateRegistrationAutomatico = 8,
	StateNone = 99,
};

enum PvPEventCategorias
{
	CategoryAmateur = 0,
	CategorySegunda = 1,
	CategoryPrimera = 2,
	CategoryMaster = 3,
	CategoryAll = 30,
};

struct PVPUser
{
	INT32 charId;
	wstring Hwid;
	INT32 pos;
	INT32 ronda;
	BOOL descalificado;
};

class PvPEvents : public CThreadSafe
{
	CSLock m_Lock;

	//map<wstring, PVPUser> m_usersRegister;
	std::vector<std::pair<std::wstring, PVPUser> > m_usersRegister;

	//map<wstring, PVPUser> m_usersRounds;
	std::vector<std::pair<std::wstring, PVPUser> > m_usersRounds;

	//map<wstring, PVPUser> m_usersGrillaClientes;
	std::vector<std::pair<std::wstring, PVPUser> > m_usersGrillaClientes;


	bool enableRegister;
	bool HwidDetect;
	int maxPlayers;
	int minPlayers;
	int MinLevel;
	int registeredPlayers;
	int TorneoCategoria;
	int Ronda;
	bool sumarpuntos_torneo;

	bool registroAutomatico;

	
	int inscripcionItemId;
	int inscripcionItemCount;

	int premioItemId;
	int premioItemCount;

	wstring inscripcionItemName;
	wstring premioItemName;

	wstring inscripcionItemIcon;
	wstring premioItemIcon;


	wstring fightStartRemindMsg;
	wstring fightStartRemindMsg2;

	wstring RegistrationStartMessage1;
	wstring RegistrationStartMessage2;
	wstring RegistrationRemindMessage;
	wstring RegistrationEndMessage;
	wstring EndMessage;
	wstring RegistratrionNontEnoughParticipants;
	wstring PreparationStartMessage;
	wstring PreparationRemindMessage;

	wstring NingunoDeLosPeronajesOnlineMsg;
	wstring PeronajesCharNo1OnlineMsg;
	wstring PeronajesCharNo2OnlineMsg;
	wstring PaseLibreMsg;
	wstring ProximaPeleaMsg;
	wstring HaGanadoLaPeleaMsg;
	wstring HaSalidoCampeonMsg;
	wstring PDescalificadoPor1HwidMsg;
	wstring PDescalificadoPor2HwidMsg;
	wstring HaGanadoLaPeleaPorDanioMsg;

	
	UINT m_SuperBuffTimestamp;


	int m_SuperBuffId;
	int m_SuperBuffLevel;

	PvPState m_state;
	time_t m_stateTime;
	bool m_lpEvent;

	bool TorneoComenzado;

	INT32 RegisterTime;
	INT32 prepareTime;
	INT32 countDownTime;
	INT32 fightTime;
	INT32 SleepEntreCadaPelea;
	INT32 SleepEntreCadaPeleaTemp;

	wstring UltimoGanador;


	INT32 BufferNpcClassId;

	IVector kickOutPos;


	IVector buffer1_Pos;
	IVector buffer2_Pos;

	IVector Player1_Pos;
	IVector Player2_Pos;

	UINT m_managerServerId;
	UINT m_managerServerId2;

	INT32 n_EventID;

	bool UpdateFixture;
	wstring html_fixture;

	User* peleador1;
	User* peleador2;
	wstring peleador1W;
	wstring peleador2W;

public:

	void Init();
	void LoadINI();

	void HabilitarRegistro();
	void HabilitarRegistroAutomatico();
	void CerrarRegistro();
	void SetMaxPlayers(int maxUsers);
	void SetMinPlayers(int maxUsers);
	void TerminarTorneo();

	void TimerExpired();


	void ValidateTerritory(User* pUser);

	void OnDie(User *pUser, CCreature *pEnemy, bool empateAtk);


	bool Register(User *pUser);
	bool UnRegister(User *pUser);

	bool Bypass(User* pUser, wstring wBypass);


	void SumarPunto(User* pUser);

	void RequestLoadPvPEvent();
	void RequestSavePvPEvent(int charId, int ronda, bool descalificado, int pos = 0);

	void ShowBoard(User* pUser, const WCHAR *wHtml);

	bool InEvent(User *pUser);

	
	void PvPEvents::EnviarAnnouncePeleaCancelada(wstring m_Message);
	
	void SendMessageDist(const WCHAR* wAnnounce);

	//void RequestSavePvPEventStatus(const WCHAR* wName, int puntos);
	//void RequestSavePvPEventRegister(const WCHAR* wName, const WCHAR* wHwid, int condicion);

	void RequestLoadPvPEventUserVars(UINT charId);
	void RequestSavePvPEventUserVars(User* pUser);
	static bool ReplyLoadPvPEventUserVars(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadPvPEvent(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);

	static bool UserExCommandPvPEvents(User *pUser, wstring params);

	bool CommandCacheD(wstring wsParams);
	bool PvPEvents::EnviarAPelear(User* pUser1, User* pUser2);
	void PvPEvents::UserDescalificar(wstring player);
	void PvPEvents::UserPasarDeRonda(wstring player);
	bool PvPEvents::DetectarHwid(User* pUser, wstring player);
	bool PvPEvents::EnCondicionesDePelear();
	void PvPEvents::MensajeGanadorPelea(wstring player);

	class BuilderCommand
	{
	public:
		static bool EventManager(User *pUser, wstring wParams);

	};

};

extern PvPEvents g_PvPEvents;
