#ifndef TVTMATCH_H
#define TVTMATCH_H

namespace TvT
{
	enum TvTType
	{
		TvTNone = 0,
		TvTLastTeamStanding = 1,
		TvTDeathMatch = 2,
		TvTGMReGroup = 3,
		TvTKorean = 4,
		TvTLastManStanding = 5,
		TvTCaptureTheFlag = 6,
		TvTCaptureTheFlag2 = 7,
		TvTDestroyTheBase = 8,
		TvTCastle = 9,
		TvTFortress = 10
	};

	enum TvTState
	{
		StateNone = 0,
		StateRegistration = 1,
		StatePreparation = 2,
		StateCountDown = 3,
		StateFight = 4,
		StateFinish = 5,
		StateDelete = 6
	};

	struct TvTInfo
	{
		BOOL enabled;
		TvTType type;
		bool dayFlag[7];
		INT32 startHour;
		INT32 startMinute;
		INT32 registerTime;
		INT32 prepareTime;
		INT32 countDownTime;
		INT32 fightTime;
		INT32 finishTime;
		BOOL dispelAbnormal;
		BOOL randomizeTeam;
		INT32 requiredItemId;
		INT32 requiredItemCount;
		INT32 minPlayers;
		INT32 maxPlayers;
		INT32 minLevel;
		INT32 maxLevel;
		INT32 respawnTime;
		INT32 skillPchId;
		INT32 rewardId;
		INT32 rewardCount;
		INT32 rewardIdTie;
		INT32 rewardCountTie;
		IVector kickOutPos;
		INT32 registerNpcClassId;
		IVector registerNpcPos;
		IVector registerNpcPos1;
		IVector registerNpcPos2;
		INT32 registerBufferId;
		IVector registerBufferPos1;
		IVector registerBufferPos2;
		IVector registerBufferPos3;
		IVector registerBufferPos4;
		INT32 blueFlagId;
		INT32 redFlagId;
		INT32 BalanceBishops;
		IVector blueFlagPos;
		IVector redFlagPos;
		INT32 fightZoneX[2];
		INT32 fightZoneY[2];
		list<wstring> doorList;
		wstring registrationStartMsg1;
		wstring registrationStartMsg2;
		wstring registrationRemindMsg;
		wstring registrationEndMsg;
		wstring registrationNotEnoughParticipantsMsg;
		wstring preparationStartMsg;
		wstring preparationRemindMsg;
		wstring fightStartRemindMsg;
		wstring fightStartMessage;
		wstring fightEndRemindMsg;
		wstring endMsg[3];
		wstring teleportBackRemindMsg;
		wstring endEventMsg;
		wstring npchtmfile;
		wstring npchtmfilebuffer;
		wstring HelpHtmlFile;
		vector<INT32> blockedSkill;
		vector<INT32> blockedItem;
		vector<INT32> blockedClasses;
		vector<SkillPchId> defaultMageBuffs;
		vector<SkillPchId> defaultFighterBuffs;
		bool blockedCrystalType[10];
		BOOL blockAugmentation;
		BOOL blockAttribute;
		INT32 maxArmorEnchant;
		INT32 maxWeaponEnchant;
		BOOL friendlyFire;
		BOOL checkHwid;
		INT32 korean_skillid;
		INT32 PartySize;
		INT32 participateplayers;
//		INT32 blueTeamSize;
//		INT32 redTeamSize;
//		vector<IVector> bluePosV;
//		vector<IVector> redPosV;

		IVector bluePos[1000];
		IVector redPos[1000];

		//CTF
		INT32 BanderaBlueNpcId;
		INT32 BanderaRedNpcId;
		IVector BanderaBlueNpcPos;
		IVector BanderaRedNpcPos;
		INT32 BanderaBlueItemId;
		INT32 BanderaRedItemId;
		INT32 CaptureFireworkId;
		INT32 rewardCountForWinCapture;

		//DESTROY THE BASE
		INT32 DestroyBaseBlueNpcId;
		INT32 DestroyBaseRedNpcId;
		INT32 DestroyBaseNpcHP;
		IVector DestroyBaseBlueNpcPos;
		IVector DestroyBaseRedNpcPos;
		INT32 rewardCountForWinDestroyBase;

		//fortress
		INT32 FortressCrystalNpcId;
		IVector FortressCrystalNpcPos;
		INT32 FortressSkillId;
		INT32 rewardCountForWinCastFortress;
		

		INT32 m_bluePosCantidad;
		INT32 m_redPosCantidad;
		INT32 m_bluePosPosicion;
		INT32 m_redPosPosicion;
		INT32 TimeAfk;
		INT32 nFireworkId;
		BOOL ResetBuffsOnFinish;
		INT32 rewardLostId;
		INT32 rewardLostCount;
		INT32 nResetReuseSkills;

		BOOL MostrarTitlesKills;
		wstring TitleCustomBlue;
		wstring TitleCustomRed;
		INT32 TitleColorBlue;
		INT32 TitleColorRed;

		BOOL MeterAlEventoSiHayCritico;

		INT32 InvertirPuestos;
		list<wstring> MurallasList;

		BOOL MostrarMuertesParaElTop;

		INT32 rank_rewardId_1;
		INT32 rank_rewardCount_1;
		tstring rank_rewardMsg_1;
		INT32 rank_rewardId_2;
		INT32 rank_rewardCount_2;
		tstring rank_rewardMsg_2;
		INT32 rank_rewardId_3;
		INT32 rank_rewardCount_3;
		tstring rank_rewardMsg_3;
		INT32 rank_rewardId_4;
		INT32 rank_rewardCount_4;
		tstring rank_rewardMsg_4;
		INT32 rank_rewardId_5;
		INT32 rank_rewardCount_5;
		tstring rank_rewardMsg_5;

		tstring messagePlayersCouns;

		INT32 teleportDelay;

		INT32 MaximoVidasPorEquipo;
		BOOL pvpReward;

	};

	class CMatch
	{
		friend class CTvT;
	protected:
		CRITICAL_SECTION m_lock;
	private:
		inline void Lock() { EnterCriticalSection(&m_lock); }
		inline void Unlock() { LeaveCriticalSection(&m_lock); }

		TvTInfo* m_lpInfo;
		map<UINT, User*> m_users;
		map<UINT, TvTUser> m_usersBackup;
		map<UINT, User*> m_Kusers;
		TvTState m_state;
		time_t m_startTime;
		time_t m_stateTime;
		UINT m_managerServerId;
		UINT m_managerServerId2;
		UINT m_managerServerId3;
		UINT m_buffer1;
		UINT m_buffer2;
		UINT m_buffer3;
		UINT m_buffer4;
		TeamType m_winnerTeam;
		INT32 m_killCountBlue;
		INT32 m_killCountRed;
		INT32 m_KoreanBlue;
		INT32 m_KoreanRed;
		UINT m_KoreanWinner;
		BOOL m_FlagsSpawned;
		UINT m_BlueFlag;
		UINT m_RedFlag;



		INT32 m_ctfCaptureCountBlue;
		INT32 m_ctfCaptureCountRed;
		UINT m_CtfUserFlag_blue;
		UINT m_CtfUserFlag_red;
		TeamType m_winnerTeamCapture;

		TeamType m_winnerTeamDestroyBase;
		INT32 m_BaseBlueDestroyed;
		INT32 m_BaseRedDestroyed;


		TeamType m_winnerTeamCastFortress;
		INT32 m_tomasCountBlue;
		INT32 m_tomasCountRed;

		UINT m_managerServerId12;
		UINT m_managerServerId13;
		UINT m_managerServerId14;
		UINT m_managerServerId15;
		UINT m_managerServerId16;

	public:
		CMatch(TvT::TvTInfo *pInfo);
		void Init();
		~CMatch();
		void OnExit(User *pUser);
		void OnFinish();
		void OnDelete();
		bool ValidateWinner(bool timeout = false);
		void Broadcast(const char* format, ...);
		void RandomizeTeams();
		//bool PickPlayers();
		bool PickPlayers(bool nIsCTF=true);
		bool PickPlayersLastMan();
		void RemovePlayers();
		//bool PickPlayersForMatch();
		//inline bool FlagsAreSpawned() { return m_FlagsSpawned; };
	};
};

#endif