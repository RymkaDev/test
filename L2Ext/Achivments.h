#pragma once

#include "DBSocket.h"

class Achivments
{
		struct AchivRewards
		{
			INT32 itemId;
			INT32 count;
			AchivRewards() : itemId(-1), count(-1) { };
		};

		struct ConditionBoss
		{
			INT32 NpcId;
			INT32 Counts;
			ConditionBoss() : NpcId(-1), Counts(-1) { };
		};

		struct ConditionMob
		{
			INT32 NpcId;
			INT32 Counts;
			ConditionMob() : NpcId(-1), Counts(-1) { };
		};

		struct ConditionItem
		{
			INT32 ItemId;
			INT32 Counts;
			ConditionItem() : ItemId(-1), Counts(-1) { };
		};

		enum Conditions
		{
			ENUM_OLYMPIAD = 1,
			ENUM_DEATHMATCH = 2,
			ENUM_LASTTEAMSTANDING = 3,
			ENUM_DESTROYTHEBASE = 4,
			ENUM_CAPTURETHEFLAG = 5,
			ENUM_SAVESCAPTURETHEFLAG = 6,
			ENUM_VOTE = 7,
			ENUM_PVP = 8,
			ENUM_BOSS = 9,
			ENUM_MOB = 10,
			ENUM_ITEM = 11,
			ENUM_PK = 12,
			ENUM_LOGIN = 13,
			ENUM_HERO = 14,
			ENUM_ZIZE = 15,
		};

		struct AchivData
		{
			INT32 ConditionOlympiad;
			INT32 ConditionDeathMatch;
			INT32 ConditionLastTeamStanding;
			INT32 ConditionDestroyTheBase;
			INT32 ConditionCaptureTheFlag;
			INT32 ConditionSavesCaptureTheFlag;
			INT32 ConditionVote;
			INT32 ConditionPvP;
			INT32 ConditionPk;
			INT32 ConditionLogin;
			INT32 ConditionHero;
			vector<ConditionBoss> ListConditionBoss;
			vector<ConditionMob> ListConditionMob;
			vector<ConditionItem> ListConditionItem;
			vector<AchivRewards> RewardList;


			AchivData() : ConditionOlympiad(-1), ConditionDeathMatch(-1), ConditionLastTeamStanding(-1), ConditionDestroyTheBase(-1), ConditionCaptureTheFlag(-1), ConditionSavesCaptureTheFlag(-1), ConditionVote(-1), ConditionPvP(-1), ConditionPk(-1) { };
		};

		struct Achiv
		{
			INT32 Id;
			INT32 position;
			INT32 timeReset;
			INT32 hwid;
			wstring name_message;
			wstring name;
			wstring description;
			AchivData data;

			Achiv() : Id(-1), position(-1) , timeReset(-1), hwid(0) { };
		};

	public:

		vector<Achiv> m_Achiv;

		vector<INT32> m_Achiv_Mobs; //public para pasar a las estructuras User*

		void LoadINI();
	
		bool Bypass(User* pUser, wstring wBypass);

		void DB_GetCharacterData(User* pUser);
		void DB_GetHWIDs();
		static bool DB_GetHWIDsReceived(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
		static bool DB_GetCharacterDataReceived_1(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
		static bool DB_GetCharacterDataReceived_2(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
		static bool DB_GetCharacterDataReceived_3(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);

		void DB_SaveHWIDs();
		void DB_SaveCharacterData_1(User* pUser);
		void DB_SaveCharacterData_2(User* pUser);
		void DB_SaveCharacterData_3(User* pUser);

		void OnEnterWorld(User* pUser);
		void TimerExpired(User* pUser);
		void Save(User* pUser);
		void VerificarParaCobrar(User* pUser);	//OK


		static bool Achivments::UserExCommandAchivement(User *pUser, wstring params);
		wstring ReplaceOptions(wstring wHtml, User* pUser);

		void Rewards(User* pUser, INT32 id);
		bool VerificarHwid(User* pUser, INT32 AchivId, INT32 timeReset);

		void SetUser_Olympiad(User* pUser);
		void SetUser_DeathMatch(User* pUser);
		void SetUser_LastTeamStanding(User* pUser);
		void SetUser_DestroyTheBase(User* pUser);
		void SetUser_CaptureTheFlag(User* pUser);
		void SetUser_SavesCaptureTheFlag(User* pUser);
		void SetUser_Vote(User* pUser);
		void SetUser_PvP(User* pUser);
		void SetUser_Pk(User* pUser);
		void SetUser_Login(User* pUser);
		void SetUser_Hero(User* pUser);
		void SetUser_KillMob(CNPC* pNpc, CCreature* pUser);

};


extern Achivments g_Achivments;