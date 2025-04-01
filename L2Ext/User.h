#pragma once
#include "CCreature.h"
#include "MacAddress.h"
#include "ItemBonus.h"
#include "OlympiadUser.h"
#include "Friends.h"
#include "Auction.h"

#define VALIDATE_AUTO_HP_TIMER 10101
#define VALIDATE_AUTO_MP_TIMER 10102
#define VALIDATE_AUTO_CP_TIMER 10103
#define VALIDATE_AUTO_CP_ADV_TIMER 10104

struct BlockItemInfo
{
	UINT databaseId;
	INT32 itemId;
	INT32 enchant;
};

namespace TvT
{
	enum UserStatus
	{
		UserNone = 0,
		UserRegistered = 1,
		UserPreparing = 2,
		UserFighting = 3,
		UserFinishing = 4
	};
	enum TeamType
	{
		TeamNone = 0,
		TeamBlue = 1,
		TeamRed = 2
	};

	struct TvTUser
	{
		UserStatus status;
		TeamType team;
		IVector orgPos;
		IVector respawnPos;
		INT32 resetTimer;
		INT32 respawnTick;
		INT32 number;
		BOOL friendlyFire;
		INT32 korean_par;
		INT32 korean_start;
		INT32 korean_start_hp;
		BOOL flag;
		INT32 killCount;
		BOOL kicked;

		TvTUser()
		{
			Clear();
		}
		inline void Clear()
		{
			status = UserNone;
			team = TeamNone;
			respawnTick = 0;
			resetTimer = 0;
			friendlyFire = 0;
			number = 0;
			korean_par = 0;
			korean_start = 0;
			korean_start_hp = 0;
			flag = 0;
			orgPos.x = 0;
			orgPos.y = 0;
			orgPos.z = 0;
			flag = 0;
			killCount = 0;
			kicked = 0;
		}
	};
};


//---------------------ACHIVEMENTS-------------------------------------
enum AchivEstadoUser
{
	ENUM_NOEXISTE = 0,
	ENUM_ENPROCESO = 1,
	ENUM_PARACOBRAR = 2,
	ENUM_FINALIZADO = 3,
};

struct AchivDataUser
{
	wstring UltimoHTML;
	map<INT32, AchivEstadoUser> ListAchivState;	//AchivId, estado
	map<INT32, INT32> ListAchivTime;	//AchivId, time
	INT32 Olympiad;
	INT32 DeathMatch;
	INT32 LastTeamStanding;
	INT32 DestroyTheBase;
	INT32 CaptureTheFlag;
	INT32 SavesCaptureTheFlag;
	INT32 Vote;
	INT32 PvP;
	INT32 Pk;
	INT32 Login;
	INT32 Hero;
	map<INT32, INT32> KillMobCounts;	//MobId, Cantidad
	bool Save;
	bool HayCambio;

	AchivDataUser() : Olympiad(0), DeathMatch(0), LastTeamStanding(0), DestroyTheBase(0), CaptureTheFlag(0), SavesCaptureTheFlag(0), Vote(0), PvP(0), Pk(0), Login(0), Hero(0), Save(0), HayCambio(0) { };
};
//----------------------------------------------------------


struct FractionUser
{
	CSLock lock;
	INT32 fractionId;
	UINT points;
	time_t leaveTimestamp;
	map<UINT, UINT> killedPlayerTimestamps;
	FractionUser()
	{
		Clear();
	}
	inline void Clear()
	{
		fractionId = 0;
		points = 0;
		leaveTimestamp = 0;
	}
};

struct QueuedBuff
{
	CSkillInfo *pSI;
	INT32 abnormalTime;
	bool summon;
	UINT npc_ObjectId;
	QueuedBuff() : pSI(0), summon(false), abnormalTime(0), npc_ObjectId(0) {}
};

struct SchemeBufferUser
{
	CSLock lock;
	vector<QueuedBuff> buffQueue;
	BOOL timerInUse;
	UINT useTick;
	//vector<SkillPchId> buffList;

	vector<SkillPchId> buffList1;
	vector<SkillPchId> buffList2;
	vector<SkillPchId> buffList3;
	vector<SkillPchId> buffList4;
	vector<SkillPchId> buffList5;
	vector<SkillPchId> buffList6;
	vector<SkillPchId> buffList7;
	vector<SkillPchId> buffList8;
	vector<SkillPchId> buffList9;
	WCHAR buffList1_Name[15];
	WCHAR buffList2_Name[15];
	WCHAR buffList3_Name[15];
	WCHAR buffList4_Name[15];
	WCHAR buffList5_Name[15];
	WCHAR buffList6_Name[15];
	WCHAR buffList7_Name[15];
	WCHAR buffList8_Name[15];
	WCHAR buffList9_Name[15];


//	vector<SkillPchId> summonBuffList;
//	vector<SkillPchId> remoteBuffList;
//	vector<SkillPchId> remoteSummonBuffList;
	bool saveList;
	bool inBlockZone;

	SchemeBufferUser(): useTick(0), timerInUse(0), saveList(false), inBlockZone(false) {};

	inline vector<SkillPchId>& GetList(bool summon, bool remote, int Id)
	{
		if(Id == 1)
			return buffList1;
		else if(Id == 2)
			return buffList2;
		else if(Id == 3)
			return buffList3;
		else if(Id == 4)
			return buffList4;
		else if(Id == 5)
			return buffList5;
		else if(Id == 6)
			return buffList6;
		else if(Id == 7)
			return buffList7;
		else if(Id == 8)
			return buffList8;
		else if(Id == 9)
			return buffList9;


		return buffList1;
	}
};

struct SentHtml
{
	UINT classId;
	WCHAR wHtml[16382];
	WCHAR wName[260];
};


struct SkillDmgMultipler
{
	int skillId;
	int level;
	double multipler;
	SkillDmgMultipler() : skillId(0), level(0), multipler(1.0) {};
};

struct AutoCastSkill
{
	enum Type
	{
		OnDamaged = 1,
		OnPhysicalAttack = 2,
		OnMagicalAttack = 3,
		OnCriticalAttack = 4
	};
	UINT type;
	int skillId;
	int level;
	double chance;
	AutoCastSkill() : skillId(0), level(0), chance(0.0) {};
};

struct AuctionUser
{
	UINT createTimeout;
	UINT itemServerId;
	UINT itemClassId;
	BOOL pendingAuction;
	UINT paymentAskTimestamp;
};

struct VisualArmorUser
{
	UINT floodTimestamp_test;
	UINT floodTimestamp;
	UINT armorId;
	UINT armorType;
	int chestSlotId;
	int legsSlotId;
	int glovesSlotId;
	int feetSlotId;
	int hairSlotId;
	int minLevel;
	int maxLevel;
	VisualArmorUser() { Clear(); };
	void Clear()
	{
		memset(this, 0, sizeof(VisualArmorUser));
	}
};

struct WeddingUser
{
	enum State
	{
		WeddingNone = 0,
		WeddingAskEngage = 1,
		WeddingEngaged = 2,
		WeddingAskMarry = 3,
		WeddingMarried = 4
	};
	UINT state;
	UINT partnerId;
	wstring partnerName;
	UINT penaltyTimeout;
	UINT teleportTimeout;
	UINT bigHeadTimeout;
	UINT weddingTime;
	WeddingUser() : state(WeddingNone), partnerId(0), penaltyTimeout(0), teleportTimeout(0), bigHeadTimeout(0), weddingTime(0) {};
	void clear() { state = WeddingNone; partnerId = 0; partnerName.clear(); };
};

struct AutoConsumeInfo;

struct ItemAutoConsumeData
{
	INT32 itemId;
	UINT lastUseTick;
	AutoConsumeInfo *pInfo;
	ItemAutoConsumeData() : itemId(0), lastUseTick(0), pInfo(0) {};
};

struct SubStackInfo
{
	UINT classId[4][2];	//subjobId, baseClass/stackClass
	UINT timestamp;
	SubStackInfo() : timestamp(GetTickCount())
	{
		for(UINT n=0;n<4;n++)
		{
			classId[n][0] = classId[n][1] = UINT_MAX;
		}
	}
};

struct InstanceData
{
	UINT instanceId;
	UINT timeSpent;
	UINT incTimeTick;
	UINT reuseTimeout;
	bool saved;
	InstanceData() : instanceId(0), timeSpent(0), incTimeTick(0), reuseTimeout(0), saved(false) {};
};

struct HiddenAbnormalData : AbnormalData
{
	time_t hideExpireTimestamp;
	bool restored;
	HiddenAbnormalData() { hideExpireTimestamp = 0; restored = false; };
	HiddenAbnormalData(const AbnormalData& other)
	{
		restored = false;
		hideExpireTimestamp = 0;
		pSI = other.pSI;
		expireTime = other.expireTime;
		selfBuff = other.selfBuff;
		casterSID = other.casterSID;
		partyBuff = other.partyBuff;
	};
};

struct L2NetworkUser
{
	WCHAR identity[33];
	UINT lastVoteTime;
	UINT lastRewardTime;
	bool loaded;
	UINT checkTimestamp;
	L2NetworkUser() : lastVoteTime(0), lastRewardTime(0), loaded(false), checkTimestamp(0) { memset(identity, 0, sizeof(identity)); };
};

struct ChampionshipUserS
{
	UINT matchId;
	UINT teamType;
	UINT state;
	IVector orgPos;
	void Clear()
	{
		matchId = 0;
		teamType = 0;
		state = 0;
	};
};


struct RebirthUser
{
	INT32 rebirthCount;
	INT32 availablePoints;
	INT32 bonusInt;
	INT32 bonusStr;
	INT32 bonusCon;
	INT32 bonusMen;
	INT32 bonusDex;
	INT32 bonusWit;
	RebirthUser() : rebirthCount(0), availablePoints(0), bonusInt(0), bonusStr(0), bonusCon(0), bonusMen(0), bonusDex(0), bonusWit(0) {};
};

struct PvPAnnounceUser
{
	INT32 killCount;
	time_t lastKillTime;
	PvPAnnounceUser() : killCount(0), lastKillTime(0) {}
};

struct DonateAugmentWeapons
{
	UINT nDBid;
	UINT nItemID;
	UINT nEnchant;
	DonateAugmentWeapons() : nDBid(0), nItemID(0), nEnchant(0) {}
};

struct UserExtData
{
	CSLock lock;
	CSLock lockAuction;
	CSLock lockDonateAugment;
	bool autoLoot;
	volatile LONG userInfoChanged;
	volatile LONG charInfoChanged;
	volatile LONG itemListChanged;
	volatile LONG abnormalStatusChanged;
	volatile LONG validateParametersRequest;
	volatile LONG saveitemsex;
	UINT spawnProtection;
	UINT spawnProtectionTimeout;
	UINT spawnProtectionTimeSent;
	INT32 charmOfCourageLevel;
	CItemBonus itemBonus;
	INT32 cursedWeaponId;
	INT32 cursedWeaponLevel;
	TvT::TvTUser tvtUser;
	UINT miningAreaId;
	FractionUser fractionUser;
	map<INT32, INT32> itemSkills;
	DWORD nicknameColor;
	DWORD titleColor;
	INT32 antiPkLevelRange;
	UINT itemDeliveryTimestamp;
	UINT invalidTick;
	UINT aioId;
	UINT aioTimestamp;
	UINT aioNicknameColor;
	UINT autoInfinitySoulshot[6];
	UINT autoInfinitySpiritshot[6];
	UINT autoInfinitySoulshot_2[6];
	UINT autoInfinitySpiritshot_2[6];
	AuctionUser auctionUser;
	vector<AuctionItemList> m_ItemAuctionList;
	SchemeBufferUser schemeBufferUser;
	VisualArmorUser visualArmorUser;
	CSLock sentHtmlLock;
	vector<SentHtml> sentHtml;
	vector<SkillDmgMultipler> skillDmgMultiplers;
	vector<AutoCastSkill> autoCastSkills;
	INT32 bonusInt;
	INT32 bonusStr;
	INT32 bonusCon;
	INT32 bonusMen;
	INT32 bonusDex;
	INT32 bonusWit;
	UINT multiSellGroupId;
	INT32 voteRewardPoints;
	UINT voteRewardTick;
	BOOL voteRewardMsgRequest;
	WeddingUser weddingUser;
	BOOL leftWorld;
	UINT nameColorEx;
	UINT titleColorEx;
	UINT vipChatTimestamp;
	UINT broadcastCombatModeTimestamp;
	BYTE lockHash[32];
	BYTE tempLockHash[32];
	bool isLocked;
	UINT lockAttempts;
	INT32 dailyPvPAmount;	//amount of daily pvp
	UINT dailyPvPTimestamp;	//this will tell us when player get last pvp if it wasn't in this day we'll reset pvp amount
	//Captcha & Jail Start
	UINT mobsKilled;
	UINT captchaQuestionR;
	wstring captchaQuestion;
	wstring captchaWQuestion1;
	wstring captchaWQuestion2;
	UINT captchaWrongTimes;
	UINT captchaPeriod;
	UINT captchaMode;
	UINT captchaUniqueID;
	UINT captchaJail;
	UINT jailtimeout;
	UINT captchareporttimes;
	UINT captchaProtection;
	UINT captchaProtectionTimeout;
	UINT captchaProtectionTimeSent;
	//Captcha & Jail End
	UINT nInCustomDailyPvPZone;
	UINT nInCustomBuffZone;
	UINT nInCustomShowHPZone;
	UINT nFactionID;
	UINT nInFactionPvpZone;
	UINT nInBuffZone;
	UINT nInBlockAllSkillsZone;
	UINT event_kills;
	UINT event_deaths;
	UINT inventory_limit;
	UINT m_ExPacketUseTimes;
	UINT m_TimeToBotRecheck;
	//UINT m_BotStringNumber1;
	//UINT m_BotStringNumber2;
	UINT nInCustomAntiPkZone;
	UINT nInCustomAntiRejunteZone;
	UINT nInCustomAntiRejunteZoneTime;

	UINT nofflinesellbuffprice;
	wstring offlineselltitle;
	//vector<OfflineBufferSkills> offlinesellbuffs;
	map<INT32, INT32> m_offlinesellbuffs;
	vector<wstring> m_BuffPagePlayer;
	vector<wstring> m_BuffPagePet;

	ItemAutoConsumeData autoConsumeHp;
	ItemAutoConsumeData autoConsumeMp;
	ItemAutoConsumeData autoConsumeCp;
	ItemAutoConsumeData autoConsumeCpAdv;

	SubStackInfo subStackInfo;
	vector<HiddenAbnormalData> hiddenAbnormals;
	bool requestSaveAllSkills;
	UINT currentInstanceId;
	vector<InstanceData> instances;
	UINT skillMasterFlag;
	
	DWORD chatTimestamp[18];

	L2NetworkUser l2networkUser;
	RebirthUser rebirthUser;
	bool preserveAbnormalTerritory;
	UINT raceChangeZoneId;
	UINT fakeRace;
	UINT fakeSex;
	UINT blockChatZoneId;
	UINT BlockAppeZoneId;
	bool gradePenaltySet;
	PvPAnnounceUser pvpAnnUser;
	list<wstring> m_Applications;
	//Auction Info
	map<UINT, AuctionItem> m_AuctionItems;
	UINT m_AuctionExpire;
	map<UINT, AuctionItem> m_AuctionItemsMy;
	UINT m_AuctionExpireMy;
	UINT m_TotalAuctions;
	UINT m_AuctionSearchGrade;
	UINT m_AuctionSearchCategory;
	UINT m_AuctionSearchSubCategory;
	wstring wAuctionSearchItemName;

	//Vote Reward
	UINT m_LastCheckVote;

	//WCHAR wShopTitle[50];
	wstring wShopTitle2;
	UINT uos_activateauto;

	UINT nInCustomNoPKZone;
	UINT nInCustomNoPKZoneTime;

	bool nInPvpZoneSteal;

	vector<DonateAugmentWeapons> m_DonateItemsAugment;
	vector<wstring> m_PagesAugmentDonation;
	short customVerAuraHero;
	UINT hats_test_id;
	UINT hats_test_timestamp;
	WCHAR OriginalwTitle[25];
	UINT OriginalnameColorEx;
	UINT OriginaltitleColorEx;
	UINT m_CtfUserFlag;
	UINT m_CtfUserFlagWeapon;
	AchivDataUser AchivSystem;
	UINT InstanceId;
	int	nCustomSubClassIndex;
	int	nCustomSubClass[4];
	bool dropItems;
	int inEventPvp;
	bool inEventPvpLocked;
	bool nNoSumarPVPniPk;
	bool nTestTvTUserSiFueCritico;
	bool inZoneCustomEventPvp;

	UINT nInCustomEventClanZone;
	UINT m_TimeResTeleport;
	WCHAR original_wTitle[25];
	INT32 WeapontTypeHand;
	INT32 EventPvpPointsTotal;
	INT32 EventPvpPointsTemporal;
	INT32 EventPvpCategoria;
	HWID EventPvplongHWID;
	double EventPvpDanio;
	bool enviarDanio;


	bool actualizarApariencias;
	int custom_sex;
	int customSkin;
	int Race;
	double ColRadius;
	double ColHeight;

	ChampionshipUserS championshipUser;
	double DropSpoilEnchantWeapon;
	double DropSpoilEnchantArmor;

	UINT shield_test_id;
	UINT shield_test_timestamp;

	UINT weapon_test_id;
	UINT weapon_test_timestamp;

	bool EsMago;



	UserExtData() : gradePenaltySet(false), skillMasterFlag(0), preserveAbnormalTerritory(false), fakeRace(UINT_MAX), fakeSex(UINT_MAX), raceChangeZoneId(0), blockChatZoneId(0), BlockAppeZoneId(0), customVerAuraHero(true), hats_test_id(0), hats_test_timestamp(0),m_CtfUserFlag(0),m_CtfUserFlagWeapon(0), InstanceId(0), nCustomSubClassIndex(0), dropItems(true), inEventPvp(0), inEventPvpLocked(0), nNoSumarPVPniPk(0), nTestTvTUserSiFueCritico(0), m_TimeResTeleport(0), nInCustomEventClanZone(0), WeapontTypeHand(0), inZoneCustomEventPvp(0), EventPvpPointsTotal(0), EventPvpPointsTemporal(0), EventPvpCategoria(0), EventPvpDanio(0), nInCustomAntiRejunteZone(0), nInCustomAntiRejunteZoneTime(0), enviarDanio(1), custom_sex(-1), customSkin(-1), Race(-1), ColRadius(0), ColHeight(0), actualizarApariencias(TRUE), DropSpoilEnchantWeapon(1), DropSpoilEnchantArmor(1), shield_test_id(0), shield_test_timestamp(0), weapon_test_id(0), weapon_test_timestamp(0), EsMago(0) {};
};

class CPrivateStoreItemData
{
public:
	CPrivateStoreItemData() { memset(this, 0, sizeof(CPrivateStoreItemData)); }
/*00*/	DWORD ObjectID; //in sell
/*04*/	DWORD n2;
/*08*/	WORD Enchant;
/*0A*/	WORD w4;
/*0C*/	DWORD n5;
/*10*/	int ItemIndex;	//in sell
/*14*/	int Count;
/*18*/	int ClassID;
/*1C*/	int Price;
};

class CRecipeInfo
{
public:
	CRecipeInfo() : RecipeID(0), Level(0), MpConsume(0), SuccessRate(0), ItemID(0) { };
/*00*/	int RecipeID;
/*04*/	int Level;
/*08*/	int MpConsume;
/*0C*/	int SuccessRate;
/*10*/	int ItemID;
};

class CRecipeInfoData
{
public:
	CRecipeInfoData() : pInfo(NULL), Price(0) {  };
/*00*/ CRecipeInfo *pInfo;
/*08*/ int Price;
};

typedef map<int, CRecipeInfo*> RecipeInfoMap;
typedef map<int, CRecipeInfoData*> PrivateStoreRecipeMap;
typedef map<int, CPrivateStoreItemData*> PrivateStoreItemMap;

class User: public CCreature
{
public:
	/* 1500 */ LPVOID _unkn1500[32];
	/* 1600 */ LPVOID _unkn1600[32];	
	/* 1700 */ LPVOID _unkn1700[32];
	/* 1800 */ LPVOID _unkn1800[32];
	/* 1900 */ //LPVOID _unkn1900[32];

	/* 1900 */ LPVOID _unkn1900[29];
	/* xxxx */ INT32 _unkn1Axx;

	/*19F0 */ int run_speed;
	/*19F4 */ int walk_speed;
	/* xxxx */ INT32 _unkn1Axx2;
	/* xxxx */ LPVOID _unkn190xx0;


	/* 1A00 */ LPVOID _unkn1A00[8];
	/* 1A40 */ bool soulShotInUse;
	/* 1A41 */ bool spiritShotInUse;
	/* 1A42 */ bool summonSoulShotInUse;
	/* 1A43 */ bool summonSpiritShotInUse;
	/* 1A44 */ INT32 _unkn1A44;
	/* 1A48 */ //LPVOID _unkn1A48[3];


	/* 1A48 */ LPVOID _unkn1A48[2];
		int m_nSnoopGmId;
		int m_nSnoopClientId;


	/* 1A60 */ bool _unkn1A60;
	/* 1A61 */ bool _unkn1A61;
	/* 1A62 */ bool equippedFormalWear;
	/* 1A63 */ bool _unkn1a63;
	/* 1A64 */ UINT _unkn1a64;
	/* 1A68 */ LPVOID _unkn1A68[7];

	/* 1AA0 */ UINT _unkn1AA0;
	/* 1AA4 */ UINT soulshotUseTick;
	/* 1AA8 */ UINT autoSoulshotFlag;
	/* 1AAC */ bool isEnchantingItem;
	/* 1AAD */ bool _unkn1AAD[3];


	/* 1AB0 */ UINT m_nLastUseDice;
	/* 1AB4 */ UINT m_FootEffect;
	/* 1AB8 */ UINT m_FootEffectEndTick;
	/* 1ABC */ //UINT _unkn1ABC;

	/* 1ABC */ bool m_bCameraMode;
			   bool aaa1;
			   bool aaa2;
			   bool aaa3;

	/* 1AC0 */ LPVOID _unkn1AB8[8];
	/* 1B00 */ LPVOID _unkn1B00[32];
	/* 1D00 */ LPVOID _unkn1D00[32];
	/* 1C00 */ LPVOID _unkn1C00[32];
	/* 1E00 */ LPVOID _unkn1E00[32];
	/* 1F00 */ LPVOID _unkn1F00[32];
	/* 2000 */ LPVOID _unkn2000[32];
	/* 2100 */ LPVOID _unkn2100[32];
	/* 2200 */ LPVOID _unkn2200[32];
	/* 2300 */ LPVOID _unkn2300[32];
	/* 2400 */ LPVOID _unkn2400[32];
	/* 2500 */ LPVOID _unkn2500[32];
	/* 2600 */ LPVOID _unkn2600[14];
	/* 2670 */ CUserSocket *pSocket;
	/* 2678 */ UINT tradeId;
	/* 267C */ UINT peti_id;


	/* 2680 */ int m_nWaitPetitionVote;
			   int rrrrree;

	/* 2688 */ LPVOID _unkn2688[3]; //LPVOID _unkn2680[16];
									 //LPVOID _unkn2700[32];

	/* 26A0 */ map<int, CRecipeInfoData*> m_ItemRecipeMap;
	/* 26B8 */ map<int, CPrivateStoreItemData*> m_ItemSellMap;
	/* 26D0 */ map<int, CPrivateStoreItemData*> m_ItemBuyMap;
	/* 26E8 */ WCHAR wszSellStoreText[30];
	/* 2724 */ WCHAR wszBuyStoreText[30];
	/* 2760 */ WCHAR wszRecipeStoreText[30];
	/* 279C */ int nPackageSell;
	/* 27A0 */ //int nUknown279C[24];

    /* 27A0 */ int nUknown279C[21];
			   bool m_bCanHearWhisper;
			   bool xxxx1;
			   bool xxxx2;
			   bool xxxx3;
			  int nUknown279Ca[1];
			  wchar_t m_sAccountName[15];
	/* 2800 */ LPVOID _unkn2800[8];


	/* 2800 */ //LPVOID _unkn2800[12];
	/* 2860 */ UINT _unkn2860;
	/* 2864 */ UINT pledgeServerId;

	/* 2868 */ //LPVOID _unkn2868;
	/* 2868 */ UINT m_nPartySid;
	/* 286C */ UINT m_nTradeTimeStamp;

	/* 2870 */ CFriends *pFriends;
	/* 2878 */ WCHAR wTitle[25];

	/* 28AA */ USHORT _align28AA;

	/* 28AC */  UINT m_nPledgeDismissTime;
	/* 28B0 */  UINT m_nPledgeOustedTime;
	/* 28B4 */  UINT m_nPledgeWithdrawTime;


	/* 28B8 */ UINT _unkn28B8;
	/* 28BC */ UINT _unkn28BC;
	/* 28C0 */ UINT _unkn28C0;
	/* 28C4 */ UINT _unkn28C4;

	/* 28C8 */ BYTE m_bFriendAddEnabled;
	/* 28C9 */ BYTE m_bTradeEnabled;
	/* 28CA */ bool blockAllChat;
	/* 28CB */ BYTE _aling28CB[5];

	/* 28D0 */ LPVOID _unkn28D0[6];

	/* 2900 */ LPVOID _unkn2900[1];
	/* 2908 */ UINT multisellNpcId;
	/* 290C */ UINT _align200C;
	/* 2910 */ LPVOID _unkn2910; //LPVOID _unkn2190[6];
	
	/* 2918 */ int InventorySlots; //inventory
	/* 291C */ int WarehouseSlots; //warehouse
	/* 2920 */ int RecipeDwarvenSlots; //recipe dwarven
	/* 2924 */ int RecipeCommonSlots; //recipe common

	/* 2928 */ int _unkn2928;
	/* 292C */ int _unkn292C;
	/* 2930 */ int _unkn2930;
	/* 2934 */ int _unkn2934;
	/* 2938 */ int _unkn2938;
	/* 293C */ int _unkn293C;
	
	/* 2940 */ UINT _unkn2940;
	/* 2944 */ UINT stopSayTick;
	/* 2948 */ LPVOID _unkn2948[2];

	/* 2958 */ UINT killDamageType;	//set to 5 in killme, set as damage type 
	/* 295C */ UINT _unkn295C;

	/* 2960 */ LPVOID _unkn2960[20];

	/* 2A00 */ LPVOID _unkn2A00[32];
	/* 2B00 */ LPVOID _unkn2B00[14];
	/* 2B70 */ long relationChangedRequest;
	/* 2B74 */ UINT m_nPledgeCrestDbId;

	/* 2B78 */ UINT m_nPledgeEmblemDbId;
	/* 2B7C */ UINT _unkn2B7C;

			  //LPVOID _unkn2B78[6];
			  const CSkillInfo *m_pNowSkill;
			  int m_nSkillEndTime;
			  int m_nSkillTargetId;
			  //LPVOID _unkn2B78b[7];
			  LPVOID _unkn2B78b[9];

	/* 2B80 */ UINT m_nFortressUnderOffenceSiegeId;
	/* 2B84 */ UINT m_nFortressUnderDefenceSiegeId;

			  LPVOID _unkn2B88[2];
			  UINT m_PetActionLastTick;
			  UINT ffsf;

	/* 2BF8 */ UINT summonId;
	/* 2BFC */ int nObservationTime;
	/* 2C00 */ //LPVOID _unkn2C00[21];

	/* 2C00 */ LPVOID _unkn2C00[1];
			  UINT m_dwPrivateStoreTick;
			  UINT zzzz1;
			  LPVOID _unkn2C00a[11];
			  int m_dwL2CommTick;
			  int fffff2;
			  LPVOID _unkn2C00b[7];


	/* 2CA8 */ UINT _unkn2CA8;
	/* 2CAC */ BYTE teamCircleId;
	/* 2CAD */ bool _align2CAD[3];
	/* 2CB0 */ COlympiadUser olympiadUser;
	
	/* 2D10 */ LPVOID _unkn2D00[9];
	/* 2D58 */ const WCHAR* wLastHtmlFileName;
	/* 2D60 */ LPVOID _unkn2D60;
	/* 2D68 */ LPVOID _unkn2D68;
	/* 2D70 */ UINT language;
	/* 2D74 */ UINT _unkn2D74;

	//Extended variables
	UserExtData* pED;

	enum RELATION_TYPE
	{
		INSIDE_PVP_ZONE = 1,
		PVP_FLAG = 2,
		KARMA = 4,
		IN_MY_PARTY = 0x20
	};
	static void ExtInit();
	static void OnCreate(User *pUser);
	static User* OnDestruct(User *pUser, DWORD param);
	static void OnDelete(LPVOID lpInstance, UINT userId, const char* file, int line);
	CPledge *GetPledge();
	CUserSocket *GetSocket();
	bool IsNowTrade();
	CParty * User::GetParty();
	void DespawnSummon();
	void DeleteItemInInventoryBeforeCommit(int ItemID, int Count)
	{
		typedef void (*_f)(User*, int, int);
		_f f = (_f) 0x00827150;
		f(this, ItemID, Count);
	}
	CWareHouseDeposit *GetWareHouseDeposit();
	CWareHouseWithdraw *GetWareHouseWithdraw();
	void ActionFailed();
	bool PacketAcceptable(int nPacketNo);
	void SendSystemMessage(PWCHAR Talker, PWCHAR Message);
	void SendSystemMessage(const wchar_t* Talker, const wchar_t* Message);
	void SendSystemMessage(PWCHAR wszMessage);
	void SendSystemMessage(const WCHAR* wszMessage);
	void SendSystemMessage(int msgId);
	void SendSystemMessage(CSystemMessage *pMsg);
	void SendSystemMessageRed(const WCHAR* wszMessage);
	void SendSystemMessageGreen(const WCHAR* wszMessage);
	void SendUserInfo(CUserSocket* bGM = NULL);
	void SendCharInfo(CUserSocket* bGM = NULL);
	void SendHpInfo();
	void SendMpInfo();
	void SendQuestList();
	bool SendCoolTime();
	void SendItemList(bool show = true);
	void SendRelationChanged(CUserSocket *pSocket = 0);
	void SendAcquireSkillToDB(int nSkillID, int nLevel, bool bMayDown = false);
	void SendDeleteSkillToDB(int nSkillID);
	void SendETCBuffStatus();
	void AquireClanSkill(double m_SkillId);
	void SendAbnormalStatusInfo();
	void SendSpelledInfoChanged();
	void SaveInfectedSkills();
	void SendSkillList(bool bNothing, CSocket *pGMSocket);
	bool TeleportToLocation(int x, int y, int z, bool bNotFadeScreen);
	void SetKarma(int nKarma);
	void TradeCancel();
	void ChangeTarget(CCreature *pObject, bool ByUser);
	CSummon *GetSummonOrPet();
	CSummon *GetSummon();
	bool InCombat();
	DWORD CombatTime();
	bool CanEquip(CItem *pItem);
	bool CanGetPartyBonus(CCreature *pCreature);
	bool InCombatZone();
	void IncreaseDuelCount();
	bool UseItem(CItem *pItem, int nForce);
	bool IsItemUsable();
	bool DropItem(CItem *pItem, int nAmount);
	bool UnEquipItem(int nSlotType);
	bool UnEquipItem(CItem* pItem);
	int ExpDown(int nExpDec);
	void SetExpDown(int nExpDec);
	void IncreaseKarma(bool bWithPk);
	CSharedNoblessInfo *GetNoblessInfo();
	void ResetJoinPledgePenalty();
	bool ChangeClass(int nClass);
	bool CanJoinPledge();
	void Ride(CCreature *pCreature);
	void RideWyvern(int wyvernClassId, int level);
	UINT GetPledgeClass();
	int GetAugmentationID();
	int GetAugmentationID(int nItemIndex);
	void DespawnPet(bool byLeaveWorld);
	void PlaySound(PWCHAR wszName, int nCount, int nObjectID, int x, int y, int z);
	void OnDieDropItem(bool bDieOnBattleField);
	PWCHAR GetTitle();
	static User *GetUserBySID(UINT *pSID);
	int GetEquipedItemSlot(int nItemIndex);
	void QuitPrivateStore();
	void QuitPrivateStoreBuy();
	void QuitRecipeStore();
	bool IsAcademyMember();
	void GetOff(bool bForce);
	void ShowHTML(const WCHAR* filename, const WCHAR* buffer, int classID);
	void SetSpelledInfoChanged();
	void SetAbnormalStatusChanged();
	void SetUserInfoChanged();
	void SetCharInfoChanged();
	void SetItemListChanged();
	void ShowBoard(const WCHAR* wHtml);
	void HideBoard();
	void SetLevelByExp(INT32 nExp);
	bool DoExtraValidation();
	bool HaveMemo(int nQuestID);
	int GetMemoState(int nQuestID);
	int GetMemoState2(int nQuestID);
	void SetMemoState(int nQuestID, int nState);
	void SetLevel(int nLevel);
	PrivateStoreItemMap* GetPrivateStoreSell();
	PrivateStoreItemMap* GetPrivateStoreBuy();
	PrivateStoreRecipeMap* GetPrivateStoreRecipe();
	RecipeInfoMap* GetRecipeInfo();
	CRecipeInfo* GetRecipeInfo(int recipeId);
	CPet *GetPet();
	void DeleteItem(CItem *pItem);
	bool IsInCombatMode();
	void ValidateAcquiredSkills(bool log = true);
	void SaveAcquiredSkills();
	int GetTradeSID();
	int GetAccountID();
	void SetCombatMode();
	void SetGuilty(bool c);
	void SetPvPFlag();
	void Kick();
	void SetStopSay(DWORD timeInMs, bool saveInDB = 1);
	void KillMyself();
	void ValidateLifeTimeItems();
	void SendLifeTimeItemsInfo();
	void SendRuneInfo();
	void ValidateItemExSkill();
	bool HaveItemInPrivateStore(int ItemID);
	bool Revive();
	int GetPledgeType();
	int GetPledgeReputation();
	void ValidateTerritory();
	void RequestUpdateSpelledInfo();
	bool ValidateStackableItems();
	bool GetDropBonuses(double& itemDrop, double& adena, double& raidBoss, double& raidBossOnlyChance, double& epicBoss, double &itemOnlyChance);
	double GetAdenaBonus();
	double GetSpoilBonus();
	int CountPlayerInventoryItems();
	void ShowBlockableItems(User *pGM = 0);
	LPBYTE GetHWID();
	INT32 GetMPCCPartyAmount();
	INT32 GetMPCCMemberDistance();
	bool QueueBuff(CSkillInfo *pSI, bool summon, int abnormalTime, UINT npcObjectId = 0);
	bool QueueBuffList(bool summon, bool remote, int abuse, int Id);
	void ActivateQueuedBuff(QueuedBuff& qb);
	void DispatchQueuedBuff();
	void ClearQueuedBuffs();
	double GetSkillDmgMultipler(int skillId, int level);
	bool TiggerAutoCastSkill(AutoCastSkill::Type type, CCreature *pOther);
	inline void SetRelationChangeRequest(int state)
	{
		InterlockedCompareExchange(&relationChangedRequest, state, 0);
	}
	void StopSummon();
	inline void SetValidateParametersRequest()
	{
		InterlockedExchange(&pED->validateParametersRequest, TRUE);
	}
	inline void SetValidateItemsExRequest()
	{
		InterlockedExchange(&pED->saveitemsex, TRUE);
	}

	bool IsFriend(User *pUser);
	void ShowPCCafePoints(INT32 totalPoints, INT32 newPoints, INT32 timeInHours, bool adding);
	void ValidateSubjobParameters();
	void HideAbnormal(AbnormalData& abnormal, UINT expireTime);
	void TimerExpiredForHiddenAbnormals(bool allExpired = false);
	void ClearHiddenAbnormals();
	void SaveInstanceTime(UINT instanceId, UINT previousInstanceId, UINT allowedTime, UINT reuseTime, bool& kick, bool byHwid = false);
	void SaveInstances();
	void ValidateEquippedItems();
	bool IsStanding();
	void SitStand();

	void SetPrivateStoreMsg(unsigned char * msg);
	int SetPrivateStoreList(unsigned char* packet);
	void SetPrivateStoreBuyMsg(unsigned char * msg);
	void SetPrivateStoreBuyList(unsigned char* packet);
	bool RequestRecipeShopManageList(int nShopType);
	void SetRecipeStoreMsg(unsigned char * msg);
	int SetRecipeStoreList(unsigned char* packet);
	static bool ValidateStorageSlot(User *pUser);

	void AutoSkills();
	void AutoSkillsByClass(int nClassID, int nLevel);
	void QuitarSkillDeTerceraDeLasOtrasClases();
	void DeleteAllSkills();
};