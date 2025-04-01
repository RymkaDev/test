#pragma once
#include "DBSocket.h"
#include "CacheD.h"

class CDB
{
/*000*/	CDB *pInstance;	//not in org l2srv class
/*008*/ LPVOID pUnkn008;
/*010*/ LPVOID pUnkn010;
/*018*/ LPVOID pUnkn018;
/*020*/ LPVOID pUnkn020;
/*028*/ CDBSocket *pDBSocket1;
/*030*/ CDBSocket *pDBSocket2;
/*038*/ CDBSocket *pAuthSocket;
public:
	CDB() { pInstance = (CDB*)0x10488E0; };
	inline CDB* GetOrgInstance() { return pInstance; };
	void Send(const char *format, ...);
	void SaveQuestInfo(User *pUser);
	void RequestSavePledgePower(User *pUser);
	void IncreaseUserPKCount(User *pUser);
	void WithdrawPet(User *pUser, CItem *pItem);
	void SendSaveItemInfo(User *pUser);
	void RequestSaveJoinPledgeLevel(int nUserDBID, int nLevel);
	void RequestSaveCharacterInfo(User *pUser, bool notActive, bool force);
	void RequestSaveCharacterForSubJob(User *pUser);
	void RequestUseItem(CItem* pItem, User* pUser, int amount);
	void RequestSetPledgeMemberRank(int nPledgeID, PWCHAR wszName, int nRank);
	void RequestSetPledgePrivilege(int nPledgeID, int nRank, INT32 nPrivilege);
	void RequestReorganizeMember(PWCHAR wszName, int nPledgeType, int nPledgeID);
	void RequestCreateExtPledgeInfo(int nPledgeID);
	void RequestHwids();
	void RequestSetPledgeReputation(int nPledgeID, int nReputation);
	void RequestSetPledgeRbPoints(int nPledgeID, int nPoints, int nRepPoints);
	void RequestSetSponsor(int nCharID, int nSponsorID, int nPledgeID);
	void RequestUpdateUserPledge(User *pUser, CPledge *pPledge, int nUpdateType);
	void RequestSetUserPledgeTypeAndRank(int nDBID, int nRank, int nPledgeType);
	void RequestSetSubCaptain(int nPledgeID, int nPledgeType, PWCHAR wszName, int nCaptainDBID);
	void RequestCreateSubPledge(int nPledgeID, int nPledgeType, PWCHAR wszName);
	void RequestRenameSubPledge(int nPledgeID, int nPledgeType, PWCHAR wszName);
	void RequestAcquirePledgeSkill(int nPledgeID, int nSkillID, int nLevel);
	void RequestEnchantItem(CItem *pScroll, CItem *pItem, int nEnchant, User *pUser);
	void RequestEnchantFail(CItem *pScroll, CItem *pItem, User *pUser);
	void RequestSaveHeroType(User *pUser, int nHeroType);
	void RequestRemoveHero(int nDBID);
	void SendAcquiredSkill(int charId, int skillId, int level, bool mayDown);
	void RequestSaveNoblessType(User *pUser, int nType);
	void RequestDestroyItem(CItem *pItem, int nAmount, User *pUser);
	void RequestPackageSendToTarget(User *pUser, int nTargetDBID, int nAmount, int nBuffSize, PUCHAR Buff, int nNpcClassID);
	void RequestSaveItemDataEx(UINT charId, CItem *pItem);
	void RequestSaveAllItemDataEx(User *pUser);
	void RequestDelegateClanMaster(int nPledgeID, int nCharID);
	void RequestSavePledgeStat(PCHAR Buff, int Size, int MemberCount);
	void RequestLoadWareHouseItems(int nDBID, User *pUser, int nWhID, CWareHouseWithdraw *pWH, int nNpcClassID, int nMemoryID);
	void RequestSaveVoteReward(const WCHAR* wIPaddr, UINT l2topzone, UINT l2topzoneReward, UINT l2hopzone, UINT l2hopzoneReward, UINT l2network, UINT l2networkReward, UINT l2jbrasil, UINT l2jbrasilReward, UINT l2servers, UINT l2serversReward, UINT l2mmotop, UINT l2mmotopReward, UINT lastchecked, const WCHAR* wHwid);
	void RequestLoadVoteReward();
	void RequestSavePrivateStoreInfo(int nCharID, int nStoreType, StoreItemList& lItems, int nOffline, int nCreate);
	void RequestNewbieCheck(User *pUser);
	void RequestLoadPledge(const WCHAR* wPledgeName);
	void RequestModifyPledgeName(unsigned int pledgeId, const WCHAR* wPledgeName);
	void RequestLoadSpiritCount(int nCharID);
	void RequestSaveBuffList(User *pUser);
	void RequestLoadBuffList(int nCharID, int nSubjobIdx);
	void RequestSaveKillDeathStat(int nCharID, int nClassID1, int nLevel, int nCharID2, int nClassID2, int nLevel2, int KillerHP, int KillerMaxHP, int KillerCP, int KillerMaxCP, int x, int y, int z, int PvP, int SkillID, int SkillLevel);
	void RequestCustomEnchantItem(int nUserID, int nItemID, int nEnchant, int scrollId = 0);
	void RequestSaveAIO(int charId, UINT id, UINT timestamp);
	void RequestLoadAIO(int charId);
	void RequestLoadVipStatus(int charId);
	void RequestSaveVipStatus(int charId, int vipLevel, DWORD vipTimestamp);
	void RequestSaveCaptchaStatus(UINT charId, UINT captcha_mobs, UINT captcha_times, UINT captcha_period, UINT captchaQuestionR, UINT captchaUniqueID, UINT captchaJail);
	void RequestCaptchaStatusSite(UINT charId);
	void RequestSaveJailStatus(UINT charId, UINT jailtimeout);
	void RequestSaveCaptchaReportStatus(UINT charId, UINT reporttimes);
	void RequestDeleteItems(DWORD UniqueId, int RequestType, DWORD StartTick,  list<int>& lItems);
	void RequestOwnAgit(int ResidenceId, int PledgeId);
	void RequestRestoreCH(int pledgeId, int lostChId);
	void RequestLoadNpcDeath();
	void RequestSaveNpcDeath(int npc_class_id, DWORD death_time);
	void RequestLoadVIPAccounts();
	void RequestLoadBannedAccounts();
	void RequestLoadVotePoints(int accountId, int charId);
	void RequestSaveVotePoints(int accountId, int charId, int points);
	void RequestBanAccount(UINT accountId, const WCHAR* wName, UINT timestamp, const WCHAR* wReason = L"Default");
	void RequestGetItemFromPet(User *pUser, CItem *pItem, INT32 itemCount);
	void RequestSaveMultiSellLog(UINT charId, UINT accountId, PWCHAR wName, PWCHAR wAccount, INT32 price1Id, INT32 price1Count, INT32 price2Id, INT32 price2Count, INT32 price3Id, INT32 price3Count, INT32 price4Id, INT32 price4Count, INT32 price5Id, INT32 price5Count, INT32 reward1Id, INT32 reward1Count, INT32 reward2Id, INT32 reward2Count, INT32 reward3Id, INT32 reward3Count, INT32 reward4Id, INT32 reward4Count, INT32 reward5Id, INT32 reward5Count, UINT timestamp);
	void RequestLockAccount(UINT accountId, LPBYTE lpHwid, WCHAR* wName);
	void RequestUnlockAccount(UINT accountId);
	void RequestLockChar(UINT charId, LPBYTE lpHwid, WCHAR* wName);
	void RequestUnlockChar(UINT charId);
	void RequestLoadHwidLockData();
	void RequestSaveUserFraction(User *pUser);
	void RequestLoadUserFraction(UINT charId);
	void RequestSetAdditionalBox(UINT accountId, UINT timestamp);
	void RequestLoadAdditionalBoxData();
	void RequestSaveFractionData(UINT fractionId, INT32 points, UINT onlineMembers);
	void RequestLoadFractionData(UINT fractionId);
	void RequestItemDeliveryAsk(UINT charId);
	void RequestItemDeliveryDone(UINT charId, UINT jobId);
	void RequestItemDeliveryAdd(UINT charId, int itemId, int itemAmount, int enchant, int augment);
	void RequestChangePos(WCHAR* wName, UINT worldId, INT32 x, INT32 y, INT32 z);
	void RequestCreateAuction(UINT sellerId, const WCHAR* wSeller, int itemId, int amount, int enchant, UINT augmentation, int priceID, int price, UINT expireTime);
	void RequestModdifyAuctionAmount(UINT auctionId, int newAmount);
	void RequestDeleteAuction(UINT auctionId);
	void RequestLoadAuctionItems();
	void RequestClassChangedJob(User *pUser);
	void RequestSaveSubjob(UINT charId, INT32 subjobId, double hp, double mp, int exp, int sp, int level, int henna1, int henna2, int henna3);
	void RequestAuctionPaymentAsk(UINT charId);
	void RequestAuctionPaymentDone(UINT charId, UINT jobId);
	void RequestAuctionAddPaymentJob(UINT sellerId, int priceItemId, int priceAmount, int itemId, int itemAmount, const WCHAR* wBuyer);
	void RequestAddPledgeSkill(UINT pledgeId, INT32 skillId, INT32 skillLevel);
	void RequestLoadPledgeSkills(UINT pledgeId);
	void RequestSaveWeddingStatus(UINT userId, UINT state, UINT partnerId, const WCHAR* wPartnerName, UINT penaltyTimeout, UINT teleportTimeout, UINT weddingTime);
	void RequestLoadWeddingStatus(UINT userId);
	void RequestTestQuery();
	void RequestLoadRaidBossStatus();
	void RequestLoadPKStatus();
	void RequestLoadPvPStatus();
	void RequestLoadDailyStatus();
	//Olympiad Start
	void RequestLoadOlympiad88();
	void RequestLoadOlympiad89();
	void RequestLoadOlympiad90();
	void RequestLoadOlympiad91();
	void RequestLoadOlympiad92();
	void RequestLoadOlympiad93();
	void RequestLoadOlympiad94();
	void RequestLoadOlympiad95();
	void RequestLoadOlympiad96();
	void RequestLoadOlympiad97();
	void RequestLoadOlympiad98();
	void RequestLoadOlympiad99();
	void RequestLoadOlympiad100();
	void RequestLoadOlympiad101();
	void RequestLoadOlympiad102();
	void RequestLoadOlympiad103();
	void RequestLoadOlympiad104();
	void RequestLoadOlympiad105();
	void RequestLoadOlympiad106();
	void RequestLoadOlympiad107();
	void RequestLoadOlympiad108();
	void RequestLoadOlympiad109();
	void RequestLoadOlympiad110();
	void RequestLoadOlympiad111();
	void RequestLoadOlympiad112();
	void RequestLoadOlympiad113();
	void RequestLoadOlympiad114();
	void RequestLoadOlympiad115();
	void RequestLoadOlympiad116();
	void RequestLoadOlympiad117();
	void RequestLoadOlympiad118();
	//Olympiad End
	void RequestLoadEpicItems();

	void RequestSaveNameColor(UINT charId, UINT namecolor);
	void RequestSaveTitleColor(UINT charId, UINT titlecolor);
	void RequestSaveSkin(UINT charId, UINT skin);
	void RequestLoadSkin();
	void RequestSaveSex(UINT charId, UINT skin);
	void RequestLoadSex();

	void RequestSetNextCastleSiege(User *pUser, CCastle *pCastle, UINT nextSiegeTime);
	void RequestSetNextAgitBattle(CResidence *pResidence);
	void RequestLoadBannedHardwareId();
	void RequestSaveHardwareId(UINT charId, LPBYTE lpHwid);
	void RequestSaveHardwareIdString(UINT charId, WCHAR* lpHwid);
	void RequestBanHardwareId(LPBYTE lpHwid, const WCHAR* wAccount, const WCHAR* wGMName, UINT timeout, UINT times);
	void RequestUnBanHardwareId(LPBYTE lpHwid);
	void RequestLoadNameTitleColor(UINT charId);
	void RequestLoadCaptchaInfo(UINT charId);
	void RequestLoadJailStatus(UINT charId);
	void RequestLoadCaptchaReportStatus(UINT charId);
	void RequestLoadCharacterLock(UINT charId);
	void RequestSaveCharacterLock(UINT charId, LPBYTE lpHash, LPBYTE lpHWID);
	void RequestSaveDailyPvP(UINT charId, INT32 amount, UINT timestamp);
	void RequestSaveDailyPvPEntry(UINT charId, LPBYTE lpHWID, UINT timestamp);
	void RequestLoadDailyPvPEntry();
	void RequestLoadDailyPvP(UINT charId);
	void RequestSaveSubStack(UINT charId, UINT subjobIndex, UINT baseClass, UINT stackClass);
	void RequestLoadSubStack(UINT charId);
	void RequestSaveInstanceTime(UINT charId, UINT instanceId, UINT timeSpent, UINT reuseTimeout);
	void RequestLoadInstanceTime(UINT charId);
	void RequestLoadL2NetworkVote(UINT charId, const WCHAR* wIdentity);
	void RequestSaveL2NetworkVote(const WCHAR* wIdentity, UINT lastVoteTime, UINT lastRewardTime);
	void RequestSaveVisualArmor(UINT charId, UINT armorId);
	void RequestLoadVisualArmor(UINT charId);
	void RequestLoadRebirth(UINT charId, UINT subjobId);
	void RequestSaveRebirth(UINT charId, UINT subjobId, INT32 rebirthCount, INT32 availablePoints, INT32 bonusInt, INT32 bonusStr, INT32 bonusCon, INT32 bonusMen, INT32 bonusDex, INT32 bonusWit);
	void RequestLoadDBNpcMaker();
	void RequestSetCharacterPIN(UINT charId, UINT pin, UINT timestamp);
	void RequestLoadCharacterPINS();
	void RequestLoadClanPvPStatus(UINT pledgeLevel, UINT topLimit);
	void RequestLoadClanRaidStatus(UINT topLimit);
	void RequestLoadClanRaidWinners();
	void RequestResetClanRaidStatus();
	void RequestLoadEventStats(UINT charId);
	void RequestSaveEventStats(UINT charId, UINT event_kills, UINT event_deaths);

	void RequestLoadCustomSubClass(UINT charId);
	void RequestSaveCustomSubClass(UINT charId, int SubClassIndex, int SubClass_0, int SubClass_1, int SubClass_2, int SubClass_3);

	void RequestSaveNoPKZoneTime(UINT nDBID, UINT timestamp);
	void RequestLoadNoPKZoneTime(UINT nDBID);
	void RequestSaveOffline(UINT nDBID, UINT timeSec);

	void RequestLoadChampionshipTeams();
	void RequestLoadChampionshipMatches();
	void RequestSaveChampionshipTeam(UINT id, INT32 points, INT32 winCount, INT32 loseCount, INT32 drawCount, INT32 killCount, INT32 deathCount);
	void RequestSaveChampionshipMatch(UINT id, UINT state, UINT winnerId);
	void RequestRegisterChampionshipTeam(wstring wName, UINT charId1, UINT charId2, UINT charId3);

};

extern CDB g_DB;


typedef bool (*DBPacketCallback)(CDBSocket*, const unsigned char*, UINT);

class CDBPacket
{
public:
	static void Init();
	static void Bind(UINT id, DBPacketCallback func);
	static bool Handler(CDBSocket *pSocket, const unsigned char* packet);
	static bool DummyPacket(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyRestoreCH(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadSpiritCount(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadBuffList(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyCustomEnchantItem(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadAIO(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadNpcDeath(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadVipStatus(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadVIPAccounts(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadVotePoints(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadBannedAccounts(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadHwidLockData(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadAdditionalBox(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadUserFraction(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyItemDeliveryAsk(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadFractionData(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyCreateAuction(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadAuctionItem(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyAuctionPaymentAsk(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadPledgeSkills(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadPledgeRaidWinners(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadWeddingStatus(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyTestQuery(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadRaidBossStatus(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadBannedHardwareId(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadPKStatus(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadPvPStatus(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadDailyStatus(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);

	//Olympiad Start
	static bool ReplyLoadOly88(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOly89(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOly90(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOly91(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOly92(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOly93(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOly94(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOly95(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOly96(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOly97(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOly98(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOly99(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOly100(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOly101(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOly102(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOly103(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOly104(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOly105(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOly106(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOly107(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOly108(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOly109(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOly110(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOly111(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOly112(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOly113(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOly114(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOly115(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOly116(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOly117(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOly118(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	//Olympiad End
	static bool ReplyLoadCaptchaStatus(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadEpicItems(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadNameTitleColor(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadCharacterLock(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadDailyPvPEntry(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadDailyPvP(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadSubStack(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadInstanceTime(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadL2NetworkVote(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadVisualArmor(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadRebirth(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadDBNpcMaker(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadCharacterPIN(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadPledgeTotalPvP(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadPledgeTotalRaid(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadJailStatus(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadCaptchaReportStatus(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadCaptchaSiteStatus(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadEventStats(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadVoteReward(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadVoteRewardDone(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadItemDataEx(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadSkin(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadSex(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);

	static bool ReplyLoadCustomSubClass(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadNoPKZoneTime(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);

	static bool ReplyLoadHwids(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);

	static bool ReplyLoadChampionshipTeam(CDBSocket* pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadChampionshipMatch(CDBSocket* pSocket, const unsigned char* packet, UINT packetId);


	
};