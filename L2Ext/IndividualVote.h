#pragma once

class CDatabaseVotes
{
public:
	CIPAddress IPaddr;
	UINT l2topzone;
	UINT l2topzoneReward;
	UINT l2hopzone;
	UINT l2hopzoneReward;
	UINT l2network;
	UINT l2networkReward;
	UINT l2jbrasil;
	UINT l2jbrasilReward;
	UINT l2servers;
	UINT l2serversReward;
	UINT l2mmotop;
	UINT l2mmotopReward;
	UINT lastchecked;
	UINT lastcheckedreminder;
	HWID hwid;

	CDatabaseVotes() : l2topzone(0),l2topzoneReward(0), l2hopzone(0), l2hopzoneReward(0), l2network(0), l2networkReward(0), l2jbrasil(0), l2jbrasilReward(0), l2servers(0), l2serversReward(0), l2mmotop(0), l2mmotopReward(0), lastchecked(0), lastcheckedreminder(0)  {}
};

struct VoteJobTodo
{
	UINT Site; //0 = L2Topzone, 1 = L2Hopzone, 2 = L2Network, 3 = L2JBrazil, 4 = L2Servers
	UINT UserId;
	CIPAddress IPaddr;
	HWID hwid;
};

class CIndivVote
{
	vector<pair<CIPAddress,CDatabaseVotes*>> m_Database;
	vector<VoteJobTodo> m_PendingJobs;
	CSLock m_LockDB;
	CSLock m_Lock;
	BOOL m_Enabled;
	UINT m_CheckCycle;
	UINT m_CheckCycleReminder;

	BOOL m_Loaded;

	int m_PendingJobLimit;

	//L2Topzone
	UINT m_TopZoneEnable;
	UINT m_TopZoneCycle;
	string m_TopZoneAPI;
	wstring m_TopZoneVoteLink;
	UINT m_TopZoneRewardId;
	UINT m_TopZoneRewardQuanity;
	//L2Hopzone
	UINT m_HopZoneEnable;
	UINT m_HopZoneCycle;
	string m_HopZoneAPI;
	wstring m_HopZoneVoteLink;
	UINT m_HopZoneRewardId;
	UINT m_HopZoneRewardQuanity;
	//L2Network
	UINT m_L2NetworkEnable;
	UINT m_L2NetworkCycle;
	string m_L2NetworkAPI;
	wstring m_L2NetworkVoteLink;
	UINT m_L2NetworkRewardId;
	UINT m_L2NetworkRewardQuanity;
	//L2JBrazil
	UINT m_L2jBrazilEnable;
	UINT m_L2jBrazilCycle;
	string m_L2jBrazilAPI;
	wstring m_L2jBrazilVoteLink;
	UINT m_L2jBrazilRewardId;
	UINT m_L2jBrazilRewardQuanity;
	//L2Servers
	UINT m_L2ServersEnable;
	UINT m_L2ServersCycle;
	string m_L2ServersAPI;
	UINT m_L2ServersServerId;
	wstring m_L2ServersVoteLink;
	UINT m_L2ServersRewardId;
	UINT m_L2ServersRewardQuanity;

	//vector<VoteJob> m_PendingJobs;

	HANDLE m_ThreadHandle;
	bool m_TerminateThread;
public:
	CIndivVote();
	~CIndivVote();
	inline BOOL IsEnabled() { return m_Enabled; };
	void Init();
	void LoadData();
	
	void LoadFromDBFinished();

	void AddDatabase(CIPAddress IPaddr, UINT l2topzone, UINT l2topzoneReward, UINT l2hopzone, UINT l2hopzoneReward, UINT l2network, UINT l2networkReward, UINT l2jbrasil, UINT l2jbrasilReward, UINT l2servers, UINT l2serversReward, UINT l2mmotop, UINT l2mmotopReward, UINT lastchecked, UINT lastcheckedreminder, HWID hwid);
	void DeleteFromDatabase(CIPAddress IPaddr);
	void UpdateDatabaseRecord(CIPAddress IPaddr, UINT UpdateCategory, UINT value, UINT value2 = 0, BOOL updatelastchecked = true);
	void UpdateDatabaseRecord(HWID hwid, UINT UpdateCategory, UINT value, UINT value2 = 0, BOOL updatelastchecked = true);
	CDatabaseVotes* GetFromDatabase(CIPAddress IPaddr);
	CDatabaseVotes* GetFromDatabase(HWID hwid);
	bool ExistInDB(CIPAddress IPaddr);
	bool ExistInDB(HWID hwid);

	void OnServerShutdown();
	void CheckVoteUser(User *pUser, BOOL enterworld = false);
	void OnShowVotePage(User *pUser);
	void OnCheckUser(User *pUser);
	void AddJobCheck(User *pUser, UINT nSiteID);
	void ClientAnswer(User *pUser, UINT nSiteID, UINT voteTime);

	//static void JobThread(LPVOID params);
	string ClearAnswer(string answer, UINT type = 0);
	
	void Test();
	

	/*inline string GetSecretKey() { return m_SecretKey; };
	inline int GetServerId() { return m_ServerId; };
	void Init();
	void LoadData();
	void OnLoad(User *pUser);
	void HandleCommand(User *pUser, wstring wParams);
	void Exchange(User *pUser);
	
	*/
};

extern CIndivVote g_IndivVote;
