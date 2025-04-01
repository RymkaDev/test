#pragma once

struct EpicItems
{
	wstring name;
	INT32 item_id;
};

class CEpicItems
{
	BOOL m_Enabled;
	CSLock m_Lock;
	UINT m_RefreshTimeout;
	time_t m_RefreshTime;
	time_t m_FirstTimeEpicItemsLoad;
	vector<EpicItems> m_DBItems;
	vector<wstring> m_PagesItems;
	void LoadINI();
public:
	void Init();
	void TimerExpired();
	void OnDBLoadEpicItems(wstring name, INT32 item_id);
	void RequestEpicItems(User *pUser, UINT page = 0);
	void GeneratePagesEpicItems();

};

extern CEpicItems g_EpicItems;