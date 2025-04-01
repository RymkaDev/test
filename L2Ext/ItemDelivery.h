#pragma once

class CItemDelivery
{
	BOOL m_enabled;
	UINT m_checkInterval; //inverval in seconds

	void LoadINI();
public:
	CItemDelivery();
	~CItemDelivery();
	void Init();
	void OnTimerExpired(User *pUser);
	void HandleRequest(User *pUser, UINT jobId, INT32 itemId, INT32 amount, INT32 enchant, UINT augmentation, UINT auction, UINT sold_id, UINT sold_amount, WCHAR* wBuyer);
};

extern CItemDelivery g_ItemDelivery;