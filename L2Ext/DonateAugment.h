#pragma once

struct CDonateItemAugment
{
	UINT catid;
	UINT augmentid;
	UINT priceid;
	UINT pricequanity;
};

struct CategoriesItemsAugment
{
	vector<CDonateItemAugment> m_Items;
};

struct CategoriesPagesAugment
{
	vector<wstring> m_Pages;
};

class CDonateSystemAugment
{
	BOOL m_Enabled;
	UINT m_categories;
	CSLock m_Lock;
	vector<CategoriesItemsAugment> m_CategoriesList;
	vector<CategoriesPagesAugment> m_CategoriesPages;
public:
	CDonateSystemAugment();
	~CDonateSystemAugment();
	void Init();
	void LoadData();
	void CreatePages();
	void RequestShowCategory(User *pUser, UINT category, UINT page);
	void RequestShowUserWeapons(User *pUser, UINT page);
	bool AugmentExistOnDonationList(User *pUser, UINT category, UINT augment);
	void RequestShowItems(User *pUser, UINT category, UINT augment);
	void RequestBuyAugment(User *pUser, UINT category, UINT itemid, UINT augment);
	inline bool Enabled() { return m_Enabled; };
};

extern CDonateSystemAugment g_DonateSystemAugment;