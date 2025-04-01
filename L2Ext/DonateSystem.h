#pragma once

struct CDonateItem
{
	UINT catid;
	UINT itemid;
	UINT itemquanity;
	UINT itemenchant;
	UINT itemaug;
	UINT priceid;
	UINT pricequanity;
};

struct CategoriesItems
{
	vector<CDonateItem> m_Items;
};

struct CategoriesPages
{
	vector<wstring> m_Pages;
};

class CDonateSystem
{
	BOOL m_Enabled;
	UINT m_categories;
	CSLock m_Lock;
	//vector<CDonateItem> m_DonationItemList;
	vector<CategoriesItems> m_CategoriesList;
	vector<CategoriesPages> m_CategoriesPages;
public:
	CDonateSystem();
	~CDonateSystem();
	void Init();
	void LoadData();
	void LoadDataAugment();
	void CreatePages();
	void RequestShowCategory(User *pUser, UINT category, UINT page);
	void RequestShowItem(User *pUser, UINT category, UINT item);
	inline bool Enabled() { return m_Enabled; };
};

extern CDonateSystem g_DonateSystem;