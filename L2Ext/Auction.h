#pragma once
#include "ItemDBEx.h"

struct AuctionItem
{
	UINT sellerDatabaseId;
	WCHAR sellerName[25];
	int itemClassId;
	int itemEnchant;
	UINT itemAugmentation;
	int itemAmount;
	int itemPrice;
	int itemPriceID;
	UINT auctionTimeoutTime;
	UINT auctionid;
	CItemInformation* pInfo;
};

struct AuctionItemList
{
	int itemDBId;
	int itemClassId;
	int itemEnchant;
	UINT itemAugmentation;
	int itemAmount;
	CItemInformation* pInfo;
};

struct SellCurrency
{
	wstring itemName;
	UINT itemId;
	wstring htmlstring;
};

class CAuction
{
	BOOL m_Enabled;
	CSLock m_Lock;
	//vector<int> m_ForbiddenItems;
	map<UINT, AuctionItem> m_Items;
	//map<UINT, wstring> m_Categories;
	//wstring m_CategoryList;
	INT32 m_AuctionTime;
	INT32 m_AuctionFeeID;
	INT32 m_AuctionFee;
	INT32 m_AuctionFeeDel;
	UINT m_AuctionLimit;
	INT32 m_PeaceMode;
	INT32 m_KarmaDisable;
	map<UINT, SellCurrency> m_SellCurrency;
	vector<wstring> m_Pages;
	//BOOL m_UpdatePageRequest;
	UINT m_ExpireTimestamp;
	INT32 m_CacheDelay;

	//UINT GetCategoryByName(wstring name);
	//void UpdatePages();
	//void UpdatePagesPlayer(User *pUser);
public:
	CAuction();
	void Init();
	void LoadINI();
	void TimerExpired();
	~CAuction();
	inline BOOL IsEnabled() { return m_Enabled; };
	void GetUserItemList(User *pUser);
	void CacheItemsMe(User *pUser, bool forceupdate = false);
	bool RequestShowAuctionMe(User *pUser, UINT page, UINT page2, UINT nItemDbID, bool forceupdate = false);
	void CacheItems(User *pUser, bool forceupdate = false);
	bool RequestShowAuction(User *pUser, UINT page = 0, bool forceupdate = false);
	bool RequestSetAuctionConfirm(User *pUser, UINT itemDbId, wstring pricename, int price, int amount);
	bool RequestSetAuction(User *pUser, UINT itemid, UINT priceId, int price, int amount);
	bool Create(UINT sellerId, const WCHAR* sellerName, UINT auctionId, INT32 itemId, INT32 amount, INT32 enchant, UINT augmentation, INT32 priceId, INT32 price, UINT expireTime, bool loadOnly = false);
	bool Delete(UINT auctionId);
	bool RequestCancelAuctionConfirm(User *pUser, UINT nAuctionId);
	bool RequestCancelAuction(User *pUser, UINT auctionId);

	bool RequestBuyAuctionPreview(User *pUser, UINT nAuctionId);
	bool RequestBuyAuctionConfirm(User *pUser, UINT nAuctionId, UINT nItemAmount);
	bool RequestBuy(User *pUser, UINT auctionId, INT32 amount);
	
	void HandlePaymentRequest(User *pUser, INT32 priceId, INT32 priceAmount, INT32 itemId, INT32 amount, const WCHAR* buyer);
	
	//help functions
	wstring GetGradeIcon(UINT gradeid);
	int CalcEnchDef(UINT BaseDef, UINT enchant);
	int CalcEnchPAtk(UINT BasePAtk, UINT enchant, WeaponType nWeaponType, SlotType nSlotType, UINT nGrade);
	int CalcEnchMAtk(UINT BaseMAtk, UINT enchant, WeaponType nWeaponType, SlotType nSlotType, UINT nGrade);
	wstring GetItemDesc(CItemInformation* pInfo, UINT nItemEnchant, UINT nAugmentation, UINT nExpireTime = 0);
	wstring GetCurrencyName(UINT m_CurrencyId);
	UINT GetCurrencyId(wstring m_CurrencyName, bool trim = false);
	wstring GetCurrencyHtml(UINT m_CurrencyId);
	bool SetSpecsGrade(User *pUser, wstring wGrade);
	bool SetSpecsCat(User *pUser, wstring wCategory);
	bool SetSpecsSubCat(User *pUser, wstring wSubCategory);
	bool SetSpecsItemName(User *pUser, wstring wItemName);
	bool SetSpecsClear(User *pUser);
	wstring ShowSearchPanel(User *pUser);
};

extern CAuction g_Auction;