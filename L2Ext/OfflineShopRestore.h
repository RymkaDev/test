#pragma once
#include "DBSocket.h"
#include "winsock.h"

struct OfflineShopItem
{
	int item_type_id;
	__int64 item_count;
	__int64 item_price;
	int enchant;
	int item_class_id;
	OfflineShopItem(int type_id, __int64 count, __int64 price, int enc, int classid) : item_type_id(type_id), item_count(count), item_price(price), enchant(enc), item_class_id(classid)  {}
};

struct OfflineShopRecord
{
	int char_db_id;
	wchar_t w_account_name[30];
	char a_account_name[30];
	int account_id;

	int current_stage;
	int nPackageSell;

	wchar_t shop_text[255];
	StoreType shop_type;
	std::vector<OfflineShopItem> shop_items;
	int price;
	bool is_buff;
	int char_locX;
	int char_locY;
	int char_locZ;
	int char_Heading;
};

/*struct OfflineShopBuffRecord
{
	int char_db_id;
	wchar_t w_account_name[30];
	char a_account_name[30];
	int account_id;

	int current_stage;

	wchar_t shop_text[255];
	int price;
};*/

class OfflineShopRestore
{
public:
	OfflineShopRestore();
	~OfflineShopRestore();
	void Initialize();
	static void OnServerLoaded();
	//static CDBSocket *OnAuthConstruct(CDBSocket *pSocket, SOCKET s, void *packettable);
	static void OnSendShortcutInfo(User *pUser);
	static bool OnLoadCharacterPacket(CDBSocket *pSocket, unsigned char *packet);
	static bool OnLoadCharacterPacket2(CUserSocket *pSocket);
	static bool OnLoadSelectedCharacterPacket2(CUserSocket *pSocket);
	static bool OnLoadSelectedCharacterPacket(CDBSocket *pSocket, unsigned char *packet);
	bool OnProtocolVersion(CUserSocket *pSocket, unsigned char *packet);
	static bool ReplyLoadOfflineShopIds(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOfflineBuffShopIds(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOfflineShop(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	static bool ReplyLoadOfflineBuffShop(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
	void AddShopRecord(OfflineShopRecord * record);
	void AddShopRecordBuff(OfflineShopBuffRecord *record);
	OfflineShopRecord *GetShopRecord();
	//OfflineShopBuffRecord *GetShopRecordBuff();
	void OnBeginOfflineShop(CUserSocket *pSocket);
	void OnEndOfflineShop(CUserSocket *pSocket);
	static void SendPrivateStoreCommitSell(CDB *pDB, User* pUser1, User* pUser2, int nPriceSum, int nItemCount, int nBufLen, char* pBuf);
	static void SendPrivateStoreCommitBuy(CDB *pDB, User* pUser1, User* pUser2, int nPriceSum, int nItemCount, int nBufLen, char* pBuf);
	void AddSocket(SOCKET s, bool isbuff);
	bool ShopRecordPending();
	//bool ShopRecordPendingBuff();
	void TimerExpired(User * pUser);

	bool processing_shops;
	//bool processing_shops_buff;

private:
	CRITICAL_SECTION records_lock;
	HANDLE socket_thread;
	std::vector<OfflineShopRecord*> record_list;
	//std::vector<OfflineShopBuffRecord*> record_list_buff;
	int last_record_update;
	//int last_record_update_buff;
	std::vector<SOCKET> socket_list;
	//std::vector<SOCKET> socket_list_buff;
	int magic_int;

};
extern OfflineShopRestore g_OfflineShopRestore;

DWORD WINAPI SocketThread(LPVOID lpParam);