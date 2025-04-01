#include "StdAfx.h"
#include "LoginDb.h"
#include "PacketHandler.h"
#include "OfflineShopRestore.h"
#include "DB.h"
#include "OfflineShop.h"
#include "OfflineBuffer.h"

#define SHOP_THREAD_MAX 1

unsigned char protocol_version_packet[] = {0x0B, 0x01, 0x00, 0xEA, 0x02, 0x00, 0x00, 0x09, 0x07, 0x54, 0x56, 0x03, 0x09, 0x0B, 0x01, 0x07, 0x02, 0x54, 0x54, 0x56, 0x07, 0x00, 0x02, 0x55, 0x56, 0x00, 0x51, 0x00, 0x53, 0x57, 0x04, 0x07, 0x55, 0x08, 0x54, 0x01, 0x07, 0x01, 0x53, 0x00, 0x56, 0x55, 0x56, 0x01, 0x06, 0x05, 0x04, 0x51, 0x03, 0x08, 0x51, 0x08, 0x51, 0x56, 0x04, 0x54, 0x06, 0x55, 0x08, 0x02, 0x09, 0x51, 0x56, 0x01, 0x53, 0x06, 0x55, 0x04, 0x53, 0x00, 0x56, 0x56, 0x53, 0x01, 0x09, 0x02, 0x09, 0x01, 0x51, 0x54, 0x51, 0x09, 0x55, 0x56, 0x09, 0x03, 0x04, 0x07, 0x05, 0x55, 0x04, 0x06, 0x55, 0x04, 0x06, 0x09, 0x04, 0x51, 0x01, 0x08, 0x08, 0x06, 0x05, 0x52, 0x06, 0x04, 0x01, 0x07, 0x54, 0x03, 0x06, 0x52, 0x55, 0x06, 0x55, 0x55, 0x51, 0x01, 0x02, 0x04, 0x54, 0x03, 0x55, 0x54, 0x01, 0x57, 0x51, 0x55, 0x05, 0x52, 0x05, 0x54, 0x07, 0x51, 0x51, 0x55, 0x07, 0x02, 0x53, 0x53, 0x00, 0x52, 0x05, 0x52, 0x07, 0x01, 0x54, 0x00, 0x03, 0x05, 0x05, 0x08, 0x06, 0x05, 0x05, 0x06, 0x03, 0x00, 0x0D, 0x08, 0x01, 0x07, 0x09, 0x03, 0x51, 0x03, 0x07, 0x53, 0x09, 0x51, 0x06, 0x07, 0x54, 0x0A, 0x50, 0x56, 0x02, 0x52, 0x04, 0x05, 0x55, 0x51, 0x02, 0x53, 0x00, 0x08, 0x54, 0x04, 0x52, 0x56, 0x06, 0x02, 0x09, 0x00, 0x08, 0x03, 0x53, 0x56, 0x01, 0x05, 0x00, 0x55, 0x06, 0x08, 0x56, 0x04, 0x0D, 0x06, 0x07, 0x52, 0x06, 0x07, 0x04, 0x0A, 0x06, 0x01, 0x04, 0x54, 0x04, 0x00, 0x05, 0x02, 0x04, 0x54, 0x00, 0x09, 0x52, 0x53, 0x05, 0x04, 0x01, 0x04, 0x05, 0x05, 0x01, 0x52, 0x51, 0x52, 0x0D, 0x06, 0x51, 0x08, 0x09, 0x54, 0x53, 0x00, 0x0D, 0x01, 0x02, 0x03, 0x54, 0x53, 0x01, 0x05, 0x03, 0x08, 0x56, 0x54, 0x07, 0x02, 0x54, 0x0B, 0x06, 0xDC, 0x4F, 0x61, 0x4F};
unsigned char enterworld_packet[] = { 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC9, 0xBC, 0xF2, 0xA7, 0x66, 0x5A, 0x0B, 0x98, 0x36, 0xA5, 0xBD, 0x89, 0xED, 0x7F, 0xE4, 0xD7, 0x6B, 0x49, 0xE2, 0x9F, 0xEF, 0x76, 0xEB, 0xCE, 0xA3, 0xFA, 0xF4, 0xBF, 0x0C, 0x64, 0xA3, 0xB4, 0xA4, 0xCE, 0xDC, 0xC6, 0x08, 0x3E, 0x6E, 0xEA, 0x45, 0xCA, 0xD3, 0xFE, 0x88, 0x13, 0x87, 0xB8, 0x06, 0x2C, 0x96, 0xF0, 0x9B, 0x1E, 0x8E, 0xBC, 0xC6, 0x9B, 0x98, 0xC8, 0x63, 0x16, 0xCF, 0xD0, 0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

extern CDBSocket *g_AuthSocket;

std::map<int,int> *onetimekey_map = (std::map<int,int>*)0x10488C8;

vector<INT32> m_Cuentas;

OfflineShopRestore g_OfflineShopRestore;

OfflineShopRestore::OfflineShopRestore()
{
	this->magic_int = rand();
	*(int *)(&protocol_version_packet[3]) = magic_int;

	last_record_update = -1;
	//last_record_update_buff = -1;
	processing_shops = false;
}

OfflineShopRestore::~OfflineShopRestore()
{
}

void OfflineShopRestore::Initialize()
{
	g_HookManager.WriteCall(0x792202, OfflineShopRestore::OnSendShortcutInfo);

	g_HookManager.WriteCall(0x84858B, OfflineShopRestore::SendPrivateStoreCommitSell);
	g_HookManager.WriteCall(0x83F7DF, OfflineShopRestore::SendPrivateStoreCommitBuy);

	InitializeCriticalSection(&records_lock);
}

void OfflineShopRestore::OnServerLoaded()
{
	guard;
	if(g_OfflineShop.SaveOnDbStores())
	{
		g_OfflineShopRestore.processing_shops = true;
		g_OfflineShopRestore.last_record_update = GetTickCount();
		g_DB.Send("ch", 0xF9, CI_REQUEST_LOAD_OFFLINESHOPIDS);
	}

	if(g_OfflineShop.SaveOnDbBuffers())
	{
		g_OfflineShopRestore.processing_shops = true;
		g_OfflineShopRestore.last_record_update = GetTickCount();
		g_DB.Send("ch", 0xF9, CI_REQUEST_LOAD_OFFLINEBUFFSHOPIDS);
	}

	//g_Log.Add(CLog::Blue,"[%s] ssssss[%x][%x][%x][%x][%x][%x]", __FUNCTION__, protocol_version_packet[0], protocol_version_packet[1], protocol_version_packet[2], protocol_version_packet[3], protocol_version_packet[4], protocol_version_packet[5]);


	if(g_OfflineShop.SaveOnDbUsers())
	{
		//TODO USUAL PLAYERS
	}

	unguard;
}

void OfflineShopRestore::OnSendShortcutInfo(User *pUser)
{
	guard;
	pUser->SendItemList(false);

	if (pUser->GetSocket() != NULL && pUser->GetSocket()->pED->is_osr) {
		pUser->GetSocket()->pED->osr->current_stage = 0;
	}

	if (pUser->GetSocket() != NULL && pUser->GetSocket()->pED->is_osr_buff) {
		pUser->GetSocket()->pED->osr->current_stage = 0;
	}

	unguard;
}

bool OfflineShopRestore::OnLoadCharacterPacket(CDBSocket *pSocket, unsigned char *packet)
{
	guard;
	typedef bool (*_lcp)(CDBSocket*,unsigned char *);
	_lcp(0x573EF0)(pSocket,packet);

	int socket_id = *(int *)packet;
	CUserSocketSP socketSP;
	typedef CUserSocket *(*f)(INT64, CUserSocketSP*, int);
	f(0x479090)(0xE6C8580, &socketSP, socket_id);

	if (socketSP.get() != NULL) {
		if (socketSP->pED->is_osr) {
			bool found = false;
			for (int i=0; i<7; i++) {
				if (socketSP->characterDBID[i] == socketSP->pED->osr->char_db_id) {
					found = true;
					
					char char_select_packet[18];
					Assemble(char_select_packet, 18, "dhddd", i, 0, 0, 0, 0);

					// fake a char select packet
					typedef bool (*_csp)(CUserSocket*,char *);
					if (_csp(0x85E9B0)(socketSP.get(), char_select_packet) == true) {
						g_Log.Add(CLog::Error, "[OfflineShopRestore] Error selecting character !!");
					}

					break;
				}
			}
			if (!found) {
				// unlikely
				g_Log.Add(CLog::Error, "[OfflineShopRestore] character db id not found in account !!");
			}
		}
	}

	unguard;
	return false;
}

bool OfflineShopRestore::OnLoadCharacterPacket2(CUserSocket *pSocket)
{
	guard;
	if (pSocket->pED->is_osr || pSocket->pED->is_osr_buff)
	{
		bool found = false;
		for (int i=0; i<7; i++) 
		{
			if(pSocket->pED->is_osr)
				if(pSocket->characterDBID[i] == pSocket->pED->osr->char_db_id)
					found = true;

			if(pSocket->pED->is_osr_buff)
				if(pSocket->characterDBID[i] == pSocket->pED->osr->char_db_id)
					found = true;

			if(found)
			{
				char char_select_packet[18];
				Assemble(char_select_packet, 18, "dhddd", i, 0, 0, 0, 0);

				pSocket->lastUsedPacketID = 0x08;

				// fake a char select packet
				typedef bool (*_csp)(CUserSocket*,char *);
				if (_csp(0x85E9B0)(pSocket, char_select_packet) == true) 
				{
					g_Log.Add(CLog::Error, "[OfflineShopRestore] Error selecting character !!");
				}
				
				break;
			}
		}
	}

	unguard;
	return false;
}

bool OfflineShopRestore::OnLoadSelectedCharacterPacket(CDBSocket *pSocket, unsigned char *packet)
{
	guard;
//	typedef bool (*_lscp)(CDBSocket*,unsigned char *);
//	_lscp(0x589C10)(pSocket,packet);

	int socket_id = *(int *)packet;
	CUserSocketSP socketSP;
	typedef CUserSocket *(*f)(INT64, CUserSocketSP*, int);
	f(0x479090)(0xE6C8580, &socketSP, socket_id);

	if (socketSP.get() != NULL) {
		if (socketSP->pED->is_osr || socketSP->pED->is_osr_buff) {
			// fake enter-world
			*(int *)&socketSP->_unkn140 = GetTickCount() - 2000; // skip bot check
			typedef bool (*_ewp)(CUserSocket*,unsigned char *);
			_ewp(0x888510)(socketSP.get(), enterworld_packet);
		}
	}

	unguard;
	return false;
}

bool OfflineShopRestore::OnLoadSelectedCharacterPacket2(CUserSocket *pSocket)
{
	guard;
	if (pSocket != NULL) 
	{
		if (pSocket->pED->is_osr || pSocket->pED->is_osr_buff) 
		{
			// fake enter-world
			*(int *)&pSocket->_unkn140 = GetTickCount() - 2000; // skip bot check
			typedef bool (*_ewp)(CUserSocket*,unsigned char *);
			_ewp(0x888510)(pSocket, enterworld_packet);
		}
	}

	unguard;
	return false;
}

bool OfflineShopRestore::OnProtocolVersion(CUserSocket *pSocket, unsigned char *packet)
{
	guard;

		//g_Log.Add(CLog::Error, "[OfflineShopRestore] this->magic_int [%d]",this->magic_int);
	if (*(int *)packet == this->magic_int) 
	{
		*(int *)packet = 746;	// correct protocol

		OfflineShopRecord *record = g_OfflineShopRestore.GetShopRecord();
		if (record != NULL) 
		{
			pSocket->pED->osr = record;
		
			if(record->is_buff)
				pSocket->pED->is_osr_buff = true;
			else
				pSocket->pED->is_osr = true;

			// process protocol
			typedef bool (*f)(CUserSocket*,unsigned char *);
			bool ret = f(0x8782D0)(pSocket,packet);

			pSocket->pED->IsLoadOfflineShop = 1;
			pSocket->pED->FileCorruptCounter = 99;

			if (ret == true) 
			{
				// something happened
				g_Log.Add(CLog::Error, "[OfflineShopRestore] Error during protocol version for osr socket!!");

				unguard;
				return false;
			}
			
			int accountId = record->account_id;
			wchar_t *u_accountName = record->w_account_name;
			char *a_accountName = record->a_account_name;

			// large enough for both uses
			char login_packet[80];
			Assemble(login_packet, 80, "dsddddcddd", accountId, a_accountName, 0, 0, 0, 1, 0, 0, 0, 0);

			// fake auth play reqest
			CLoginDb::OnAuthRequestAboutToPlay((PVOID)g_AuthSocket, (const unsigned char *)login_packet);

			int onetimekey = (*onetimekey_map)[accountId];

			Assemble(login_packet, 80, "Sddddd", u_accountName, accountId, onetimekey, accountId, rand(), 1);
			
			// fake login
			if (f(0x885F20)(pSocket, (unsigned char *)login_packet) == true) 
			{
				g_Log.Add(CLog::Error, "[OfflineShopRestore] Error during LoginPacket for osr socket!!");
			}


			unguard;
			return false;
		}		
		else
		{
			unguard;
			return true; // kill socket
		}
	} 
	else 
	{
		pSocket->pED->is_osr = false; // just to be sure
		pSocket->pED->is_osr_buff = false; // just to be sure
	}

	unguard;
	return true;
}

bool OfflineShopRestore::ReplyLoadOfflineShopIds(CDBSocket *pSocket, const unsigned char* packet, UINT packetId)
{
	guard;
	int shop_count;
	packet = Disassemble(packet, "d", &shop_count);

	int shop_id;
	for (int i=0; i<shop_count; i++) 
	{
		packet = Disassemble(packet, "d", &shop_id);
		Sleep(50);
		g_DB.Send("chd", 0xF9, CI_REQUEST_LOAD_OFFLINESHOP, shop_id);
	}

	unguard;
	return false;
}

bool OfflineShopRestore::ReplyLoadOfflineBuffShopIds(CDBSocket *pSocket, const unsigned char* packet, UINT packetId)
{
	guard;
	int shop_count;
	packet = Disassemble(packet, "d", &shop_count);

	int shop_id;
	for (int i=0; i<shop_count; i++) {
		packet = Disassemble(packet, "d", &shop_id);
		Sleep(50);
		g_DB.Send("chd", 0xF9, CI_REQUEST_LOAD_OFFLINEBUFFSHOP, shop_id);
		//g_Log.Add(CLog::Error, "[OfflineShopRestore] Buff[%d]", shop_id);
	}

	unguard;
	return false;
}

bool OfflineShopRestore::ReplyLoadOfflineShop(CDBSocket *pSocket, const unsigned char* packet, UINT packetId)
{
	guard;
	OfflineShopRecord *record = new OfflineShopRecord();
	memset(record,0,sizeof(OfflineShopRecord));

	record->current_stage = -1;
	record->nPackageSell = 0;
	record->price = 0;
	record->is_buff = false;

	record->char_locX = 0;
	record->char_locY = 0;
	record->char_locZ = 0;
	record->char_Heading = 0;

	int shop_item_count = 0;

	packet = Disassemble(packet, "dSdddddSdd", &record->shop_type, sizeof(record->shop_text), &record->shop_text, &record->char_db_id, &record->char_locX, &record->char_locY, &record->char_locZ, &record->char_Heading, sizeof(record->w_account_name), &record->w_account_name, &record->account_id, &shop_item_count);
	sprintf_s(record->a_account_name, sizeof(record->a_account_name), "%S", record->w_account_name);

	if(record->shop_type == StoreSellPackage)
	{
		record->shop_type = StoreSell;
		record->nPackageSell = 1;
	}
	
	for(UINT n=0;n<m_Cuentas.size();n++)
	{
		if (m_Cuentas[n] == record->account_id || record->account_id < 0)
		{
			shop_item_count = -1000;
		}
	}

	//g_Log.Add(CLog::Error, "[OfflineShopRestorer] StoreSell [%S]", pUser->pSD->wszName);

	if (shop_item_count > 0) 
	{
		m_Cuentas.push_back(record->account_id);
		int item_type_id,item_count,item_price, enchant, item_class_id;
		for (int i=0; i<shop_item_count; i++) 
		{
			packet = Disassemble(packet, "ddddd", &item_type_id, &item_count, &item_price, &enchant, &item_class_id);
			record->shop_items.push_back(OfflineShopItem(item_type_id, item_count, item_price, enchant, item_class_id));
		}
		//g_Log.Add(CLog::Error, "[OfflineShopRestore] Shop[%d]", record->char_db_id);
		g_OfflineShopRestore.AddShopRecord(record);
	} 
	else 
		delete record;

	unguard;
	return false;
}


bool OfflineShopRestore::ReplyLoadOfflineBuffShop(CDBSocket *pSocket, const unsigned char* packet, UINT packetId)
{
	guard;
	OfflineShopRecord *record = new OfflineShopRecord();
	memset(record,0,sizeof(OfflineShopRecord));

	record->current_stage = -1;
	record->nPackageSell = 0;
	record->price = 0;
	record->is_buff = true;


	record->char_locX = 0;
	record->char_locY = 0;
	record->char_locZ = 0;
	record->char_Heading = 0;


	packet = Disassemble(packet, "dSdddddSd", &record->price, sizeof(record->shop_text), &record->shop_text, &record->char_db_id, &record->char_locX, &record->char_locY, &record->char_locZ, sizeof(record->w_account_name), &record->w_account_name, &record->account_id);
	sprintf_s(record->a_account_name, sizeof(record->a_account_name), "%S", record->w_account_name);


	bool pasar = true;
	for(UINT n=0;n<m_Cuentas.size();n++)
	{
		if (m_Cuentas[n] == record->account_id || record->account_id < 0)
		{
			pasar = false;
		}
	}

	if (pasar)
	{
		m_Cuentas.push_back(record->account_id);

		g_OfflineShopRestore.AddShopRecord(record);
	} 
	else 
		delete record;


	unguard;
	return false;
}

void OfflineShopRestore::AddShopRecord(OfflineShopRecord *record)
{
	guard;

	EnterCriticalSection(&records_lock);
	record_list.push_back(record);
	last_record_update = GetTickCount();
	if (socket_thread == NULL)
		socket_thread = CreateThread(NULL,0,SocketThread,NULL,0,NULL);
	LeaveCriticalSection(&records_lock);

	unguard;
}

OfflineShopRecord *OfflineShopRestore::GetShopRecord()
{
	guard;

	OfflineShopRecord *record = NULL;
	EnterCriticalSection(&records_lock);
	if (record_list.size() > 0) 
	{
		record = record_list[0];
		record_list.erase(record_list.begin());
		last_record_update = GetTickCount();
	}
	LeaveCriticalSection(&records_lock);

	unguard;
	return record;
}

void OfflineShopRestore::OnBeginOfflineShop(CUserSocket *pSocket)
{
	guard;

	if (pSocket->GetUser()) 
	{
		User *pUser = pSocket->GetUser();

		if (pUser->pSD->nStoreMode == 3 || pUser->pSD->nStoreMode == 5 || pUser->pSD->nStoreMode == 1) 
		{
			char buf[8192];
			int buf_len = 0;
			int item_count = 0;

			int nStoreMode = pUser->pSD->nStoreMode;
			if (pUser->pSD->nStoreMode == 1) 
			{
				if( pUser->nPackageSell)
					nStoreMode = 8;

				PrivateStoreItemMap *pItemMap = pUser->GetPrivateStoreSell();
				for (PrivateStoreItemMap::const_iterator iter = pItemMap->begin(); iter != pItemMap->end(); iter++) 
				{
					CItem *pItem = pUser->inventory.GetItemBySID(iter->second->ObjectID);
					if (pItem) 
					{
						buf_len += Assemble(&buf[buf_len], 8192-buf_len, "ddddd", pItem->nDBID, iter->second->Count, iter->second->Price, iter->second->Enchant, iter->second->ClassID );
						item_count++;
					}
				}
			} 
			else if (pUser->pSD->nStoreMode == 3) 
			{
				PrivateStoreItemMap *pItemMap = pUser->GetPrivateStoreBuy();
				for (PrivateStoreItemMap::const_iterator iter = pItemMap->begin(); iter != pItemMap->end(); iter++) 
				{
					CSharedItemData* lpSharedItemDataArray = (*(CSharedItemData**)0x0E412138);
					INT32 itemCount = 0;
					CItem *pItem;
					CItem *pItem2;

					pUser->inventory.ReadLock(__FILEW__, __LINE__);
					INT32 index = pUser->inventory.GetFirstItemIndex();
					try
					{
						while(index > -1 && index < 900000 && itemCount < 200)
						{
							CSharedItemData *lpSID = &lpSharedItemDataArray[index];
							if(lpSID)
							{
								if(pItem = pUser->inventory.GetItemByIndex(index))
								{
									if(pItem->IsValidItem())
									{
										if( (pItem->pSID->nItemID == iter->second->ClassID) && (pItem->pSID->nEnchantLevel == iter->second->Enchant)  )
										{
											pItem2 = pItem;
										}
									}
								}
							}
							index = lpSID->nNextIndex;
							itemCount++;
						}
										
					}catch(...)
					{
						EXCEPTION_LOG;
					}
					pUser->inventory.ReadUnlock();


					buf_len += Assemble(&buf[buf_len], 8192-buf_len, "ddddd", pItem2->nDBID, iter->second->Count, iter->second->Price, iter->second->Enchant, iter->second->ClassID );
						item_count++;
				}
			} 
			else 
			{
				PrivateStoreRecipeMap *pRecipeMap = pUser->GetPrivateStoreRecipe();
				for (PrivateStoreRecipeMap::const_iterator iter = pRecipeMap->begin(); iter != pRecipeMap->end(); iter++) 
				{
					buf_len += Assemble(&buf[buf_len], 8192-buf_len, "ddddd", iter->second->pInfo->RecipeID, -1, iter->second->Price, 0, 0);
					item_count++;
				}
			}

			const WCHAR * wShopTitle = pUser->pED->wShopTitle2.c_str();
			g_DB.Send("chdddddSddb", 0xF9, CI_REQUEST_SAVE_OFFLINESHOP, pUser->pSD->nDBID, (int)pUser->pSD->Pos.x, (int)pUser->pSD->Pos.y, (int)pUser->pSD->Pos.z, pUser->pSD->sHeading, wShopTitle, nStoreMode, item_count, buf_len, buf);
			
		}
		else if(g_OfflineBuffer.IsOfflineBuffer(pUser))
		{
			const WCHAR * wShopTitle = pUser->pED->offlineselltitle.c_str();
			g_DB.Send("chdddddSd", 0xF9, CI_REQUEST_SAVE_OFFLINEBUFFSHOP, pUser->pSD->nDBID, (int)pUser->pSD->Pos.x, (int)pUser->pSD->Pos.y, (int)pUser->pSD->Pos.z, pUser->pSD->sHeading, wShopTitle, pUser->pED->nofflinesellbuffprice);
		}
		else
		{
			//For Normal Char Save on DB
		}
	}

	unguard;
}

void OfflineShopRestore::OnEndOfflineShop(CUserSocket *pSocket)
{
	guard;

	if(User *pUser = pSocket->pUser->SafeCastUser())
	{
		if(g_OfflineBuffer.IsOfflineBuffer(pUser))
			g_DB.Send("chdddddSd", 0xF9, CI_REQUEST_SAVE_OFFLINEBUFFSHOP, pUser->pSD->nDBID, 0, 0, 0, 0, L"", 0);
		else if( (pUser->pSD->nStoreMode == 1) || ( pUser->pSD->nStoreMode == 3) || ( pUser->pSD->nStoreMode == 5) )  
			g_DB.Send("chdddddSdd", 0xF9, CI_REQUEST_SAVE_OFFLINESHOP, pUser->pSD->nDBID, 0, 0, 0, 0, L"", 0, 0);
		//else //TODO NORMAL CHARS
		//	g_DB.Send("chdSdd", 0xF9, CI_REQUEST_SAVE_OFFLINESHOP, pUser->pSD->nDBID, L"", 0, 0);
	}

	unguard;
}

void OfflineShopRestore::SendPrivateStoreCommitSell(CDB *pDB, User* pUser1, User* pUser2, int nPriceSum, int nItemCount, int nBufLen, char* pBuf)
{
	guard;

	if (g_OfflineShop.IsOfflineShop(pUser1->GetSocket())) 
	{
		char *p = pBuf;
		for (int i=0; i<nItemCount; i++) 
		{
			int d1,d2,d3,d4,d5,d6,d7,d8;
			p = (char*)Disassemble((const unsigned char *)p,"dddddddd", &d1, &d2, &d3, &d4, &d5, &d6, &d7, &d8);
			g_DB.Send("chdddd", 0xF9, CI_REQUEST_UPDATE_OFFLINESHOP_ITEM, 0, pUser1->pSD->nDBID, d2, d7);
		}
	}
	typedef void (*f)(CDB*,User*,User*,int,int,int,char*);
	f(0x527D20)(pDB,pUser1,pUser2,nPriceSum,nItemCount,nBufLen,pBuf);

	unguard;
}

void OfflineShopRestore::SendPrivateStoreCommitBuy(CDB *pDB, User* pUser1, User* pUser2, int nPriceSum, int nItemCount, int nBufLen, char* pBuf)
{
	guard;

	if (g_OfflineShop.IsOfflineShop(pUser2->GetSocket())) 
	{
		char *p = pBuf;
		for (int i=0; i<nItemCount; i++) 
		{
			int d1,d2,d3,d4,d5,d6,d7,d8;
			p = (char*)Disassemble((const unsigned char *)p,"dddddddd", &d1, &d2, &d3, &d4, &d5, &d6, &d7, &d8);
			CItem *pItem = pUser1->inventory.GetItemBySID(d3);
			if (pItem) 
			{
				g_DB.Send("chdddd", 0xF9, CI_REQUEST_UPDATE_OFFLINESHOP_ITEM, 1, pUser2->pSD->nDBID, pItem->pSID->nItemID, d7);
			}
		}
	}
	typedef void (*f)(CDB*,User*,User*,int,int,int,char*);
	f(0x527D20)(pDB,pUser1,pUser2,nPriceSum,nItemCount,nBufLen,pBuf);

	unguard;
}

void OfflineShopRestore::AddSocket(SOCKET s, bool isbuff)
{
	guard;

	socket_list.push_back(s);

	unguard;
}

bool OfflineShopRestore::ShopRecordPending()
{
	guard;
	bool ret = false;
	EnterCriticalSection(&records_lock);
	if (record_list.size() > 0) {
		ret = true;
	} else {
		if (last_record_update != -1 && (GetTickCount()-last_record_update) >= 15000) {
			processing_shops = false;
			g_Log.Add(CLog::Blue, L"[OfflineShopRestore] Offline Shops have been loaded!");
			for (int i=0; i<socket_list.size(); i++) {
				SOCKET s = socket_list[i];
				closesocket(s);
			}
			socket_list.clear();
		}
	}
	LeaveCriticalSection(&records_lock);
	unguard;
	return ret;
}

void OfflineShopRestore::TimerExpired(User * pUser)
{
	guard;

	if (pUser->GetSocket() != NULL && pUser->GetSocket()->pED->is_osr) 
	{
		CUserSocket *pSocket = pUser->GetSocket();

		char buffer[8192];
		int buffer_len = 0;
		int item_count = 0;

		int nPackageSell = 0;
		if(pSocket->pED->osr->shop_type == StoreSellPackage)
		{
			pSocket->pED->osr->shop_type = StoreSell;
			nPackageSell = 1;
		}



		if (pSocket->pED->osr->shop_type == StoreSell) 
		{
			if (pSocket->pED->osr->current_stage == 0) 
			{
				// private store manage
				typedef bool (*_psm)(CUserSocket*,unsigned char *);
				_psm(0x8707E0)(pSocket, NULL);
				pSocket->pED->osr->current_stage++;
//g_Log.Add(CLog::Error, "[OfflineShopRestorer] here add record name [%s]", wstring(pSocket->pED->osr->shop_text).c_str());
			} 
			else if (pSocket->pED->osr->current_stage == 1) 
			{
				if(pSocket->pED->osr->char_locX >0)
				{
					pUser->pSD->Pos.x = pSocket->pED->osr->char_locX;
					pUser->pSD->Pos.y = pSocket->pED->osr->char_locY;
					pUser->pSD->Pos.z = pSocket->pED->osr->char_locZ;
					pUser->pSD->sHeading = (WORD)pSocket->pED->osr->char_Heading;
				}

				pUser->SetPrivateStoreMsg((unsigned char *)pSocket->pED->osr->shop_text); //mby we loose special chars here?
				pUser->pED->wShopTitle2 = wstring(pSocket->pED->osr->shop_text);
				pSocket->pED->osr->current_stage++;
			}
			else if (pSocket->pED->osr->current_stage == 2) 
			{
				// build private store sell list
				buffer_len = Assemble(buffer, 8192, "dd", pSocket->pED->osr->nPackageSell, 0); // put a placeholder for item count

				for (int i=0; i<pSocket->pED->osr->shop_items.size(); i++) 
				{
					OfflineShopItem *shop_item = &pSocket->pED->osr->shop_items[i];
					CItem *pItem = pUser->inventory.GetItemByDBID(shop_item->item_type_id);
					if (pItem == NULL) 
					{
						g_Log.Add(CLog::Error, "[OfflineShopRestore] Unable to locate item in player inventory! (Sell) [%d]", shop_item->item_type_id);
						//g_DB.Send("chdddd", 0xF9, CI_REQUEST_UPDATE_OFFLINESHOP_ITEM, 1, pUser->pSD->nDBID, shop_item->item_class_id, UINT_MAX);
					} 
					else 
					{
						buffer_len += Assemble(&buffer[buffer_len], 8192-buffer_len, "ddd", pItem->nObjectID, (int)shop_item->item_count, (int)shop_item->item_price);
						item_count++;
					}
				}

				*(int *)&buffer[4] = item_count;

				pUser->SetPrivateStoreList((unsigned char *)buffer);

				pSocket->pED->osr->current_stage++;
			} 
			else 
			{
				pSocket->pED->osr->current_stage++;
			}
		} 
		else if (pSocket->pED->osr->shop_type == StoreBuy) 
		{
			if (pSocket->pED->osr->current_stage == 0) 
			{
				// private store manage
				typedef bool (*_psm)(CUserSocket*,unsigned char *);
				bool ret = _psm(0x872DD0)(pSocket, NULL);
				pSocket->pED->osr->current_stage++;
			} 
			else if (pSocket->pED->osr->current_stage == 1) 
			{
				if(pSocket->pED->osr->char_locX >0)
				{
					pUser->pSD->Pos.x = pSocket->pED->osr->char_locX;
					pUser->pSD->Pos.y = pSocket->pED->osr->char_locY;
					pUser->pSD->Pos.z = pSocket->pED->osr->char_locZ;
					pUser->pSD->sHeading = (WORD)pSocket->pED->osr->char_Heading;
				}

				pUser->SetPrivateStoreBuyMsg((unsigned char *)pSocket->pED->osr->shop_text);
				pUser->pED->wShopTitle2 = wstring(pSocket->pED->osr->shop_text);
				pSocket->pED->osr->current_stage++;
			} 
			else if (pSocket->pED->osr->current_stage == 2) 
			{
				// build private store sell list
				buffer_len = Assemble(buffer, 8192, "d", 0); // put a placeholder for item count

				bool m_continue = true;
				for (int i=0; i<pSocket->pED->osr->shop_items.size(); i++) 
				{
					OfflineShopItem *shop_item = &pSocket->pED->osr->shop_items[i];
					CItem *pItem = pUser->inventory.GetItemByDBID(shop_item->item_type_id);
					if (pItem == NULL) 
					{
						g_Log.Add(CLog::Error, "[OfflineShopRestore] Unable to locate item in player inventory! [%d]", shop_item->item_type_id);
					} 
					else 
					{
						//buffer_len += Assemble(&buffer[buffer_len], 8192-buffer_len, "dddd", pItem->nObjectID, pItem->pSID->nItemID, (int)shop_item->item_count, (int)shop_item->item_price);
						buffer_len += Assemble(&buffer[buffer_len], 8192-buffer_len, "dhhdd", pItem->pSID->nItemID, (int)shop_item->enchant, 0, (int)shop_item->item_count, (int)shop_item->item_price);
						item_count++;
					}
				}

				*(int *)buffer = item_count;

				pUser->SetPrivateStoreBuyList((unsigned char *)buffer);

				pSocket->pED->osr->current_stage++;
			} 
			else 
			{
				pSocket->pED->osr->current_stage++;
			}
		} 
		else if (pSocket->pED->osr->shop_type == StoreRecipe) 
		{
			if (pSocket->pED->osr->current_stage == 0) 
			{
				bool is_dwarf = (pUser->pSD->nClass == 57 || pUser->pSD->nClass == 118);

				bool ret = pUser->RequestRecipeShopManageList((int)!is_dwarf);
				pSocket->pED->osr->current_stage++;
			} 
			else if (pSocket->pED->osr->current_stage == 1) 
			{
				if(pSocket->pED->osr->char_locX >0)
				{
					pUser->pSD->Pos.x = pSocket->pED->osr->char_locX;
					pUser->pSD->Pos.y = pSocket->pED->osr->char_locY;
					pUser->pSD->Pos.z = pSocket->pED->osr->char_locZ;
					pUser->pSD->sHeading = (WORD)pSocket->pED->osr->char_Heading;
				}

				pUser->SetRecipeStoreMsg((unsigned char *)pSocket->pED->osr->shop_text);
				pUser->pED->wShopTitle2 = wstring(pSocket->pED->osr->shop_text);
				pSocket->pED->osr->current_stage++;
			} 
			else if (pSocket->pED->osr->current_stage == 2) 
			{
				// build private store sell list
				buffer_len = Assemble(buffer, 8192, "d", 0); // put a placeholder for item count

				for (int i=0; i<pSocket->pED->osr->shop_items.size(); i++) 
				{
					OfflineShopItem *shop_item = &pSocket->pED->osr->shop_items[i];
					buffer_len += Assemble(&buffer[buffer_len], 8192-buffer_len, "dd", shop_item->item_type_id, (int)shop_item->item_price);
					item_count++;
				}

				*(int *)buffer = item_count;

				pUser->SetRecipeStoreList((unsigned char *)buffer);
				pSocket->pED->osr->current_stage++;
			} 
			else 
			{
				pSocket->pED->osr->current_stage++;
			}
		}

		if (pSocket->pED->osr->current_stage == 5) 
		{
			if (pUser->pSD->nStoreMode == 3 || pUser->pSD->nStoreMode == 5 || pUser->pSD->nStoreMode == 1) 
			{
				g_OfflineShop.AutoActivate(pUser);
				//g_OfflineShop.RequestActivateOfflineShop(pUser);
//				g_Log.Add(CLog::Error, "[OfflineShopRestorer] private store for user [%S]", pUser->pSD->wszName);
			} 
			else 
			{
				g_Log.Add(CLog::Error, "[OfflineShopRestorer] failed to create private store for user [%S]", pUser->pSD->wszName);
			}
		}
		
	}

	if (pUser->GetSocket() != NULL && pUser->GetSocket()->pED->is_osr_buff) 
	{
		CUserSocket *pSocket = pUser->GetSocket();

		if (pSocket->pED->osr->current_stage == 0) 
		{
			g_OfflineBuffer.EnableBuffer(pUser,pSocket->pED->osr->shop_text,pSocket->pED->osr->price);
			pSocket->pED->osr->current_stage++;
		}

	}

	unguard;
}

DWORD WINAPI SocketThread(LPVOID lpParam)
{
	while (g_OfflineShopRestore.processing_shops) {
		if (!g_OfflineShopRestore.ShopRecordPending()) {
			Sleep(1000);
			continue;
		}

		SOCKET conn = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (conn == INVALID_SOCKET) {
			g_Log.Add(CLog::Error, "[OfflineShopRestore] WSA Error at socket [%d]", WSAGetLastError());
			return 1;
		}

		sockaddr_in endpoint;
		endpoint.sin_family = AF_INET;
		endpoint.sin_addr.s_addr = inet_addr("127.0.0.1");
		//endpoint.sin_port = htons(UserPort); // should use l2server config value
		endpoint.sin_port = htons(GetPrivateProfileInt(_T("Setting"), _T("UserPort"), FALSE, l2server_ini));

		int res = connect(conn, (SOCKADDR *)&endpoint, sizeof(endpoint)); 
		if (res == SOCKET_ERROR) {
			closesocket(conn);
			g_Log.Add(CLog::Error, "[OfflineShopRestore] WSA Error at connect [%d]", WSAGetLastError());
			return 1;
		}

		g_OfflineShopRestore.AddSocket(conn,false);

//Sleep(3000);

		res = send(conn, (const char *)protocol_version_packet, sizeof(protocol_version_packet), 0);
			
		if (res == SOCKET_ERROR) {
			closesocket(conn);
			g_Log.Add(CLog::Error, "[OfflineShopRestore] WSA Error at send [%d]", WSAGetLastError());
			return 1;
		}

		char recvbuf[2];
		res = recv(conn, recvbuf, 2, 0);
		if (res == 0) {
			closesocket(conn);
		}
	}
	return 1;
}