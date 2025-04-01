#include "StdAfx.h"
#include "Hair2Slot.h"
#include <winbase.h>
#include "DB.h"
#include "Utils.h"
#include "PacketHandler.h"
//#include "BossRangePvp.h"
#include "OfflineShopRestore.h"
#include "MemoryObject.h"

MemoryObject;
int StotTypeArr[21] = {
	0x1,
	0x2,
	0x4,
	0x8,
	0x10,
	0x20,
	0x40,
	0x80,
	0x100,
	0x200,
	0x400,
	0x800,
	0x1000,
	0x2000,
	0x4000,
	0x8000,
	0x10000,
	0x20000,
	0x40000,
	0x80000,
	0
};

void Hair2Slot::PostInit() {
	g_HookManager.WriteMemoryDWORD(0xBEFE00, (DWORD)Hair2Slot::LoadSelectedCharacterPacket);
}

//bool Hair2Slot::UnequipItemPacket(CUserSocket* pSocket, const unsigned char* packet) {
//	typedef bool (*f)(CUserSocket*,const unsigned char*);
//	return f(0x860310)(pSocket, packet);
//}

void Hair2Slot::Initialize() {
	//BossRangePvp::Initialize();
	//hook CCreature::ValidateAttachedSkills
	//CCreature::ValidateParameters
	g_HookManager.WriteCall(0x517FCD, Hair2Slot::CCreature::ValidateAttachedSkills, 0);
	//CCreature::EquipItem
	g_HookManager.WriteCall(0x519E07, Hair2Slot::CCreature::ValidateAttachedSkills, 0);
	//CCreature::UnequipItem by slot type
	g_HookManager.WriteCall(0x51A1D2, Hair2Slot::CCreature::ValidateAttachedSkills, 0);
	//CCreature::UnequipItem by item pointer
	g_HookManager.WriteCall(0x51A4B4, Hair2Slot::CCreature::ValidateAttachedSkills, 0);

	//g_HookManager.WriteMemoryDWORD(0xBF8958, (DWORD)Hair2Slot::UnequipItemPacket);
	//hook
	g_HookManager.WriteCall(0x5720A7, Hair2Slot::HookCreatePet, 0);
	//g_HookManager.WriteMemoryDWORD(0xA876C8, (DWORD) Hair2Slot::User::UnequipItemBySlot);

	//TODO hook 4DA780?
	//#UnequipItemPacket
	g_HookManager.WriteRelativeAddress(0x8604A1, 3, StotTypeArr, 0);//bottom
	g_HookManager.WriteRelativeAddress(0x8604A8, 3, &(StotTypeArr[20]), 0);//top

	//#CCreature::IsEquiped
	// User::SendItemList
	g_HookManager.WriteCall(0x81AB60, Hair2Slot::CCreature::IsEquiped, 0);
	g_HookManager.WriteCall(0x81A17F, Hair2Slot::CCreature::IsEquiped, 0);
	//ItemSlotTypeMaskArray
	g_HookManager.WriteRelativeAddress(0x81AB3F, 3, StotTypeArr, 0);//bottom
	g_HookManager.WriteRelativeAddress(0x81A154, 3, StotTypeArr, 0);//bottom
	g_HookManager.WriteRelativeAddress(0x81A04E, 3, StotTypeArr + 20, 0);//top
	g_HookManager.WriteRelativeAddress(0x81A92C, 3, StotTypeArr + 20, 0);//top
	g_HookManager.WriteRelativeAddress(0x81AA84, 3, StotTypeArr + 20, 0);//top
	g_HookManager.WriteRelativeAddress(0x81A93D, 3, StotTypeArr + 20, 0);//top
	g_HookManager.WriteRelativeAddress(0x81B033, 3, StotTypeArr + 20, 0);//top
	g_HookManager.WriteRelativeAddress(0x81B044, 3, StotTypeArr + 20, 0);//top
	g_HookManager.WriteMemoryBYTE(0x81AB67, 20);//SlotType count
	g_HookManager.WriteMemoryBYTE(0x81A186, 20);//SlotType count

	//User::DropItem
	//ItemSlotTypeMaskArray
	//top array0xBEFD80
	//{//LoadSelectedCharacterPacket
	//}
	
	//

}

/*struct socket_sp {
	CUserSocket* pSocket;
	int type;
};*/


class socket_sp {
public:
    socket_sp() : pSocket(0), type(0)
    {
    }

    ~socket_sp() {
		if (pSocket) reinterpret_cast<MemoryObject*>(pSocket)->Release(__FILE__, __LINE__, type, false);
    }

    CUserSocket* pSocket;
    int type;
};

void GetUserSocket(socket_sp& pSocket, int id) {
	void* socket_table = (void*)0xE6C8580;
	typedef void (*f)(void*, socket_sp&, INT64);
	f(0x479090)(socket_table, pSocket, id);
}

bool Hair2Slot::UnequipItem(::User* pUser, int nSlotIndex) {
	g_Log.Add(CLog::Blue, "Hair2Slot::UnequipItem (%d)", nSlotIndex);
	return false;
}

bool Hair2Slot::UnequipItem(::User* pUser, CItem* pItem) {
	return false;
}


void Hair2Slot::HookCreatePet(void* table, ::User* pUser, void* pet) {
	if(pUser->ValidUser()) {
		if(pUser->pSD->pExData->hair[0] != -1) {
			if(CItem* pItem = pUser->inventory.GetItemByDBID(pUser->pSD->pExData->hair[0]))
				if(pItem->IsValidItem()) 
					pUser->pSD->pExData->hair[0] = pItem->pSID->nItemIndex;
		} else if(pUser->pSD->pExData->hair[1] != -1) {
			if(CItem* pItem = pUser->inventory.GetItemByDBID(pUser->pSD->pExData->hair[1]))
				if(pItem->IsValidItem()) 
					pUser->pSD->pExData->hair[1] = pItem->pSID->nItemIndex;
		}
	}
}

bool Hair2Slot::LoadSelectedCharacterPacket(void* pSocket, const unsigned char* packet) {
	guard;
//	g_Log.Add(CLog::Blue, "Hair2Slot::LoadSelectedCharacterPacket");
	typedef char (*f)(void*, const unsigned char*);
	int hair2 = 1, hairall = 2;
	int nSocketIndex;
	Disassemble(packet, "ddd", &hair2, &hairall, &nSocketIndex);
	socket_sp socketSP;
	GetUserSocket(socketSP, nSocketIndex);
	char result = f(0x589C10)(pSocket, packet + 8);
	::User* pUser = socketSP.pSocket->GetUser();
	if(pUser != NULL && pUser->ValidUser()) {
//		g_Log.Add(CLog::Blue, "Hair2Slot::LoadSelectedCharacterPacket hair2(%d) hairall(%d)", hair2, hairall);
		pUser->pSD->pExData->hair[0] = hair2 == 0 ? -1 : hair2;
		pUser->pSD->pExData->hair[1] = hairall == 0 ? -1 : hairall;
	}

	unguard;
	return g_OfflineShopRestore.OnLoadSelectedCharacterPacket((CDBSocket*)pSocket,(unsigned char*)packet+8);
	//return result;
}

void Hair2Slot::GetDataBaseEquipID(::User* pUser, int &hair, int& hair2, int& hairall) {
	guard;
	hair = hair2 = hairall = 0;
	if(pUser && pUser->ValidUser()) {
		{
			//ignore hair0
		}
		{
			//hair2
			if(pUser->pSD->pExData->hair[0] != -1) {
				CItemSP itemsp;
				CItem::FindItemSp(itemsp, pUser->pSD->pExData->hair[0]);
				if(CItem* item = itemsp.get())
					hair2 = item->nDBID;
			}
		}
		{
			//hairall
			if(pUser->pSD->pExData->hair[1] != -1) {
				CItemSP itemsp;
				CItem::FindItemSp(itemsp, pUser->pSD->pExData->hair[1]);
				if(CItem* item = itemsp.get())
					hairall = item->nDBID;
			}
		}
	}
	unguard;
}

//head?
void Hair2Slot::GetUserPaperDollID(::User* pUser, int& nHeadObjectID, int& nHeadItemID, int& nFaceObjectID, int& nFaceItemID) {
	guard;
	nHeadObjectID = nHeadItemID = nFaceObjectID = nFaceItemID = 0;
	if(pUser->ValidUser()) {
		if(pUser->pSD->nEquipment[16] != -1) {
			CItemSP itemsp;
			CItem::FindItemSp(itemsp, pUser->pSD->nEquipment[16]);
			if(CItem* pItem = itemsp.get()) {
				nHeadObjectID = pItem->nObjectID;
				nHeadItemID = pItem->pSID->nItemID;
			}
		}
		if(pUser->pSD->pExData->hair[0] != -1) {
			CItemSP itemsp;
			CItem::FindItemSp(itemsp, pUser->pSD->pExData->hair[0]);
			if(CItem* pItem = itemsp.get()) {
				nFaceObjectID = pItem->nObjectID;
				nFaceItemID = pItem->pSID->nItemID;

			}
		} else if(pUser->pSD->pExData->hair[1] != -1) {
			CItemSP itemsp;
			CItem::FindItemSp(itemsp, pUser->pSD->pExData->hair[1]);
			if(CItem* pItem = itemsp.get()) {
				nHeadObjectID = pItem->nObjectID;
				nHeadItemID = pItem->pSID->nItemID;
			}
		}
	}
	unguard;
//		g_Log.Add(CLog::Blue, "nFaceObjectID(%d) nFaceItemID(%d) nHeadObjectID(%d) nHeadItemID(%d)", nFaceObjectID, nFaceItemID, nHeadObjectID,nHeadItemID);
}

//return -1 not handle 
//return 0 false
//return 1 true
int Hair2Slot::User::EquipItem(::User *pUser, CItem *pItem, int nForce) {
	guard;
	//g_Log.Add(CLog::Blue, "Hair2Slot::User::EquipItem");
	if(pUser && pUser->ValidUser() && pItem && pItem->IsValidItem()) {
		int nSlotType = pItem->pSID->nSlotType;
		//g_Log.Add(CLog::Blue, "Hair2Slot arg nForce %d nSlotType %d", nForce, nSlotType);
		if(nSlotType == 0x40000 || nSlotType == 0x80000 || nSlotType == 0x10000) {
			if(InterlockedExchange((volatile LONG*)(((INT64)pUser) + 0x1A2C), 1) == 1)
			{
				unguard;
				return 0;
			}
			//g_Log.Add(CLog::Blue, "Try equip hairall hair2 %d", nSlotType);

			if(pItem->pII->_align[12] <= 0) {
				if(pUser->CanEquip(pItem)) {
					
					//g_Log.Add(CLog::Blue, "can equip");
					
					if(pUser->pSD->nStoreMode) {
						pUser->SendSystemMessage(1578);
						InterlockedExchange((volatile LONG*)(((INT64)pUser) + 0x1A2C), 0);
						unguard;
						return 0;
					}
					if(nSlotType == 0x10000) {
						{ //hair
							CItemSP itemsp;
							CItem::FindItemSp(itemsp, pUser->pSD->nEquipment[16]);
							if(CItem* pItemHair = itemsp.get()) {
								if(pUser->inventory.ReadLock(pUser->pSD->pExData->hair[0]))
									pUser->inventory.SetInventoryChanged(pItemHair, 2);
							}
						}
						{ //hairall
							CItemSP itemsp;
							CItem::FindItemSp(itemsp, pUser->pSD->pExData->hair[1]);
							if(CItem* pItemHair = itemsp.get()) {
								if(pUser->inventory.ReadLock(pUser->pSD->pExData->hair[1]))
									pUser->inventory.SetInventoryChanged(pItemHair, 2);
							}
						}
					} else if(nSlotType == 0x40000) {

						{ //hair2
							CItemSP itemsp;
							CItem::FindItemSp(itemsp, pUser->pSD->pExData->hair[0]);
							if(CItem* pItemHair = itemsp.get()) {
								if(pUser->inventory.ReadLock(pUser->pSD->pExData->hair[0]))
									pUser->inventory.SetInventoryChanged(pItemHair, 2);
							}
						}
						{ //hairall
							CItemSP itemsp;
							CItem::FindItemSp(itemsp, pUser->pSD->pExData->hair[1]);
							if(CItem* pItemHair = itemsp.get()) {
								if(pUser->inventory.ReadLock(pUser->pSD->pExData->hair[1]))
									pUser->inventory.SetInventoryChanged(pItemHair, 2);
							}
						}
					} else if(nSlotType == 0x80000) {
						{ //hair
							CItemSP itemsp;
							CItem::FindItemSp(itemsp, pUser->pSD->nEquipment[16]);
							if(CItem* pItemHair = itemsp.get()) {
								if(pUser->inventory.ReadLock(pUser->pSD->pExData->hair[0]))
									pUser->inventory.SetInventoryChanged(pItemHair, 2);
							}
						}
						{ //hair2
							CItemSP itemsp;
							CItem::FindItemSp(itemsp, pUser->pSD->pExData->hair[0]);
							if(CItem* pItemHair = itemsp.get()) {
								if(pUser->inventory.ReadLock(pUser->pSD->pExData->hair[0]))
									pUser->inventory.SetInventoryChanged(pItemHair, 2);
							}
						}
						{ //hairall
							CItemSP itemsp;
							CItem::FindItemSp(itemsp, pUser->pSD->pExData->hair[1]);
							if(CItem* pItemHair = itemsp.get()) {
								if(pUser->inventory.ReadLock(pUser->pSD->pExData->hair[1]))
									pUser->inventory.SetInventoryChanged(pItemHair, 2);
							}
						}
					}

					CItemSP itemsp;
					CItem::FindItemSp(itemsp, pUser->pSD->pExData->hair[0]);
					if(CItem* pItemHair2 = itemsp.get()) {
						if(pUser->inventory.ReadLock(pUser->pSD->pExData->hair[0]))
							pUser->inventory.SetInventoryChanged(pItemHair2, 2);
					}

					if(pUser->inventory.ReadLock(pItem->pSID->nItemIndex)) {
						pUser->lpSharedDataLock->Lock(__FILEW__, 0);
						switch(nSlotType) {
						case 0x10000://hair
							pUser->pSD->nEquipment[16] = pItem->pSID->nItemIndex;
							pUser->pSD->pExData->hair[1] = -1;
							break;
						case 0x40000://hair2
							pUser->pSD->pExData->hair[0] = pItem->pSID->nItemIndex;
							pUser->pSD->pExData->hair[1] = -1;
							break;
						case 0x80000://hairall
							pUser->pSD->nEquipment[16] = -1;
							pUser->pSD->pExData->hair[0] = -1;
							pUser->pSD->pExData->hair[1] = pItem->pSID->nItemIndex;
							break;
						}
						pUser->lpSharedDataLock->Unlock(__FILEW__, 0);
					}
					//819C40 send Item list
					{
						typedef void(*f)(::User*, BYTE, WORD, INT64);
						f(0x00819C40)(pUser, 1, 1, 0);
					}
					pUser->SendUserInfo();
					
					//*((char*)(((LONG)pUser) + 0xCA4)) = 1;
					pUser->broadcastInfoPacket = true;
					
					{//SendETCBuffStatusInfo
						typedef void (* f) (::User*);
						f(0x7FFEB0L)(pUser);
					}
					InterlockedExchange((volatile LONG*)(((INT64)pUser) + 0x1A2C), 0);
					unguard;
					return 1;
				}
			}
			InterlockedExchange((volatile LONG*)(((INT64)pUser) + 0x1A2C), 0);
			unguard;
			return 0;
		} else
			{
			unguard;
			return -1;
		}
	} else {
		unguard;
		return -1;
		}

		unguard;
}

int Hair2Slot::CCreature::IsEquiped(::CCreature* pCreature, int nItemServerId, int nSlotIndex) {

	//g_Log.Add(CLog::Blue, "EquipItem nItemServerId(%d) nSlotIndex(%d)", nItemServerId, nSlotIndex);
	if(pCreature->pSD->pExData->hair[0] == nItemServerId)
		return 18;
	if(pCreature->pSD->pExData->hair[1] == nItemServerId)
		return 19;
	typedef int (*f)(::CCreature*, int, int);
	int result = f(0x4E11D0)(pCreature, nItemServerId, nSlotIndex);
	return result == 18 ? 20 : result;
}

int Hair2Slot::CCreature::EquipItem(::User *pUser, CItem *pItem, int nSlotIndex) {

	return 0;
}