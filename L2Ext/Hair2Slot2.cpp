#include "StdAfx.h"
#include "Hair2Slot.h"

void Hair2Slot::GetItemIDCharInfo(::User *pUser, int& haird, int& hair, int& face) {
	guard;
	haird = hair = face = 0;
	if(pUser) {
		if(pUser->pSD->pExData->hair[1] != -1) {
			CItemSP item;
			CItem::FindItemSp(item, pUser->pSD->pExData->hair[1]);
			if(CItem* pItem = item.get())
				haird = hair = pItem->pSID->nItemID;
		} else {
			if(pUser->pSD->nEquipment[16] != -1) {
				CItemSP item;
				CItem::FindItemSp(item, pUser->pSD->nEquipment[16]);
				if(CItem* pItem = item.get())
					hair = pItem->pSID->nItemID;
					
			}
			
			if(pUser->pSD->pExData->hair[0] != -1) {
				CItemSP item;
				CItem::FindItemSp(item, pUser->pSD->pExData->hair[0]);
				if(CItem* pItem = item.get())
					face = pItem->pSID->nItemID;
					
					
			}
		}
	}
//	g_Log.Add(CLog::Blue, "Hair2Slot::GetItemIDCharInfo: haird(%d) hair(%d) face(%d)", haird, hair, face);
	unguard;
}

//see PlayerAction::UnequipItem
int Hair2Slot::User::UnequipItem2(::User* pUser, int nSlotType) {
	guard;
//	g_Log.Add(CLog::Blue, "Hair2Slot::User::UnequipItem2 ----1");
	if(!pUser)
	{
		unguard;
		return -1;
	}
	if(nSlotType == 18 || nSlotType == 19) {
		int nHairIndex = nSlotType - 18;
		if(pUser->pSD->pExData->hair[nHairIndex] != -1) {
			CItemSP itemsp;
			CItem::FindItemSp(itemsp, pUser->pSD->pExData->hair[nHairIndex]);
			if(CItem* pItem = itemsp.get()) {
				return Hair2Slot::User::UnequipItem2(pUser, pItem) < 20;
			} else
			{
				unguard;
				return 0;
			}
		} else
		{
			unguard;
			return 0;
		}
	} else
	{
		unguard;
		return -1;
	}
	unguard;
}
//must return unequiped slot index
//if not equiped than return 18(max num slot) in our case return 20(extens slot type)
//current method extends support for hair2 and hairall Creature::UnequipItem
//NOTE using hook from CreatureAction
int Hair2Slot::CCreature::UnequipItem(::CCreature* pCreature, CItem* pItem) {
	guard;
//	g_Log.Add(CLog::Blue, "Hair2Slot::CCreature::UnequipItem");
	if(!(pCreature && pItem))
	{
		unguard;
		return 20;
	}
	if((pItem->pSID->nSlotType & 0xD0000) == 0) {
		unguard;
//		g_Log.Add(CLog::Error, "Hair2Slot::CCreature::UnequipItem try unequip item with wrong slot type(%d)", pItem->pSID->nSlotType);
		return 20;
	}

	if(CInventory::LockItemIndex(pCreature->inventory, pItem->pSID->nItemIndex)) {//TODO CInventory::ReadLock(pCreature->inventory, pItem->pSID->nItemIndex)
		if(pItem->pSID->nSlotType == 0x10000) {
			pCreature->lpSharedDataLock->Lock();
			if(pCreature->pSD->nEquipment[16] == pItem->pSID->nItemIndex)
			{
				if (pItem->pII->itemSkillId > 0)
				{
					if(pCreature->HaveSkill(pItem->pII->itemSkillId, 1))
					{
						pCreature->DeleteSkill(pItem->pII->itemSkillId);
					}
				}

				pCreature->pSD->nEquipment[16] = -1;
				CCreature::ValidateAllOnWeapon(pCreature);
				CCreature::ValidateAllOnArmors(pCreature);
				CCreature::ValidateAttachedSkills(pCreature);
				CCreature::ValidateAllOnSIM(pCreature);
			}
			pCreature->lpSharedDataLock->Unlock();
			unguard;
			return 16;
		} else {
			pCreature->lpSharedDataLock->Lock();
			int nHairIndex = 0;
			if(pItem->pSID->nSlotType == 0x40000) {
				nHairIndex = 0;
			} else if(pItem->pSID->nSlotType == 0x80000) {
				nHairIndex = 1;
			}
			
			if(pCreature->pSD->pExData->hair[nHairIndex] == pItem->pSID->nItemIndex) 
			{
				if (pItem->pII->itemSkillId > 0)
				{
					if(pCreature->HaveSkill(pItem->pII->itemSkillId, 1))
					{
						pCreature->DeleteSkill(pItem->pII->itemSkillId);
					}
				}
				pCreature->pSD->pExData->hair[nHairIndex] = -1;
				CCreature::ValidateAllOnWeapon(pCreature);
				CCreature::ValidateAllOnArmors(pCreature);
				CCreature::ValidateAttachedSkills(pCreature);
				CCreature::ValidateAllOnSIM(pCreature);
			}
		
			pCreature->lpSharedDataLock->Unlock();
			unguard;
			return 18 + nHairIndex;
		}

	} else
	{
		unguard;
		return 20;
	}
	unguard;
}

#define ENTER_STUB(user) InterlockedExchange((volatile LONG*)(((INT64)user) + 0x1A2C), 1)
#define LEAVE_STUB(user) InterlockedExchange((volatile LONG*)(((INT64)user) + 0x1A2C), 0)

//second version
//unequip user item by item slot
int Hair2Slot::User::UnequipItem2(::User *pUser, CItem *pItem) {
	guard;
	if(pUser && pItem && (pItem->pSID->nSlotType & 0xD0000)) {
		if(ENTER_STUB(pUser) == 1)
		{
			unguard;
			return 20;
		}
		if(pUser->pSD->pExData->hair[0] != pItem->pSID->nItemIndex && pUser->pSD->pExData->hair[1] != pItem->pSID->nItemIndex && pUser->pSD->nEquipment[16] != pItem->pSID->nItemIndex) {
			LEAVE_STUB(pUser);
			unguard;
			return 20;
		}
		int result = Hair2Slot::CCreature::UnequipItem(pUser->SafeCastCreature(), pItem);
		if(result < 20) {
			pUser->inventory.pLock->WriteLock();
			pUser->inventory.SetInventoryChanged(pItem, 2);
			pUser->inventory.pLock->Done();
			//pUser->SendItemList();
			{
				typedef void(*f)(::User*, BYTE, WORD, INT64);//SendItemList
				f(0x00819C40L)(pUser, 1, 1, 0);
			}

			if(pItem->pSID->nEnchantLevel <= 0) {
				pUser->pSocket->Send("cdddd", 0x64, 417, 1, 3, pItem->nObjectType);
			} else {
				pUser->pSocket->Send("cddddd", 0x64, 1064, 2, 1, pItem->pSID->nEnchantLevel, 3, pItem->nObjectType);
			}
			if(pUser->pSD->fHP > pUser->pSD->MaxHP)
				pUser->pSD->fHP = pUser->pSD->MaxHP;
			if(pUser->pSD->fMP > pUser->pSD->MaxMP)
				pUser->pSD->fMP = pUser->pSD->MaxMP;
			if(pUser->pSD->fCP > pUser->pSD->MaxCP)
				pUser->pSD->fCP = pUser->pSD->MaxCP;
			pUser->SendUserInfo();
			//*((char*)(((LONG)pUser) + 0xCA4)) = 1;
			pUser->broadcastInfoPacket = true;
			LEAVE_STUB(pUser);
			unguard;
			return result;
		} else {
			LEAVE_STUB(pUser);
			unguard;
			return 20;
		}

	} else
	{
		unguard;
		return 20;
	}
	unguard;
}


int Hair2Slot::CCreature::EquipItem2(::User* pUser, CItem* pItem, int nSlotIndex) {
	guard;
//	g_Log.Add(CLog::Blue, "Hair2Slot::CCreature::EquipItem2 [%d]",pItem->pSID->nSlotType);
	if(pItem && pUser && (pItem->pSID->nSlotType & 0xD0000)) {
		if(CInventory::LockItemIndex(pUser->inventory, pItem->pSID->nItemIndex)) {
			pUser->lpSharedDataLock->Lock();
			if(pItem->pSID->nSlotType == 0x10000) {
				pUser->pSD->nEquipment[16] = pItem->pSID->nItemIndex;
				pUser->pSD->pExData->hair[1] = -1;
			} else if(pItem->pSID->nSlotType == 0x40000) {
				pUser->pSD->pExData->hair[0] = pItem->pSID->nItemIndex;
				pUser->pSD->pExData->hair[1] = -1;

				if (pItem->pII->itemSkillId > 0)
				{
					if(!pUser->CastCreature()->HaveSkill(pItem->pII->itemSkillId, 1))
					{
						pUser->AcquireSkill(pItem->pII->itemSkillId, 1);
					}
				}

			} else if(pItem->pSID->nSlotType == 0x80000) {
				pUser->pSD->nEquipment[16] = -1;
				pUser->pSD->pExData->hair[0] = -1;
				pUser->pSD->pExData->hair[1] = pItem->pSID->nItemIndex;

				if (pItem->pII->itemSkillId > 0)
				{
					if(!pUser->CastCreature()->HaveSkill(pItem->pII->itemSkillId, 1))
					{
						pUser->AcquireSkill(pItem->pII->itemSkillId, 1);
					}
				}
			}
			CCreature::ValidateAttachedSkills(pUser->CastCreature());
			pUser->ValidateAllOnSIM();
			pUser->lpSharedDataLock->Unlock();

			unguard;
			return  1;
		} else
		{
			unguard;
			return 0;
		}
	} else
	{
		unguard;
		return 0;
	}
	unguard;
}

bool Hair2Slot::User::EquipItem2(::User* pUser, CItem* pItem, int nForce) {
	guard;
//	g_Log.Add(CLog::Blue, "Hair2Slot::User::EquipItem2");
	if(!(pUser && pItem))
	{
		unguard;
		return false;
	}
	if((pItem->pSID->nSlotType & 0xD0000) == 0) {
//		g_Log.Add(CLog::Error, "Hair2Slot::User::EquipItem2 try equip item with wrong slot type(%d)", pItem->pSID->nSlotType);
		unguard;
		return false;
	}
	if(ENTER_STUB(pUser) == 1)
	{
		unguard;
		return false;
	}

//if(*((int *)(((int)&pItem->pII) + 0xF0)) <= 0) {
	if(pUser->CanEquip(pItem)) {
		if(pUser->pSD->nStoreMode) {
			pUser->pSocket->SendSystemMessage(1578);
			LEAVE_STUB(pUser);
			unguard;
			return false;
		} 
		if(pItem->pSID->nSlotType == 0x10000) {
			{ //hair
				if(pUser->pSD->nEquipment[16] >= 0) {
					CItemSP itemsp;
					CItem::FindItemSp(itemsp, pUser->pSD->nEquipment[16]);
					if(CItem* pItemHair = itemsp.get()) {
						if(pUser->inventory.ReadLock(pUser->pSD->nEquipment[16]))
							pUser->inventory.SetInventoryChanged(pItemHair, 2);
					}
				}
			}
			{ //hairall
				if(pUser->pSD->pExData->hair[1] >= 0) {
					CItemSP itemsp;
					CItem::FindItemSp(itemsp, pUser->pSD->pExData->hair[1]);
					if(CItem* pItemHair = itemsp.get()) {
						if(pUser->inventory.ReadLock(pUser->pSD->pExData->hair[1]))
							pUser->inventory.SetInventoryChanged(pItemHair, 2);
					}
				}
			}
		} else if(pItem->pSID->nSlotType == 0x40000) { 
			{ //hair2
				if(pUser->pSD->pExData->hair[0] >= 0) {
					CItemSP itemsp;
					CItem::FindItemSp(itemsp, pUser->pSD->pExData->hair[0]);
					if(CItem* pItemHair = itemsp.get()) {
						if(pUser->inventory.ReadLock(pUser->pSD->pExData->hair[0]))
							pUser->inventory.SetInventoryChanged(pItemHair, 2);
					}
				}
			}
			{ //hairall
				CItemSP itemsp;
				if(pUser->pSD->pExData->hair[1] >= 0) {
					CItem::FindItemSp(itemsp, pUser->pSD->pExData->hair[1]);
					if(CItem* pItemHair = itemsp.get()) {
						if(pUser->inventory.ReadLock(pUser->pSD->pExData->hair[1]))
							pUser->inventory.SetInventoryChanged(pItemHair, 2);
					}
				}
			}
		} else if(pItem->pSID->nSlotType == 0x80000) {
			{ //hair
				if(pUser->pSD->nEquipment[16] >= 0) {
					CItemSP itemsp;
					CItem::FindItemSp(itemsp, pUser->pSD->nEquipment[16]);
					if(CItem* pItemHair = itemsp.get()) {
						if(pUser->inventory.ReadLock(pUser->pSD->nEquipment[16]))
							pUser->inventory.SetInventoryChanged(pItemHair, 2);
					}
				}
			}
			{ //hair2
				if(pUser->pSD->pExData->hair[0] >= 0) {
					CItemSP itemsp;
					CItem::FindItemSp(itemsp, pUser->pSD->pExData->hair[0]);
					if(CItem* pItemHair = itemsp.get()) {
						if(pUser->inventory.ReadLock(pUser->pSD->pExData->hair[0]))
							pUser->inventory.SetInventoryChanged(pItemHair, 2);
					}
				}
			}
			{ //hairall
				if(pUser->pSD->pExData->hair[1] >= 0) {
					CItemSP itemsp;
					CItem::FindItemSp(itemsp, pUser->pSD->pExData->hair[1]);
					if(CItem* pItemHair = itemsp.get()) {
						if(pUser->inventory.ReadLock(pUser->pSD->pExData->hair[1]))
							pUser->inventory.SetInventoryChanged(pItemHair, 2);
					}
				}
			}
		}

		if(Hair2Slot::CInventory::LockItemIndex(pUser->inventory, pItem->pSID->nItemIndex))
			pUser->inventory.SetInventoryChanged(pItem, 2);
		
		if(Hair2Slot::CCreature::EquipItem2(pUser, pItem, nForce)) {
			
			if(pItem->pSID->nEnchantLevel <= 0) {
				pUser->pSocket->Send("cdddd", 0x64, 49, 1, 3, pItem->nObjectType);
			} else {
				pUser->pSocket->Send("cddddd", 0x64, 368, 2, 1, pItem->pSID->nEnchantLevel, 3, pItem->nObjectType);
			}
			
			pUser->inventory.pLock->WriteLock();
			pUser->inventory.SetInventoryChanged(pItem, 2);
			pUser->inventory.pLock->Done();

			//pUser->SendItemList();
			{
				typedef void(*f)(::User*, BYTE, WORD, INT64);//SendItemList
				f(0x00819C40L)(pUser, 1, 1, 0);
			}
			if(pUser->pSD->fHP > pUser->pSD->MaxHP)
				pUser->pSD->fHP = pUser->pSD->MaxHP;
			if(pUser->pSD->fMP > pUser->pSD->MaxMP)
				pUser->pSD->fMP = pUser->pSD->MaxMP;
			if(pUser->pSD->fCP > pUser->pSD->MaxCP)
				pUser->pSD->fCP = pUser->pSD->MaxCP;
			pUser->SendUserInfo();
			pUser->broadcastInfoPacket = true;
			//*((char*)(((LONG)pUser) + 0xCA4)) = 1;

			LEAVE_STUB(pUser);
			unguard;
			return true;
		} else {
			LEAVE_STUB(pUser);
			unguard;
			return false;
		}
	} else {
		pUser->pSocket->SendSystemMessage(0x5EE);
		LEAVE_STUB(pUser);
		unguard;
		return false;
	}
//} else {
//	pUser->pSocket->SendSystemMessage(0x258);
//	LEAVE_STUB(pUser):
//	return false;
//}
	unguard;
}


//see CreatureAction::UseItem
//l2server hook call CCreature::UseItem in method User::UseItem
//return 0 as false
//return 1 as true
//return -1 unhandled n
int Hair2Slot::CCreature::UseItem(::CCreature* pCreature, CItem* pItem, bool nForce) {
	guard;
//	g_Log.Add(CLog::Blue, "Hair2Slot::CCreature::UseItem");
	if(pCreature && pItem && pItem->pII->defaultAction == 2 && (pItem->pSID->nSlotType & 0xD0000)) {
//		g_Log.Add(CLog::Blue, "Hair2Slot::CCreature::UseItem nSlotType(%d)", pItem->pSID->nSlotType);

		pCreature->WriteLock(__FILEW__, __LINE__);
		bool bIsEquiped = false;
		if(pItem->pSID->nSlotType == 0x10000) {
			bIsEquiped = pItem->pSID->nItemIndex == pCreature->pSD->nEquipment[16];
		} else if(pItem->pSID->nSlotType == 0x40000) {

			CItemSP item;
			CItem::FindItemSp(item, pCreature->pSD->pExData->hair[0]);
			if(CItem* pItem = item.get())
			{
				if (pItem->pII->itemSkillId > 0)
				{
					if(pCreature->HaveSkill(pItem->pII->itemSkillId, 1))
					{
						pCreature->DeleteSkill(pItem->pII->itemSkillId);
					}
				}
			}

			bIsEquiped = pItem->pSID->nItemIndex == pCreature->pSD->pExData->hair[0];
		} else {

			CItemSP item2;
			CItem::FindItemSp(item2, pCreature->pSD->pExData->hair[1]);
			if(CItem* pItem2 = item2.get())
			{
				if (pItem2->pII->itemSkillId > 0)
				{
					if(pCreature->HaveSkill(pItem2->pII->itemSkillId, 1))
					{
						pCreature->DeleteSkill(pItem2->pII->itemSkillId);
					}
				}
			}

			bIsEquiped = pItem->pSID->nItemIndex == pCreature->pSD->pExData->hair[1];
		}
		pCreature->WriteUnlock();
		if(bIsEquiped) {
			Hair2Slot::User::UnequipItem2(pCreature->SafeCastUser(), pItem);
		} else
			Hair2Slot::User::EquipItem2(pCreature->SafeCastUser(), pItem, 20);

		unguard;
		return 1;
	} else 
	{
		unguard;
		return -1;
	}
	unguard;
}