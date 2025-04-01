#include "StdAfx.h"
#include "CursedWeaponSystem.h"
#include "Packets.h"
#include "AIO.h"
#include "TerritoryData.h"
#include "VisualArmor.h"
#include "PlayerCustomizer.h"
#include "SubStack.h"
#include "OfflineBuffer.h"
#include "AccountDB.h"
#include "Hair2Slot.h"

extern UINT g_ClanLeaderTitleColor;
extern UINT g_ClanLeaderNicknameColor;
extern UINT g_GMTitleColor;
extern UINT g_GMNicknameColor;
extern UINT g_DefaultTitleColor;

extern INT32 g_MinEnchantLevelAuraHero;


void CPacketFix::UserInfoFix(CUserSocket *pSocket, const char *format, ...)
{
	guard;

	int race = 0;
	int clase = 0;
	int sex = 0;
	double ColRadius = 5;
	double ColHeight = 30;

	CPacket Packet;
	if(User *pUser = pSocket->GetUser())
	{

		TerritoryData& td = pUser->pSD->pExData->territoryData;

		va_list tag;
		va_start (tag, format); //start reading old packet data and assembling new packet
	/*c*/ Packet.WriteC(va_arg(tag, BYTE));
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//x
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//y
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//z
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//heading
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//object_id

			PWCHAR wName = va_arg(tag, PWCHAR);
			CNickNameChangeTerritory *pTerritory = NULL;
			if(int TerritoryID = pUser->pSD->nInNickNameChangeZone)
			{
				pTerritory = g_TerritoryChecker.GetTerritory(TerritoryID)->SafeCastNickNameChange();
				if(pTerritory)
				{
					PWCHAR wNewName = (PWCHAR)pTerritory->GetNickName();
					if(wNewName)
					{
						wName = wNewName;
					}
				}
			}
			/*S*/ Packet.WriteS(wName); //nickname

			DWORD Race = va_arg(tag, DWORD);
			DWORD Sex = va_arg(tag, DWORD);
			DWORD BaseClass = va_arg(tag, DWORD);

			if(pUser->pED->actualizarApariencias)
			{
				int custom_sex = g_AccountDB.GetCustomSex(pUser->pSD->nDBID);
				if (custom_sex >-1)
					Sex = custom_sex;

				int customSkin = g_AccountDB.GetCustomSkin(pUser->pSD->nDBID);
				if (customSkin >-1)
					BaseClass = customSkin;

				if (BaseClass >= 0 && BaseClass <= 9 || BaseClass >= 88 && BaseClass <= 93)				//humano warrior
					Race=0;
				else if (BaseClass >= 10 && BaseClass <= 17 || BaseClass >= 94 && BaseClass <= 98)		//humano mago
					Race=0;
				else if (BaseClass >= 18 && BaseClass <= 30 || BaseClass >= 99 && BaseClass <= 105)		//elf warrior y mago
					Race=1;
				else if (BaseClass >= 31 && BaseClass <= 43 || BaseClass >= 106 && BaseClass <= 112)	//dark elf warrior y mago
					Race=2;
				else if (BaseClass >= 44 && BaseClass <= 52 || BaseClass >= 113 && BaseClass <= 116)	//orco warrior y mago
					Race=3;
				else if (BaseClass >= 53 && BaseClass <= 57 || BaseClass >= 117 && BaseClass <= 118)	// enano
					Race=4;

				DWORD Magic = 0;
				if(CCategoryDataDB::IsInCategory(BaseClass, CCategoryDataDB::MAGE_GROUP))
					Magic = 1;

				ColRadius = g_World.GetRadius(Race, Sex, Magic);
				ColHeight = g_World.GetHeight(Race, Sex, Magic);

				pUser->pED->actualizarApariencias = false;
				pUser->pED->custom_sex = Sex;
				pUser->pED->customSkin = BaseClass;
				pUser->pED->Race = Race;
				pUser->pED->ColRadius = ColRadius;
				pUser->pED->ColHeight = ColHeight;
			}
			else
			{
				Sex = pUser->pED->custom_sex;
				BaseClass = pUser->pED->customSkin;
				Race = pUser->pED->Race;
				ColRadius = pUser->pED->ColRadius;
				ColHeight = pUser->pED->ColHeight;
			}

	/*d*/ Packet.WriteD(Race);	//race
	/*d*/ Packet.WriteD(Sex);	//sex
					
			if(g_SubStack.IsEnabled())
			{
				//get char index;
				UINT charIndex = UINT_MAX;
				for(UINT n=0;n<7;n++)
				{
					if(pSocket->characterDBID[n] == pUser->nDBID)
					{
						charIndex = n;
						break;
					}
				}
				if(charIndex != UINT_MAX && charIndex < 7)
				{
					if(pSocket->pED->baseClass[charIndex] != UINT_MAX)
					{
						BaseClass = pSocket->pED->baseClass[charIndex];
					}
				}
			}

	int nHeadObjectID = 0, nHeadItemID = 0, nFaceObjectID = 0, nFaceItemID = 0;
	Hair2Slot::GetUserPaperDollID(pUser, nHeadObjectID, nHeadItemID, nFaceObjectID, nFaceItemID);

	/*d*/ Packet.WriteD(BaseClass);	//class

	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//level
	/*d*/ Packet.WriteQ(va_arg(tag, INT64));	// - Exp will be Q in c5 format in format
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//str
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//dex
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//con
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//int
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//wit
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//men
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//max_hp
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//current_hp
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//max_mp
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//current_mp
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//sp
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//current_load
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//max_load
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//unknown SD->nWeaponRange
	//PAPERDOLL_START objectId
	DWORD dhairId_p = va_arg(tag, DWORD);
	DWORD rearId_p = va_arg(tag, DWORD);
	DWORD learId_p = va_arg(tag, DWORD);
	DWORD neckId_p = va_arg(tag, DWORD);
	DWORD rfingerId_p = va_arg(tag, DWORD);
	DWORD lfingerId_p = va_arg(tag, DWORD);
	DWORD headId_p = va_arg(tag, DWORD);
	DWORD rhandId_p = va_arg(tag, DWORD);
	DWORD lhandId_p = va_arg(tag, DWORD);
	DWORD glovesId_p = va_arg(tag, DWORD);
	DWORD chestId_p = va_arg(tag, DWORD);
	DWORD legsId_p = va_arg(tag, DWORD);
	DWORD feetId_p = va_arg(tag, DWORD);
	DWORD backId_p = va_arg(tag, DWORD);
	DWORD lrhandId_p = va_arg(tag, DWORD);
	va_arg(tag, DWORD);

	//PAPERDOLL item class id
		INT32 dhairId = va_arg(tag, INT32);
		INT32 rearId = va_arg(tag, INT32);
		INT32 learId = va_arg(tag, INT32);
		INT32 neckId = va_arg(tag, INT32);
		INT32 rfingerId = va_arg(tag, INT32);
		INT32 lfingerId = va_arg(tag, INT32);
		INT32 headId = va_arg(tag, INT32);
		INT32 rhandId = va_arg(tag, INT32);
		INT32 lhandId = va_arg(tag, INT32);
		INT32 glovesId = va_arg(tag, INT32);
		INT32 chestId = va_arg(tag, INT32);
		INT32 legsId = va_arg(tag, INT32);
		INT32 feetId = va_arg(tag, INT32);
		INT32 backId = va_arg(tag, INT32);
		INT32 lrhandId = va_arg(tag, INT32);
		va_arg(tag, INT32);
		INT32 hairId = nHeadItemID;
		INT32 faceId = nFaceItemID;


		if(pUser->pED->tvtUser.status == TvT::UserFighting || pUser->pED->tvtUser.status == TvT::UserPreparing)
		{
			if(pUser->pED->tvtUser.flag)
			{
				rhandId = 6718;
				lrhandId = 6718;
			}
		}

		if(g_VisualArmor.IsEnabled())
		{
			VisualArmorUser& vUser = pUser->pED->visualArmorUser;
			if(vUser.armorId > 0)
			{
				if(!pUser->olympiadUser.IsInside())
				{
					if(vUser.armorType == 0 || vUser.armorType == pUser->pSD->nArmorType)
					{
						chestId = vUser.chestSlotId;
						if (vUser.chestSlotId >0)
							chestId_p=1;

						legsId = vUser.legsSlotId;
						if (vUser.legsSlotId >0)
							legsId_p=2;

						glovesId = vUser.glovesSlotId;
						if (vUser.glovesSlotId >0)
							glovesId_p=3;

						feetId = vUser.feetSlotId;
						if (vUser.feetSlotId >0)
							feetId_p=4;

						if (vUser.hairSlotId > 0 && hairId == 0)
						{
							hairId = vUser.hairSlotId;
							if (vUser.hairSlotId >0)
								nHeadObjectID=5;
						}
					}
				}
			}
		}

		if (pUser->pED->hats_test_id>0)
		{
			nHeadObjectID = 6;
			hairId = pUser->pED->hats_test_id;
		}

		if (pUser->pED->shield_test_id>0)
		{
			lhandId_p = 7;
			lhandId = pUser->pED->shield_test_id;
		}

		if (pUser->pED->weapon_test_id>0)
		{
			rhandId_p = 8;
			rhandId = pUser->pED->weapon_test_id;
		}


		if(pUser->pED->tvtUser.status == TvT::UserFighting || pUser->pED->tvtUser.status == TvT::UserPreparing)
		{
			if(pUser->pED->tvtUser.flag)
			{
				rhandId_p = 1;
				lrhandId_p = 1;
			}
		}

		if(pUser->pED->m_CtfUserFlag>0)
		{
			lrhandId_p = 7;
			rhandId_p = 0;
			lhandId_p = 0;

			lrhandId = pUser->pED->m_CtfUserFlag;
			rhandId = 0;
			lhandId = 0;
		}


	/*d*/ Packet.WriteD(dhairId_p);	//dhair
	/*d*/ Packet.WriteD(rearId_p);	//rear
	/*d*/ Packet.WriteD(learId_p);	//lear
	/*d*/ Packet.WriteD(neckId_p);	//neck
	/*d*/ Packet.WriteD(rfingerId_p);	//rfinger
	/*d*/ Packet.WriteD(lfingerId_p);	//lfinger
	/*d*/ Packet.WriteD(headId_p);	//head
	/*d*/ Packet.WriteD(rhandId_p);	//rhand
	/*d*/ Packet.WriteD(lhandId_p);	//lhand
	/*d*/ Packet.WriteD(glovesId_p);	//gloves
	/*d*/ Packet.WriteD(chestId_p);	//chest
	/*d*/ Packet.WriteD(legsId_p);	//legs
	/*d*/ Packet.WriteD(feetId_p);	//feet
	/*d*/ Packet.WriteD(backId_p);	//back
	/*d*/ Packet.WriteD(lrhandId_p);	//lrhand
	/*d*/ Packet.WriteD(nHeadObjectID);	//hair  
	/*d*/ Packet.WriteD(nFaceObjectID);//face - interlude addon

	/*d*/ Packet.WriteD(dhairId);	//dhair
	/*d*/ Packet.WriteD(rearId);	//rear
	/*d*/ Packet.WriteD(learId);	//lear
	/*d*/ Packet.WriteD(neckId);	//neck
	/*d*/ Packet.WriteD(rfingerId);	//rfinger
	/*d*/ Packet.WriteD(lfingerId);	//lfinger
	/*d*/ Packet.WriteD(headId);	//head
	/*d*/ Packet.WriteD(rhandId);	//rhand
	/*d*/ Packet.WriteD(lhandId);	//lhand
	/*d*/ Packet.WriteD(glovesId);	//gloves
	/*d*/ Packet.WriteD(chestId);	//chest
	/*d*/ Packet.WriteD(legsId);	//legs
	/*d*/ Packet.WriteD(feetId);	//feet
	/*d*/ Packet.WriteD(backId);	//back
	/*d*/ Packet.WriteD(lrhandId);	//lrhand
	/*d*/ Packet.WriteD(hairId);	//hair
	/*d*/ Packet.WriteD(faceId);						//face - interlude addon - 

	//PAPERDOLL_END

			UINT nAugmentation = pUser->GetAugmentationID();
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteD(nAugmentation);//Augmentation ID lhand
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteD(nAugmentation);//Augmentation ID lrhand
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//p_atk
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//p_atk_speed
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//p_def
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//evasion
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//accuracy
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//critical_rate
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//m_atk
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//m_atk_speed
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//p_atk_speed
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//m_def
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//pvp_flag
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//karma
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//run_speed
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//walk_speed
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//swim_run_speed
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//swim_walk_speed
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//fly_run_speed
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//fly_walk_speed
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//fly_run_speed
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//fly_walk_speed
	/*f*/ Packet.WriteF(va_arg(tag, double));	//move_multipler
	/*f*/ Packet.WriteF(va_arg(tag, double));	//atk_speed_multipler

			double radius = va_arg(tag, double);
			double height = va_arg(tag, double);

			radius = ColRadius;
			height = ColHeight;

	/*f*/ Packet.WriteF(radius);	//collision_radius
	/*f*/ Packet.WriteF(height);	//collision_height

	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//hair_style
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//hair_color
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//face
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//builder_level

			if(pTerritory && pTerritory->IsHidePledge())
			{
					va_arg(tag, PWCHAR);
			/*S*/ Packet.WriteS(L"");	//title
					va_arg(tag, DWORD);
			/*d*/ Packet.WriteD(0);	//pledge_id
					va_arg(tag, DWORD);
			/*d*/ Packet.WriteD(0);	//pledge_crest_id
					va_arg(tag, DWORD);
			/*d*/ Packet.WriteD(0);	//ally_id
					va_arg(tag, DWORD);
			/*d*/ Packet.WriteD(0);	//ally_crest_id
			}else
			{
				PWCHAR wUserTitleOriginal = va_arg(tag, PWCHAR); //title save

				if(td.territoryId[SHOW_HP_TITLE] != 0)
				{
					int nCurrent_hp = static_cast<int>((int)pUser->pSD->fHP);
					int nCurrent_cp = static_cast<int>((int)pUser->pSD->fCP);
					int total_life = nCurrent_hp + nCurrent_cp;

					wstring wUserTitleHP = L"CP/HP: ["  + Utils::IntToWString(total_life) + L"]";

					if(pUser->pED->tvtUser.status == TvT::UserFighting || pUser->pED->tvtUser.status == TvT::UserPreparing)
					{
						if(pUser->pED->tvtUser.flag)
							wUserTitleHP = L"[FLAG]";
					}
						const WCHAR * wUserTitle = wUserTitleHP.c_str();
					/* S */ Packet.WriteS(wUserTitle);	//title
				}
				else if( (pUser->pSD->activateOfflineShopTime > 0) && (pUser->pED->nofflinesellbuffprice > 0) ) //offline buff shop
				{
					const WCHAR * wUserTitle = pUser->pED->offlineselltitle.c_str();
					Packet.WriteS(wUserTitle);	//title
				}
				else
				{
					if(pUser->pED->tvtUser.status == TvT::UserFighting || pUser->pED->tvtUser.status == TvT::UserPreparing)
					{
						if(pUser->pED->tvtUser.flag)
						{
							wstring wUserTitleHP = L"[FLAG]";
							const WCHAR * wUserTitle = wUserTitleHP.c_str();
							/* S */ //Packet.WriteS(wUserTitle);	//title
							Packet.WriteS(wUserTitleOriginal);
						}
						else
						{
							/* S */ //Packet.WriteS(L"");	//title
							Packet.WriteS(wUserTitleOriginal);
						}
					}
					else
					{
						/* S */ Packet.WriteS(wUserTitleOriginal);	//title
					}
				}

			/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//pledge_id
			/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//pledge_crest_id
			/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//ally_id
			/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//ally_crest_id
			}

	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//relation // 0x40 leader rights siege flags: attacker - 0x180 sword over name, defender - 0x80 shield, 0xC0 crown (|leader), 0x1C0 flag (|leader)
	/*c*/ Packet.WriteC(va_arg(tag, BYTE));		//mount_type
	/*c*/ Packet.WriteC(va_arg(tag, BYTE));		//private_store_mode
	/*c*/ Packet.WriteC(va_arg(tag, BYTE));		//dwarven_craft_mode
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//pk_count
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//pvp_count
	/*h*/ Packet.WriteH(va_arg(tag, WORD));		//cubic_count
	/*BuffSize*/ DWORD CubicBuffSize = va_arg(tag, DWORD);	//cubic_buff_size
	/*b*/ Packet.WriteB(CubicBuffSize, va_arg(tag, PUCHAR)); //cubic_buff
	/*c*/ Packet.WriteC(va_arg(tag, BYTE));		//find_party_members
	/*d*/ DWORD AbnormalVisualEffect = va_arg(tag, DWORD);	//abnormal_visual_effect
			if(pUser->pSD->pExData->SkillMod.semiInvisible)
			{
				AbnormalVisualEffect |= 0x100000;	//Stealth
			}
			if(pUser->pSD->activateOfflineShopTime)
			{
//				if(pUser->pSD->nStoreMode > 0)
//					AbnormalVisualEffect |= 0x000080; //Sleep
			}
			if(pUser->pED->spawnProtection == 2)
			{
				AbnormalVisualEffect |= 0x200000;
			}
			Packet.WriteD(AbnormalVisualEffect);
	/*c*/ Packet.WriteC(va_arg(tag, DWORD));	//unknown
	/*BuffSize*/ DWORD ClanPrivilegeBuffSize = va_arg(tag, DWORD); //c5fix = 4	//pledge_rights_buff_size
	/*b*/ PUCHAR ClanPrivilege = va_arg(tag, PUCHAR); //ClanPrivileges - 32 BYTES	//pledge_rights_buff
		Packet.WriteD(8388606);	//write static rights
	/*h*/ Packet.WriteH(va_arg(tag, WORD));		//recommendation_remaining
	/*h*/ Packet.WriteH(va_arg(tag, WORD));		//recommendation_received
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//unknown
		WORD inventory_limit = va_arg(tag, WORD);
		//pUser->pED->inventory_limit = (int)inventory_limit;

	/*h*/ Packet.WriteH(inventory_limit);		//inventory_limit
	
	UINT classId = va_arg(tag, DWORD);

	/*d*/ Packet.WriteD(classId);	//class_id

	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//unknown
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//max_cp
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//current_cp
	/*c*/ Packet.WriteC(va_arg(tag, BYTE));		//enchant_effect
	/*c*/ BYTE bTeam = va_arg(tag, BYTE);		//team_circle

			if(pUser->pSD->DuelInfo.DuelID && pUser->pSD->DuelInfo.Fighting)
				bTeam = pUser->pSD->DuelInfo.DuelTeam;

			if(pUser->pED->tvtUser.status == TvT::UserFighting || pUser->pED->tvtUser.status == TvT::UserPreparing)
				bTeam = pUser->pED->tvtUser.team;

			if(pUser->pED->inEventPvp > 0)
				bTeam = pUser->pED->inEventPvp;



			Packet.WriteC(bTeam); //1blue 2 red
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//pledge_large_crest_id
	/*c*/ Packet.WriteC(va_arg(tag, BYTE));		//is_nobless

	BYTE is_hero = va_arg(tag, BYTE);

	bool armaHeroAura = false;
	if (g_MinEnchantLevelAuraHero > 0)
	{
		CSharedItemData *pData = pUser->GetEquipedWeapon();
		if(pData)
		{
			CItem *pItem = pUser->inventory.GetItemBySID(pData->nObjectID);
			if(pItem->IsValid(VT_ITEMWEAPON))
			{
				if (pItem->pII->nCrystalType == 5 && pItem->pSID->nEnchantLevel >= g_MinEnchantLevelAuraHero)
				{
					is_hero = 1;	
					armaHeroAura = true;
				}
			}
		}
	}

	if(pUser->pSD->nHero == 2 && !armaHeroAura)
	/*c*/ Packet.WriteC(pUser->pED->customVerAuraHero);		//is_hero
	else if(armaHeroAura)
	/*c*/ Packet.WriteC(pUser->pED->customVerAuraHero);		//is_hero
	else
	/*c*/ Packet.WriteC(is_hero);		//is_hero


	/*c*/ Packet.WriteC(va_arg(tag, BYTE));		//is_fishing
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//fishing_x
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//fishing_y
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//fishing_z
		
			DWORD NickNameColor = va_arg(tag, DWORD);	//nickname_color
			if(pUser->pSD->nIsPledgeLeader && g_ClanLeaderNicknameColor != 0)
			{
				NickNameColor = g_ClanLeaderNicknameColor;
			}
			if(pUser->pSD->nBuilder && g_GMNicknameColor != 0)
			{
				NickNameColor = g_GMNicknameColor;
			}
			if(pUser->pED->nicknameColor != 0)
			{
				NickNameColor = pUser->pED->nicknameColor;
			}
			if(pUser->pED->nameColorEx != 0)
			{
				NickNameColor = pUser->pED->nameColorEx;
			}

			if(pUser->pED->aioId > 0)
			{
				if(g_AIOSystem.IsEnabled())
				{
					NickNameColor = pUser->pED->aioNicknameColor;
				}
			}
			if(pTerritory)
			{
				if(DWORD Color = pTerritory->GetColor())
					NickNameColor = Color;
			}

			//red = 255 //green = 65280
			if(td.territoryId[FACTION_ZONE] != 0)
			{
				if(pUser->pED->nFactionID == 1)
				{
					NickNameColor = (DWORD)255; //Red
				}
				else if(pUser->pED->nFactionID == 2)
				{
					NickNameColor = (DWORD)65280; //Green
				}
			}
			
			if(pUser->pED->tvtUser.status == TvT::UserFighting || pUser->pED->tvtUser.status == TvT::UserPreparing)
				NickNameColor = (DWORD)16777215; //White

	/*d*/ Packet.WriteD(NickNameColor);
		va_end(tag);

		//New C5 Things cdddddd
		Packet.WriteC((BYTE)pUser->pSD->nMoveType);
		Packet.WriteD(pUser->GetPledgeClass());
		Packet.WriteD(pUser->GetPledgeType());
		DWORD titleColor = g_DefaultTitleColor;
	
		if(pUser->pSD->nIsPledgeLeader && g_ClanLeaderTitleColor != 0)
		{
			titleColor = g_ClanLeaderTitleColor;
		}
				
		if(g_PlayerCustomizer.IsEnabled())
		{
			titleColor = g_PlayerCustomizer.GetPvpTitleColor(pUser->pSD->nPvpCount);
		}

		if(pUser->pSD->nBuilder && g_GMTitleColor != 0)
		{
			titleColor = g_GMTitleColor;
		}

		if(pUser->pED->titleColor != 0)
		{
			titleColor = pUser->pED->titleColor;
		}
		if(pUser->pED->titleColorEx != 0)
		{
			titleColor = pUser->pED->titleColorEx;
		}

		if(td.territoryId[SHOW_HP_TITLE] != 0)
		{
			int nCurrent_hp = static_cast<int>((int)pUser->pSD->fHP);
			int nCurrent_cp = static_cast<int>((int)pUser->pSD->fCP);
			int total_life = nCurrent_hp + nCurrent_cp;

			int nMax_hp = static_cast<int>((int)pUser->pSD->MaxHP);
			int nMax_cp = static_cast<int>((int)pUser->pSD->MaxCP);
			int Maxtotal_life = nMax_hp + nMax_cp;

			int n50perhp = Maxtotal_life * 0.50;
			int n35perhp = Maxtotal_life * 0.35;

			if( (total_life <= n50perhp) && (total_life > n35perhp) )
			{
				titleColor = 33023; //Orange
			}
			else if( total_life <= n35perhp )
			{
				titleColor = 255; //Red
			}
		}

		if( (pUser->pSD->activateOfflineShopTime > 0) && (pUser->pED->nofflinesellbuffprice > 0) ) //offline buff shop
		{
			titleColor = g_OfflineBuffer.GetOfflineBufferColor(); //Red
		}

		if(pUser->pED->tvtUser.status == TvT::UserFighting || pUser->pED->tvtUser.status == TvT::UserPreparing)
		{
			if(pUser->pED->tvtUser.flag)
			{
				titleColor = 65535; //Yellow
			}	
		}

		Packet.WriteD(titleColor);
		Packet.WriteD(pUser->pED->cursedWeaponLevel);
		Packet.WriteD(pUser->GetPledgeReputation());

		//SendNewInfo
		pSocket->Send("b", Packet.GetSize(), Packet.GetBuff());
	}

	unguard;
}

void CPacketFix::GMUserInfoFix(CUserSocket *pSocket, const char *format, ...)
{
	int race = 0;
	int clase = 0;
	int sex = 0;
	double ColRadius = 5;
	double ColHeight = 30;

	CPacket Packet;
	va_list tag;
	va_start (tag, format); //start reading old packet data and assembling new packet

	/*c*/ Packet.WriteC(va_arg(tag, BYTE));
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//x
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//y
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//z
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//heading
	UINT nObjectId = va_arg(tag, UINT);
	/*d*/ Packet.WriteD(nObjectId);	//object_id
	
	User *pUser = User::GetUserBySID(&nObjectId);
	
	if(pUser->ValidUser())
	{
		TerritoryData& td = pUser->pSD->pExData->territoryData;

		PWCHAR wName = va_arg(tag, PWCHAR);
		CNickNameChangeTerritory *pTerritory = NULL;
		if(int TerritoryID = pUser->pSD->nInNickNameChangeZone)
		{
			pTerritory = g_TerritoryChecker.GetTerritory(TerritoryID)->SafeCastNickNameChange();
			if(pTerritory)
			{
				PWCHAR wNewName = (PWCHAR)pTerritory->GetNickName();
				if(wNewName)
				{
					wName = wNewName;
				}
			}
		}
	/*S*/ Packet.WriteS(wName); //nickname

			DWORD Race = va_arg(tag, DWORD);
			DWORD Sex = va_arg(tag, DWORD);
			DWORD BaseClass = va_arg(tag, DWORD);

			if(pUser->pED->actualizarApariencias)
			{
				int custom_sex = g_AccountDB.GetCustomSex(pUser->pSD->nDBID);
				if (custom_sex >-1)
					Sex = custom_sex;

				int customSkin = g_AccountDB.GetCustomSkin(pUser->pSD->nDBID);
				if (customSkin >-1)
					BaseClass = customSkin;

				if (BaseClass >= 0 && BaseClass <= 9 || BaseClass >= 88 && BaseClass <= 93)				//humano warrior
					Race=0;
				else if (BaseClass >= 10 && BaseClass <= 17 || BaseClass >= 94 && BaseClass <= 98)		//humano mago
					Race=0;
				else if (BaseClass >= 18 && BaseClass <= 30 || BaseClass >= 99 && BaseClass <= 105)		//elf warrior y mago
					Race=1;
				else if (BaseClass >= 31 && BaseClass <= 43 || BaseClass >= 106 && BaseClass <= 112)	//dark elf warrior y mago
					Race=2;
				else if (BaseClass >= 44 && BaseClass <= 52 || BaseClass >= 113 && BaseClass <= 116)	//orco warrior y mago
					Race=3;
				else if (BaseClass >= 53 && BaseClass <= 57 || BaseClass >= 117 && BaseClass <= 118)	// enano
					Race=4;

				DWORD Magic = 0;
				if(CCategoryDataDB::IsInCategory(BaseClass, CCategoryDataDB::MAGE_GROUP))
					Magic = 1;

				ColRadius = g_World.GetRadius(Race, Sex, Magic);
				ColHeight = g_World.GetHeight(Race, Sex, Magic);

				pUser->pED->actualizarApariencias = false;
				pUser->pED->custom_sex = Sex;
				pUser->pED->customSkin = BaseClass;
				pUser->pED->Race = Race;
				pUser->pED->ColRadius = ColRadius;
				pUser->pED->ColHeight = ColHeight;
			}
			else
			{
				Sex = pUser->pED->custom_sex;
				BaseClass = pUser->pED->customSkin;
				Race = pUser->pED->Race;
				ColRadius = pUser->pED->ColRadius;
				ColHeight = pUser->pED->ColHeight;
			}

	/*d*/ Packet.WriteD(Race);	//race
	/*d*/ Packet.WriteD(Sex);	//sex
				
	if(g_SubStack.IsEnabled())
	{
		//get char index;
		UINT charIndex = UINT_MAX;
		for(UINT n=0;n<7;n++)
		{
			if(pSocket->characterDBID[n] == pUser->nDBID)
			{
				charIndex = n;
				break;
			}
		}
		if(charIndex != UINT_MAX && charIndex < 7)
		{
			if(pSocket->pED->baseClass[charIndex] != UINT_MAX)
			{
				BaseClass = pSocket->pED->baseClass[charIndex];
			}
		}
	}

	int nHeadObjectID = 0, nHeadItemID = 0, nFaceObjectID = 0, nFaceItemID = 0;
	Hair2Slot::GetUserPaperDollID(pUser, nHeadObjectID, nHeadItemID, nFaceObjectID, nFaceItemID);

	/*d*/ Packet.WriteD(BaseClass);	//class

	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//level
	/*d*/ Packet.WriteQ(va_arg(tag, INT64));	// - Exp will be Q in c5 format in format
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//str
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//dex
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//con
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//int
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//wit
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//men
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//max_hp
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//current_hp
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//max_mp
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//current_mp
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//sp
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//current_load
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//max_load
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//unknown
	//PAPERDOLL_START objectId
	DWORD dhairId_p = va_arg(tag, DWORD);
	DWORD rearId_p = va_arg(tag, DWORD);
	DWORD learId_p = va_arg(tag, DWORD);
	DWORD neckId_p = va_arg(tag, DWORD);
	DWORD rfingerId_p = va_arg(tag, DWORD);
	DWORD lfingerId_p = va_arg(tag, DWORD);
	DWORD headId_p = va_arg(tag, DWORD);
	DWORD rhandId_p = va_arg(tag, DWORD);
	DWORD lhandId_p = va_arg(tag, DWORD);
	DWORD glovesId_p = va_arg(tag, DWORD);
	DWORD chestId_p = va_arg(tag, DWORD);
	DWORD legsId_p = va_arg(tag, DWORD);
	DWORD feetId_p = va_arg(tag, DWORD);
	DWORD backId_p = va_arg(tag, DWORD);
	DWORD lrhandId_p = va_arg(tag, DWORD);
	va_arg(tag, DWORD);

	//PAPERDOLL item class id
		INT32 dhairId = va_arg(tag, INT32);
		INT32 rearId = va_arg(tag, INT32);
		INT32 learId = va_arg(tag, INT32);
		INT32 neckId = va_arg(tag, INT32);
		INT32 rfingerId = va_arg(tag, INT32);
		INT32 lfingerId = va_arg(tag, INT32);
		INT32 headId = va_arg(tag, INT32);
		INT32 rhandId = va_arg(tag, INT32);
		INT32 lhandId = va_arg(tag, INT32);
		INT32 glovesId = va_arg(tag, INT32);
		INT32 chestId = va_arg(tag, INT32);
		INT32 legsId = va_arg(tag, INT32);
		INT32 feetId = va_arg(tag, INT32);
		INT32 backId = va_arg(tag, INT32);
		INT32 lrhandId = va_arg(tag, INT32);
		va_arg(tag, INT32);
		INT32 hairId = nHeadItemID;
		INT32 faceId = nFaceItemID;

		if(pUser->pED->tvtUser.status == TvT::UserFighting || pUser->pED->tvtUser.status == TvT::UserPreparing)
		{
			if(pUser->pED->tvtUser.flag)
			{
				rhandId = 6718;
				lrhandId = 6718;
			}
		}

		if(g_VisualArmor.IsEnabled())
		{
			VisualArmorUser& vUser = pUser->pED->visualArmorUser;
			if(vUser.armorId > 0)
			{
				if(!pUser->olympiadUser.IsInside())
				{
					if(vUser.armorType == 0 || vUser.armorType == pUser->pSD->nArmorType)
					{
						chestId = vUser.chestSlotId;
						if (vUser.chestSlotId >0)
							chestId_p=1;

						legsId = vUser.legsSlotId;
						if (vUser.legsSlotId >0)
							legsId_p=2;

						glovesId = vUser.glovesSlotId;
						if (vUser.glovesSlotId >0)
							glovesId_p=3;

						feetId = vUser.feetSlotId;
						if (vUser.feetSlotId >0)
							feetId_p=4;

						if (vUser.hairSlotId > 0 && hairId == 0)
						{
							hairId = vUser.hairSlotId;
							if (vUser.hairSlotId >0)
								nHeadObjectID=5;
						}
					}
				}
			}
		}

		if (pUser->pED->hats_test_id>0)
		{
			nHeadObjectID = 6;
			hairId = pUser->pED->hats_test_id;
		}


		if (pUser->pED->shield_test_id>0)
		{
			lhandId_p = 7;
			lhandId = pUser->pED->shield_test_id;
		}

		if (pUser->pED->weapon_test_id>0)
		{
			rhandId_p = 8;
			rhandId = pUser->pED->weapon_test_id;
		}


	
	if(pUser->pED->tvtUser.status == TvT::UserFighting || pUser->pED->tvtUser.status == TvT::UserPreparing)
	{
		if(pUser->pED->tvtUser.flag)
		{
			rhandId_p = 6718;
			lrhandId_p = 6718;
		}
	}

		if(pUser->pED->m_CtfUserFlag>0)
		{
			lrhandId_p = 7;
			rhandId_p = 0;
			lhandId_p = 0;

			lrhandId = pUser->pED->m_CtfUserFlag;
			rhandId = 0;
			lhandId = 0;
		}



	/*d*/ Packet.WriteD(dhairId_p);	//dhair
	/*d*/ Packet.WriteD(rearId_p);	//rear
	/*d*/ Packet.WriteD(learId_p);	//lear
	/*d*/ Packet.WriteD(neckId_p);	//neck
	/*d*/ Packet.WriteD(rfingerId_p);	//rfinger
	/*d*/ Packet.WriteD(lfingerId_p);	//lfinger
	/*d*/ Packet.WriteD(headId_p);	//head
	/*d*/ Packet.WriteD(rhandId_p);	//rhand
	/*d*/ Packet.WriteD(lhandId_p);	//lhand
	/*d*/ Packet.WriteD(glovesId_p);	//gloves
	/*d*/ Packet.WriteD(chestId_p);	//chest
	/*d*/ Packet.WriteD(legsId_p);	//legs
	/*d*/ Packet.WriteD(feetId_p);	//feet
	/*d*/ Packet.WriteD(backId_p);	//back
	/*d*/ Packet.WriteD(lrhandId_p);	//lrhand
	/*d*/ Packet.WriteD(nHeadObjectID);	//hair
	/*d*/ Packet.WriteD(nFaceObjectID); 					//face - interlude addon

	/*d*/ Packet.WriteD(dhairId);	//dhair
	/*d*/ Packet.WriteD(rearId);	//rear
	/*d*/ Packet.WriteD(learId);	//lear
	/*d*/ Packet.WriteD(neckId);	//neck
	/*d*/ Packet.WriteD(rfingerId);	//rfinger
	/*d*/ Packet.WriteD(lfingerId);	//lfinger
	/*d*/ Packet.WriteD(headId);	//head
	/*d*/ Packet.WriteD(rhandId);	//rhand
	/*d*/ Packet.WriteD(lhandId);	//lhand
	/*d*/ Packet.WriteD(glovesId);	//gloves
	/*d*/ Packet.WriteD(chestId);	//chest
	/*d*/ Packet.WriteD(legsId);	//legs
	/*d*/ Packet.WriteD(feetId);	//feet
	/*d*/ Packet.WriteD(backId);	//back
	/*d*/ Packet.WriteD(lrhandId);	//lrhand
	/*d*/ Packet.WriteD(hairId);	//hair  
	/*d*/ Packet.WriteD(faceId);//face - interlude addon
	//PAPERDOLL_END

			UINT nAugmentation = pUser->GetAugmentationID();
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteD(nAugmentation);//Augmentation ID lhand
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteD(nAugmentation);//Augmentation ID lrhand
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
			Packet.WriteH(0x00);
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//p_atk
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//p_atk_speed
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//p_def
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//evasion
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//accuracy
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//critical_rate
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//m_atk
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//m_atk_speed
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//p_atk_speed
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//m_def
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//pvp_flag
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//karma
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//run_speed
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//walk_speed
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//swim_run_speed
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//swim_walk_speed
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//fly_run_speed
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//fly_walk_speed
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//fly_run_speed
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//fly_walk_speed
	/*f*/ Packet.WriteF(va_arg(tag, double));	//move_multipler
	/*f*/ Packet.WriteF(va_arg(tag, double));	//atk_speed_multipler

			double radius = va_arg(tag, double);
			double height = va_arg(tag, double);

			radius = ColRadius;
			height = ColHeight;

	/*f*/ Packet.WriteF(radius);	//collision_radius
	/*f*/ Packet.WriteF(height);	//collision_height

	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//hair_style
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//hair_color
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//face
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//builder_level

	/*S*/ //Packet.WriteS(va_arg(tag, PWCHAR));	//title
		PWCHAR wUserTitleOriginal = va_arg(tag, PWCHAR);

		if(td.territoryId[SHOW_HP_TITLE] != 0)
		{
			int nCurrent_hp = static_cast<int>((int)pUser->pSD->fHP);
			int nCurrent_cp = static_cast<int>((int)pUser->pSD->fCP);
			int total_life = nCurrent_hp + nCurrent_cp;

			wstring wUserTitleHP = L"CP/HP: ["  + Utils::IntToWString(total_life) + L"]";

			if(pUser->pED->tvtUser.status == TvT::UserFighting || pUser->pED->tvtUser.status == TvT::UserPreparing)
			{
				if(pUser->pED->tvtUser.flag)
					wUserTitleHP = L"[FLAG]";
			}
				const WCHAR * wUserTitle = wUserTitleHP.c_str();
			/* S */ Packet.WriteS(wUserTitle);	//title
		}
		else if( (pUser->pSD->activateOfflineShopTime > 0) && (pUser->pED->nofflinesellbuffprice > 0) ) //offline buff shop
		{
			const WCHAR * wUserTitle = pUser->pED->offlineselltitle.c_str();
			Packet.WriteS(wUserTitle);	//title
		}
		else
		{
			if(pUser->pED->tvtUser.status == TvT::UserFighting || pUser->pED->tvtUser.status == TvT::UserPreparing)
			{
				if(pUser->pED->tvtUser.flag)
				{
					wstring wUserTitleHP = L"[FLAG]";
					const WCHAR * wUserTitle = wUserTitleHP.c_str();
					/* S */ //Packet.WriteS(wUserTitle);	//title
					Packet.WriteS(wUserTitleOriginal);
				}
				else
				{
					/* S */ //Packet.WriteS(L"");	//title
					Packet.WriteS(wUserTitleOriginal);
				}
			}
			else
			{
				/* S */ Packet.WriteS(wUserTitleOriginal);	//title
			}
		}

	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//pledge_id
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//pledge_crest_id
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//ally_id

	/*c*/ Packet.WriteC(va_arg(tag, BYTE));		//mount_type
	/*c*/ Packet.WriteC(va_arg(tag, BYTE));		//private_store_mode
	/*c*/ Packet.WriteC(va_arg(tag, BYTE));		//dwarven_craft_mode
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//pk_count
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//pvp_count
	/*h*/ Packet.WriteH(va_arg(tag, WORD));		//recommendation_remaining
	/*h*/ Packet.WriteH(va_arg(tag, WORD));		//recommendation_received

	UINT classId = va_arg(tag, DWORD);
	/*d*/ Packet.WriteD(classId);	//class_id
	
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//unknown
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//max_cp
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//current_cp
	/*c*/ Packet.WriteC(va_arg(tag, BYTE));		//enchant_effect
	/*c*/ BYTE bTeam = va_arg(tag, BYTE);		//team_circle

			if(pUser->pSD->DuelInfo.DuelID && pUser->pSD->DuelInfo.Fighting)
				bTeam = pUser->pSD->DuelInfo.DuelTeam;

			if(pUser->pED->tvtUser.status == TvT::UserFighting || pUser->pED->tvtUser.status == TvT::UserPreparing)
				bTeam = pUser->pED->tvtUser.team;

			if(pUser->pED->inEventPvp > 0)
				bTeam = pUser->pED->inEventPvp;

			Packet.WriteC(bTeam); //1blue 2 red
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//pledge_large_crest_id
	/*c*/ Packet.WriteC(va_arg(tag, BYTE));		//is_nobless

	BYTE is_hero = va_arg(tag, BYTE);

	bool armaHeroAura = false;
	if (g_MinEnchantLevelAuraHero > 0)
	{
		CSharedItemData *pData = pUser->GetEquipedWeapon();
		if(pData)
		{
			CItem *pItem = pUser->inventory.GetItemBySID(pData->nObjectID);
			if(pItem->IsValid(VT_ITEMWEAPON))
			{
				if (pItem->pII->nCrystalType == 5 && pItem->pSID->nEnchantLevel >= g_MinEnchantLevelAuraHero)
				{
					is_hero = 1;	
					armaHeroAura = true;
				}
			}
		}
	}

	if(pUser->pSD->nHero == 2 && !armaHeroAura)
	/*c*/ Packet.WriteC(pUser->pED->customVerAuraHero);		//is_hero
	else if(armaHeroAura)
	/*c*/ Packet.WriteC(pUser->pED->customVerAuraHero);		//is_hero
	else
	/*c*/ Packet.WriteC(is_hero);		//is_hero


	/*c*/ Packet.WriteC(va_arg(tag, BYTE));		//is_fishing
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//fishing_x
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//fishing_y
	/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//fishing_z
		
			DWORD NickNameColor = va_arg(tag, DWORD);	//nickname_color
			if(pUser->pED->nicknameColor != 0)
			{
				NickNameColor = pUser->pED->nicknameColor;
			}
			if(pUser->pED->nameColorEx != 0)
			{
				NickNameColor = pUser->pED->nameColorEx;
			}
			if(pUser->pED->aioId > 0)
			{
				if(g_AIOSystem.IsEnabled())
				{
					NickNameColor = pUser->pED->aioNicknameColor;
				}
			}
			if(pTerritory)
			{
				if(DWORD Color = pTerritory->GetColor())
					NickNameColor = Color;
			}

			//red = 255 //green = 65280
			if(td.territoryId[FACTION_ZONE] != 0)
			{
				if(pUser->pED->nFactionID == 1)
				{
					NickNameColor = (DWORD)255; //Red
				}
				else if(pUser->pED->nFactionID == 2)
				{
					NickNameColor = (DWORD)65280; //Green
				}
			}

	/*d*/ Packet.WriteD(NickNameColor);
		va_end(tag);

		//New C5 Things cdddddd
		Packet.WriteC((BYTE)pUser->pSD->nMoveType);
		Packet.WriteD(pUser->GetPledgeClass());
		Packet.WriteD(pUser->GetPledgeType());
		if(g_PlayerCustomizer.IsEnabled())
		{
			Packet.WriteD(g_PlayerCustomizer.GetPvpTitleColor(pUser->pSD->nPvpCount));
		}else
		{
			if(td.territoryId[SHOW_HP_TITLE] != 0)
			{
				int nCurrent_hp = static_cast<int>((int)pUser->pSD->fHP);
				int nCurrent_cp = static_cast<int>((int)pUser->pSD->fCP);
				int total_life = nCurrent_hp + nCurrent_cp;

				int nMax_hp = static_cast<int>((int)pUser->pSD->MaxHP);
				int nMax_cp = static_cast<int>((int)pUser->pSD->MaxCP);
				int Maxtotal_life = nMax_hp + nMax_cp;

				int n50perhp = Maxtotal_life * 0.50;
				int n35perhp = Maxtotal_life * 0.35;

				DWORD titleColor = 0;

				if( (total_life <= n50perhp) && (total_life > n35perhp) )
				{
					titleColor = 33023; //Orange
				}
				else if( total_life <= n35perhp )
				{
					titleColor = 255; //Red
				}

				if( (pUser->pSD->activateOfflineShopTime > 0) && (pUser->pED->nofflinesellbuffprice > 0) ) //offline buff shop
				{
					titleColor = g_OfflineBuffer.GetOfflineBufferColor(); //Red
				}

				if(pUser->pED->tvtUser.status == TvT::UserFighting || pUser->pED->tvtUser.status == TvT::UserPreparing)
				{
					if(pUser->pED->tvtUser.flag)
					{
						titleColor = 65535; //Yellow
					}
				}

				Packet.WriteD(titleColor);

			}
			else
			{
				Packet.WriteD(0x0ECF9A2);
			}
		}

		Packet.WriteD(pUser->pED->cursedWeaponLevel);
		Packet.WriteD(pUser->GetPledgeReputation());
		
		//SendNewInfo
		pSocket->Send("b", Packet.GetSize(), Packet.GetBuff());
	}
}


void CPacketFix::MyTargetSelected(CSocket *pSocket, const char* format, ...)
{
	va_list va;
	va_start(va, format);
	//cdh -> cdhd
	BYTE opCode = va_arg(va, BYTE);
	DWORD targetId = va_arg(va, DWORD);
	WORD wColor = va_arg(va, WORD);
	va_end(va);
	
	pSocket->Send("cdhd", opCode, targetId, wColor, 0);
}