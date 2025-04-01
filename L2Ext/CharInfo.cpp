#include "StdAfx.h"
#include "CursedWeaponSystem.h"
#include "Packets.h"
#include "AIO.h"
#include "TerritoryData.h"
#include "VisualArmor.h"
#include "PlayerCustomizer.h"
#include "SubStack.h"
#include "Utils.h"
#include "OfflineBuffer.h"
#include "AccountDB.h"
#include "Hair2Slot.h"

extern UINT g_ClanLeaderTitleColor;
extern UINT g_ClanLeaderNicknameColor;
extern UINT g_GMTitleColor;
extern UINT g_GMNicknameColor;
extern UINT g_DefaultTitleColor;

extern INT32 g_MinEnchantLevelAuraHero;

extern User* g_CharInfoUser[16];

void CPacketFix::CharInfoFix(CUserSocket *pSocket, const char *format, ...)
{
	int race = 0;
	int clase = 0;
	int sex = 0;
	double ColRadius = 5;
	double ColHeight = 30;

	User *pUser = 0;
	UINT threadIndex = GetThreadIndex();
	if(threadIndex < 16)
	{
		pUser = g_CharInfoUser[threadIndex];
	}

	CPacket Packet;
	va_list tag;
	va_start(tag, format);
/* c */ Packet.WriteC(va_arg(tag, BYTE)); 
/* d */ Packet.WriteD(va_arg(tag, DWORD)); //X
/* d */ Packet.WriteD(va_arg(tag, DWORD)); //Y
/* d */ Packet.WriteD(va_arg(tag, DWORD)); //Z
		DWORD heading = va_arg(tag, DWORD);
/* d */ Packet.WriteD(heading); //Heading
/* d */	UINT nObjectID = va_arg(tag, DWORD); //ObjectID

		if(pUser == 0)
		{
			pUser = User::GetUserBySID(&nObjectID);
			if(!pUser->ValidUser())
			{
				return;
			}
		}

		TerritoryData& td = pUser->pSD->pExData->territoryData;

		Packet.WriteD(nObjectID); 

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
		if(pUser->pED->fakeRace != UINT_MAX)
		{
			Race = pUser->pED->fakeRace;
		}
		DWORD Sex = va_arg(tag, DWORD);
		if(pUser->pED->fakeSex != UINT_MAX)
		{
			Sex = pUser->pED->fakeSex;
		}

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



/* d */ Packet.WriteD(Race);	//race
/* d */ Packet.WriteD(Sex);	//sex

		if(g_SubStack.IsEnabled())
		{
			//get char index;
			UINT charIndex = UINT_MAX;
			for(UINT n=0;n<7;n++)
			{
				if(pUser->pSocket->characterDBID[n] == pUser->nDBID)
				{
					charIndex = n;
					break;
				}
			}
			if(charIndex != UINT_MAX && charIndex < 7)
			{
				if(pUser->pSocket->pED->baseClass[charIndex] != UINT_MAX)
				{
					BaseClass = pUser->pSocket->pED->baseClass[charIndex];
				}
			}
		}

/* d */ Packet.WriteD(BaseClass);

		INT32 dhairId = va_arg(tag, INT32);
		INT32 headId = va_arg(tag, INT32);
		INT32 rhandId = va_arg(tag, INT32);
		INT32 lhandId = va_arg(tag, INT32);
		INT32 glovesId = va_arg(tag, INT32);
		INT32 chestId = va_arg(tag, INT32);
		INT32 legsId = va_arg(tag, INT32);
		INT32 feetId = va_arg(tag, INT32);
		INT32 backId = va_arg(tag, INT32);
		INT32 lrhandId = va_arg(tag, INT32);
		INT32 hairId = va_arg(tag, INT32);
		INT32 faceId = 0;	//interlude addon - 0


		Hair2Slot::GetItemIDCharInfo(pUser, dhairId, hairId, faceId);

		if(g_VisualArmor.IsEnabled())
		{
			VisualArmorUser& vUser = pUser->pED->visualArmorUser;
			if(!pUser->olympiadUser.IsInside())
			{
				if(vUser.armorId > 0)
				{
					if(vUser.armorType == 0 || vUser.armorType == pUser->pSD->nArmorType)
					{
						if(vUser.chestSlotId > 0)
						{
							chestId = vUser.chestSlotId;
						}
						if(vUser.legsSlotId > 0)
						{
							legsId = vUser.legsSlotId;
						}
						if(vUser.glovesSlotId > 0)
						{
							glovesId = vUser.glovesSlotId;
						}
						if(vUser.feetSlotId > 0)
						{
							feetId = vUser.feetSlotId;
						}
						if(vUser.hairSlotId > 0 && hairId == 0)
						{
							hairId = vUser.hairSlotId;
						}
					}
				}
			}
		}
		if(pUser->pED->tvtUser.status == TvT::UserFighting || pUser->pED->tvtUser.status == TvT::UserPreparing)
		{
			if(pUser->pED->tvtUser.flag)
			{
				rhandId = 6718;
				lrhandId = 6718;
			}
		}
		if(pUser->pED->BlockAppeZoneId)
		{
			dhairId = 0;
			headId = 0;
			rhandId = 0;
			lhandId = 0;
			glovesId = 0;
			chestId = 0;
			legsId = 0;
			feetId = 0;
			backId = 0;
			lrhandId = 0;
			hairId = 0;
			faceId = 0;
		}

		if(pUser->pED->m_CtfUserFlag>0)
		{
			lrhandId = pUser->pED->m_CtfUserFlag;
			rhandId = 0;
			lhandId = 0;
		}

/* d */ Packet.WriteD(dhairId);	//dhair
/* d */ Packet.WriteD(headId);	//head
/* d */ Packet.WriteD(rhandId);	//rhand
/* d */ Packet.WriteD(lhandId);	//lhand
/* d */ Packet.WriteD(glovesId);	//gloves
/* d */ Packet.WriteD(chestId);	//chest
/* d */ Packet.WriteD(legsId);	//legs
/* d */ Packet.WriteD(feetId);	//feet
/* d */ Packet.WriteD(backId);	//back
/* d */ Packet.WriteD(lrhandId);	//lrhand
/* d */ Packet.WriteD(hairId);	//hair
/* d */ Packet.WriteD(faceId); //Face slot

		int nAugmentation = pUser->GetAugmentationID();
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* d */ Packet.WriteD(nAugmentation); //Augmentation id
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* d */ Packet.WriteD(nAugmentation); //Augmentation ID
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* f */ Packet.WriteF(va_arg(tag, double));
/* f */ Packet.WriteF(va_arg(tag, double));

		double radius = va_arg(tag, double);
		double height = va_arg(tag, double);
		
		if(pUser->pED->fakeRace != UINT_MAX || pUser->pED->fakeSex != UINT_MAX)
		{
			DWORD Magic = 0;
			if(CCategoryDataDB::IsInCategory(BaseClass, CCategoryDataDB::MAGE_GROUP))
				Magic = 1;
			radius = g_World.GetRadius(Race, Sex, Magic);
			height = g_World.GetHeight(Race, Sex, Magic);
		}
		else
		{
			radius = ColRadius;
			height = ColHeight;
		}
/* f */ Packet.WriteF(radius);	//collision_radius
/* f */ Packet.WriteF(height);	//collision_height

/* d */ Packet.WriteD(va_arg(tag, DWORD));	//hair_style
/* d */ Packet.WriteD(va_arg(tag, DWORD));	//hair_color
/* d */ Packet.WriteD(va_arg(tag, DWORD));	//face
		
		if(pTerritory && pTerritory->IsHidePledge())
		{
				va_arg(tag, PWCHAR);
		/* S */ Packet.WriteS(L"");	//title
				va_arg(tag, DWORD);
		/* d */ Packet.WriteD(0);	//pledge_id
				va_arg(tag, DWORD);
		/* d */ Packet.WriteD(0);	//pledge_crest_id
				va_arg(tag, DWORD);
		/* d */ Packet.WriteD(0);	//ally_id
				va_arg(tag, DWORD);
		/* d */ Packet.WriteD(0);	//ally_crest_id
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
		
		/* d */ Packet.WriteD(va_arg(tag, DWORD));	//pledge_id
		/* d */ Packet.WriteD(va_arg(tag, DWORD));	//pledge_crest_id
		/* d */ Packet.WriteD(va_arg(tag, DWORD));	//ally_id
		/* d */ Packet.WriteD(va_arg(tag, DWORD));	//ally_crest_id
		}


		// 0x40 leader rights
		// siege flags: attacker - 0x180 sword over name, defender - 0x80 shield, 0xC0 crown (|leader), 0x1C0 flag (|leader)
		DWORD _relation = va_arg(tag, DWORD);

/* d */ Packet.WriteD(_relation);	//unknown
/* c */ Packet.WriteC(va_arg(tag, BYTE)); //is sit
/* c */ Packet.WriteC(va_arg(tag, BYTE)); //is run
/* c */ Packet.WriteC(va_arg(tag, BYTE)); //is combat
/* c */ Packet.WriteC(va_arg(tag, BYTE)); //is alike dead
/* c */ Packet.WriteC(va_arg(tag, BYTE)); //hide
/* c */ Packet.WriteC(va_arg(tag, BYTE)); //mount type

		BYTE isprivatestore = va_arg(tag, BYTE);
		
		if(g_OfflineBuffer.IsOfflineBuffer(pUser))
			isprivatestore = 0x01;

/* c */ Packet.WriteC(isprivatestore); //is private store

/* h */ Packet.WriteH(va_arg(tag, WORD));		//Cubics
/*BuffSize*/ DWORD dBuffSize = va_arg(tag, DWORD);	//cubic_buff_size
/* b */ Packet.WriteB(dBuffSize, va_arg(tag, PUCHAR));	//cubic_buff


/* c */ Packet.WriteC(va_arg(tag, BYTE));		//isInPartyMatchRoom
/* d */ DWORD AbnormalVisualEffect = va_arg(tag, DWORD);

		if(pUser->pSD->pExData->SkillMod.semiInvisible)
		{
			AbnormalVisualEffect |= 0x100000;	//stealth
		}
		if(pUser->pSD->activateOfflineShopTime)
		{
//			if(pUser->pSD->nStoreMode > 0)
//				AbnormalVisualEffect |= 0x000080; //Sleep
		}
		if(pUser->pED->spawnProtection == 2)
		{
			AbnormalVisualEffect |= 0x200000;
		}
		Packet.WriteD(AbnormalVisualEffect);
/* c */ Packet.WriteC(va_arg(tag, BYTE));
/* h */ Packet.WriteH(va_arg(tag, WORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* c */ Packet.WriteC(va_arg(tag, BYTE));
/* c */ BYTE bTeam = va_arg(tag, BYTE);

		if(pUser->pSD->DuelInfo.DuelID && pUser->pSD->DuelInfo.Fighting)
		{
			bTeam = pUser->pSD->DuelInfo.DuelTeam;
		}
		if(pUser->pED->tvtUser.status == TvT::UserFighting || pUser->pED->tvtUser.status == TvT::UserPreparing)
		{
				bTeam = pUser->pED->tvtUser.team;
		}
		if(pUser->pED->inEventPvp > 0)
		{
				bTeam = pUser->pED->inEventPvp;
		}

		Packet.WriteC(bTeam); //Team?
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* c */ Packet.WriteC(va_arg(tag, BYTE));

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


/* c */ Packet.WriteC(va_arg(tag, BYTE));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));

		DWORD NickNameColor = va_arg(tag, DWORD);

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

/* d */ Packet.WriteD(NickNameColor);

	va_end(tag);
//C5 + IL things
	Packet.WriteD(heading);
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
	

	if(td.territoryId[NOCHARSHOWZONE] != 0)
	{

	}
	else
	{

		int InstanceId_Other = 0;
		if(CUserSocket *pUS = pSocket->CastUserSocket())
		{
			if(User *pUserA = pSocket->CastUserSocket()->GetUser())
			{
				if(pUserA->ValidUser())
				{
					InstanceId_Other = pUserA->pED->InstanceId;
				}
			}
		}

		if (pUser->pED->InstanceId == InstanceId_Other)
			pSocket->Send("b", Packet.GetSize(), Packet.GetBuff());
	}

}

void CPacketFix::CharInfoBCFix(INT64 dwAddr, int nObjID, int nRange, FVector *pLocation, const char *format, ...)
{
	int race = 0;
	int clase = 0;
	int sex = 0;
	double ColRadius = 5;
	double ColHeight = 30;

	User *pUser = 0;
	UINT threadIndex = GetThreadIndex();
	if(threadIndex < 16)
	{
		pUser = g_CharInfoUser[threadIndex];
	}

	CPacket Packet;
	va_list tag;
	va_start(tag, format);
/* c */ Packet.WriteC(va_arg(tag, BYTE)); 
/* d */ Packet.WriteD(va_arg(tag, DWORD)); //X
/* d */ Packet.WriteD(va_arg(tag, DWORD)); //Y
/* d */ Packet.WriteD(va_arg(tag, DWORD)); //Z
		DWORD heading = va_arg(tag, DWORD);
/* d */ Packet.WriteD(heading); //Heading
/* d */	UINT nObjectID = va_arg(tag, DWORD); //ObjectID

		if(pUser == 0)
		{
			pUser = User::GetUserBySID(&nObjectID);
			if(!pUser->ValidUser())
			{
				return;
			}
		}

		TerritoryData& td = pUser->pSD->pExData->territoryData;

		Packet.WriteD(nObjectID); 

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
		if(pUser->pED->fakeRace != UINT_MAX)
		{
			Race = pUser->pED->fakeRace;
		}
		DWORD Sex = va_arg(tag, DWORD);
		if(pUser->pED->fakeSex != UINT_MAX)
		{
			Sex = pUser->pED->fakeSex;
		}

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


/* d */ Packet.WriteD(Race);	//race
/* d */ Packet.WriteD(Sex);	//sex

		if(g_SubStack.IsEnabled())
		{
			//get char index;
			UINT charIndex = UINT_MAX;
			for(UINT n=0;n<7;n++)
			{
				if(pUser->pSocket->characterDBID[n] == pUser->nDBID)
				{
					charIndex = n;
					break;
				}
			}
			if(charIndex != UINT_MAX && charIndex < 7)
			{
				if(pUser->pSocket->pED->baseClass[charIndex] != UINT_MAX)
				{
					BaseClass = pUser->pSocket->pED->baseClass[charIndex];
				}
			}
		}
/* d */ Packet.WriteD(BaseClass);

		INT32 dhairId = va_arg(tag, INT32);
		INT32 headId = va_arg(tag, INT32);
		INT32 rhandId = va_arg(tag, INT32);
		INT32 lhandId = va_arg(tag, INT32);
		INT32 glovesId = va_arg(tag, INT32);
		INT32 chestId = va_arg(tag, INT32);
		INT32 legsId = va_arg(tag, INT32);
		INT32 feetId = va_arg(tag, INT32);
		INT32 backId = va_arg(tag, INT32);
		INT32 lrhandId = va_arg(tag, INT32);
		INT32 hairId = va_arg(tag, INT32);
		INT32 faceId = 0;	//interlude addon

		Hair2Slot::GetItemIDCharInfo(pUser, dhairId, hairId, faceId);

		if(g_VisualArmor.IsEnabled())
		{
			VisualArmorUser& vUser = pUser->pED->visualArmorUser;
			if(vUser.armorId > 0)
			{
				if(!pUser->olympiadUser.IsInside())
				{
					if(vUser.armorType == 0 || vUser.armorType == pUser->pSD->nArmorType)
					{
						if(vUser.chestSlotId > 0)
						{
							chestId = vUser.chestSlotId;
						}
						if(vUser.legsSlotId > 0)
						{
							legsId = vUser.legsSlotId;
						}
						if(vUser.glovesSlotId > 0)
						{
							glovesId = vUser.glovesSlotId;
						}
						if(vUser.feetSlotId > 0)
						{
							feetId = vUser.feetSlotId;
						}
						if(vUser.hairSlotId > 0 && hairId == 0)
						{
							hairId = vUser.hairSlotId;
						}
					}
				}
			}
		}
		if(pUser->pED->tvtUser.status == TvT::UserFighting || pUser->pED->tvtUser.status == TvT::UserPreparing)
		{
			if(pUser->pED->tvtUser.flag)
			{
				rhandId = 6718;
				lrhandId = 6718;
			}
		}
		if(pUser->pED->BlockAppeZoneId)
		{
			dhairId = 0;
			headId = 0;
			rhandId = 0;
			lhandId = 0;
			glovesId = 0;
			chestId = 0;
			legsId = 0;
			feetId = 0;
			backId = 0;
			lrhandId = 0;
			hairId = 0;
			faceId = 0;
		}

		if(pUser->pED->m_CtfUserFlag>0)
		{
			lrhandId = pUser->pED->m_CtfUserFlag;
			rhandId = 0;
			lhandId = 0;
		}


/* d */ Packet.WriteD(dhairId);	//dhair
/* d */ Packet.WriteD(headId);	//head
/* d */ Packet.WriteD(rhandId);	//rhand
/* d */ Packet.WriteD(lhandId);	//lhand
/* d */ Packet.WriteD(glovesId);	//gloves
/* d */ Packet.WriteD(chestId);	//chest
/* d */ Packet.WriteD(legsId);	//legs
/* d */ Packet.WriteD(feetId);	//feet
/* d */ Packet.WriteD(backId);	//back
/* d */ Packet.WriteD(lrhandId);	//lrhand
/* d */ Packet.WriteD(hairId);	//hair
/* d */ Packet.WriteD(faceId); //Face slot - faceId

		UINT nAugmentation = pUser->GetAugmentationID();
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* d */ Packet.WriteD(nAugmentation); //Augmentation id
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* d */ Packet.WriteD(nAugmentation); //Augmentation ID
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* h */ Packet.WriteH(0);
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* f */ Packet.WriteF(va_arg(tag, double));
/* f */ Packet.WriteF(va_arg(tag, double));

		double radius = va_arg(tag, double);
		double height = va_arg(tag, double);
		
		if(pUser->pED->fakeRace != UINT_MAX || pUser->pED->fakeSex != UINT_MAX)
		{
			DWORD Magic = 0;
			if(CCategoryDataDB::IsInCategory(BaseClass, CCategoryDataDB::MAGE_GROUP))
				Magic = 1;
			radius = g_World.GetRadius(Race, Sex, Magic);
			height = g_World.GetHeight(Race, Sex, Magic);
		}
		else
		{
			radius = ColRadius;
			height = ColHeight;
		}
/* f */ Packet.WriteF(radius);	//collision_radius
/* f */ Packet.WriteF(height);	//collision_height

/* d */ Packet.WriteD(va_arg(tag, DWORD));	//hair_style
/* d */ Packet.WriteD(va_arg(tag, DWORD));	//hair_color
/* d */ Packet.WriteD(va_arg(tag, DWORD));	//face
		
		if(pTerritory && pTerritory->IsHidePledge())
		{
				va_arg(tag, PWCHAR);
		/* S */ Packet.WriteS(L"");	//title
				va_arg(tag, DWORD);
		/* d */ Packet.WriteD(0);	//pledge_id
				va_arg(tag, DWORD);
		/* d */ Packet.WriteD(0);	//pledge_crest_id
				va_arg(tag, DWORD);
		/* d */ Packet.WriteD(0);	//ally_id
				va_arg(tag, DWORD);
		/* d */ Packet.WriteD(0);	//ally_crest_id
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
		/* d */ Packet.WriteD(va_arg(tag, DWORD));	//pledge_id
		/* d */ Packet.WriteD(va_arg(tag, DWORD));	//pledge_crest_id
		/* d */ Packet.WriteD(va_arg(tag, DWORD));	//ally_id
		/* d */ Packet.WriteD(va_arg(tag, DWORD));	//ally_crest_id
		}

		// 0x40 leader rights
		// siege flags: attacker - 0x180 sword over name, defender - 0x80 shield, 0xC0 crown (|leader), 0x1C0 flag (|leader)
		DWORD _relation = va_arg(tag, DWORD);

/* d */ Packet.WriteD(_relation);	//unknown
/* c */ Packet.WriteC(va_arg(tag, BYTE));
/* c */ Packet.WriteC(va_arg(tag, BYTE));
/* c */ Packet.WriteC(va_arg(tag, BYTE));
/* c */ Packet.WriteC(va_arg(tag, BYTE));
/* c */ Packet.WriteC(va_arg(tag, BYTE));
/* c */ Packet.WriteC(va_arg(tag, BYTE));

		BYTE isprivatestore = va_arg(tag, BYTE);
		
		if(g_OfflineBuffer.IsOfflineBuffer(pUser))
			isprivatestore = 0x01;

/* c */ Packet.WriteC(isprivatestore);
/* h */ Packet.WriteH(va_arg(tag, WORD));
/*BuffSize*/ DWORD dBuffSize = va_arg(tag, DWORD);
/* b */ Packet.WriteB(dBuffSize, va_arg(tag, PUCHAR));
/* c */ Packet.WriteC(va_arg(tag, BYTE));
/* d */ DWORD AbnormalVisualEffect = va_arg(tag, DWORD);

		if(pUser->pSD->pExData->SkillMod.semiInvisible)
		{
			AbnormalVisualEffect |= 0x100000;	//stealth
		}
		if(pUser->pSD->activateOfflineShopTime)
		{
//			if(pUser->pSD->nStoreMode > 0)
//				AbnormalVisualEffect |= 0x000080; //Sleep
		}
		if(pUser->pED->spawnProtection == 2)
		{
			AbnormalVisualEffect |= 0x200000;
		}
		Packet.WriteD(AbnormalVisualEffect);
/* c */ Packet.WriteC(va_arg(tag, BYTE));
/* h */ Packet.WriteH(va_arg(tag, WORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* c */ Packet.WriteC(va_arg(tag, BYTE));
/* c */ BYTE bTeam = va_arg(tag, BYTE);

		if(pUser->pSD->DuelInfo.DuelID && pUser->pSD->DuelInfo.Fighting)
		{
			bTeam = pUser->pSD->DuelInfo.DuelTeam;
		}
		if(pUser->pED->tvtUser.status == TvT::UserFighting || pUser->pED->tvtUser.status == TvT::UserPreparing)
		{
				bTeam = pUser->pED->tvtUser.team;
		}
		if(pUser->pED->inEventPvp > 0)
		{
				bTeam = pUser->pED->inEventPvp;
		}

		Packet.WriteC(bTeam); //Team?
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* c */ Packet.WriteC(va_arg(tag, BYTE));

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


/* c */ Packet.WriteC(va_arg(tag, BYTE));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));
/* d */ Packet.WriteD(va_arg(tag, DWORD));

		DWORD NickNameColor = va_arg(tag, DWORD);
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
			{
				NickNameColor = Color;
			}
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

/* d */ Packet.WriteD(NickNameColor);

	va_end(tag);
//C5 + IL things
	Packet.WriteD(heading);
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

	if(td.territoryId[NOCHARSHOWZONE] != 0)
	{

	}
	else
	{
		BroadcastToNeighborExceptSelf(nObjID, nRange, pLocation, (int)Packet.GetSize(), Packet.GetBuff());
	}
}