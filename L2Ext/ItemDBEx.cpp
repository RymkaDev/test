#include "StdAfx.h"

map<INT32, DWORD> g_ItemNicknameColor;
map<INT32, DWORD> g_ItemNicknameColor2;
map<INT32, DWORD> g_ItemTitleColor;
map<INT32, ItemExSkillList> g_ItemExSkillList;

CItemDBEx::CItemDBEx()
{

}

CItemDBEx::~CItemDBEx()
{

}

void CItemDBEx::Init()
{
	Clear();
	ReadData();
	LoadItemName();
	LoadItemGrp();
	ReadDataItemPch();
	ReadDataItemData();
}

void CItemDBEx::Clear()
{
	Lock();
	g_ItemNicknameColor.clear();
	g_ItemNicknameColor2.clear();
	g_ItemTitleColor.clear();
	g_ItemExSkillList.clear();
	m_ItemName.clear();
	m_ItemSA.clear();
	m_ItemIcon.clear();
	m_LifeTime.clear();
	m_ItemPch.clear();
	m_Items.clear();
	for(map<int, CItemDataEx*>::iterator Iter = mData.begin();Iter!=mData.end();Iter++)
	{
		if(Iter->second)
			delete Iter->second;
	}
	mData.clear();
	Unlock();
}

void CItemDBEx::LoadItemGrp()
{
	guard;
	wstringstream file(ReadFileW(g_ChangeFolders.ItemGrp_txt));
	wstring line;
	while(getline(file, line))
	{
		if(line.find(L"\\") == 0)
		{
			continue;
		}

		//2	17	0	3	8	4	0	dropitems.drop_quiver_m00			dropitemstex.drop_quiver_t00			icon.etc_wooden_quiver_i00					-1	6	13	0	0	1	LineageWeapons.wooden_arrow_m00_et	1	LineageWeaponsTex.wooden_arrow_t00_et	ItemSound.itemdrop_arrow		2	2	0
		vector<wstring> parts = Parser::Split(line, L"\t");
		if(parts.size() > 13)
		{
			int itemId = _wtoi(parts[1].c_str());
			if(itemId > 0)
			{
				m_ItemIcon.insert(pair<INT32, wstring>(itemId, parts[13]));
			}
		}
	}

	g_Log.Add(CLog::Blue, "[%s] Loaded [%d] items.", __FUNCTION__, m_ItemIcon.size());

	unguard;
}

void CItemDBEx::LoadItemName()
{
	guard;
	wstringstream file(ReadFileW(g_ChangeFolders.ItemName_txt));
	wstring line;
	while(getline(file, line))
	{
		if(line.find(L"\\") == 0)
		{
			continue;
		}

		//687	Darin's Letter		a,The love letter that Darin has written to Roxxy. Darin has asked you to deliver this letter to Gatekeeper Roxxy.\0	-1	a,	a,	a,	a,	0	0	0	a,

		vector<wstring> parts = Parser::Split(line, L"\t");
		if(parts.size() > 2)
		{
			int itemId = _wtoi(parts[0].c_str());
			if(itemId > 0)
			{
				m_ItemName.insert(pair<INT32, wstring>(itemId, parts[1]));
				m_ItemSA.insert(pair<INT32, wstring>(itemId, parts[2]));
			}
		}
	}
	g_Log.Add(CLog::Blue, "[%s] Loaded [%d] items.", __FUNCTION__, m_ItemName.size());
	unguard;
}

wstring CItemDBEx::GetItemName(int itemId)
{
	map<INT32, wstring>::iterator iter = m_ItemName.find(itemId);
	if(iter != m_ItemName.end())
	{
		return iter->second;
	}
	return L"NoName";
}

wstring CItemDBEx::GetItemSA(int itemId)
{
	map<INT32, wstring>::iterator it = m_ItemSA.find(itemId);
	if(it != m_ItemSA.end())
	{
		return it->second;
	}
	return L"";
}

wstring CItemDBEx::GetItemIcon(int itemId)
{
	map<INT32, wstring>::iterator it = m_ItemIcon.find(itemId);
	if(it != m_ItemIcon.end())
	{
		return it->second;
	}
	return L"";
}

void CItemDBEx::ReadData()
{
	ifstream file(g_ChangeFolders.ItemDataEx_txt.c_str());
	if(file)
	{
		Lock();
		string sLine;
		while(getline(file, sLine))
		{
			if(sLine[0] == '/' || sLine[0] == ';')
			{
				continue;
			}
			if(sLine.find("begin") == 0)
			{
				int ItemID = CParser::GetValueInt(sLine, "item_id");
				UINT lifeTime = CParser::GetValueInt(sLine, "life_time");
				int ShadowTime = CParser::GetValueInt(sLine, "shadow_time");
				int ReuseGroup = CParser::GetValueInt(sLine, "reuse_group", -1);
				int maxStackableLevel = CParser::GetValueInt(sLine, "max_stackable_level", 0);
				int stackType = Parser::ParseOptionInt(sLine, "stack_type", 0);
				DWORD nicknameColor = CParser::GetValueInt(sLine, "nickname_color", 0);
				DWORD nicknameColor2 = CParser::GetValueInt(sLine, "nicknamecolor2", 0);
				DWORD titleColor = CParser::GetValueInt(sLine, "title_color", 0);
				string skillList = CParser::GetValueString(sLine, "skill_list");
				if(skillList.size() > 3)
				{
					ItemExSkillList iesl;

					skillList = CParser::Replace(skillList, '{', ' ');
					skillList = CParser::Replace(skillList, '}', ' ');
					skillList = CParser::Replace(skillList, ';', ' ');
					wstring skillListW = StringToWString(skillList);
					wstringstream nameStream;
					nameStream << skillListW;
					wstring skillName;
					while(nameStream >> skillName)
					{
						int skillId = 0, level = 0;
						g_SkillDB.GetSkillIdLevelByName((PWCHAR)skillName.c_str(), &skillId, &level);
						if(skillId > 0 && level > 0)
						{
							CSkillKey key(skillId, level);
							iesl.m_Skills.push_back(key);
						}
					}
					if(iesl.m_Skills.size() > 0)
					{
						iesl.m_maxStackableLevel = maxStackableLevel;
						iesl.m_stackType = stackType;
						g_ItemExSkillList.insert(pair<INT32, ItemExSkillList>(ItemID, iesl));
					}
				}
				if(ItemID)
				{
					CItemDataEx *pData = new CItemDataEx();
					if(pData)
					{
						if(lifeTime > 0)
						{
							m_LifeTime[ItemID] = lifeTime;
						}
						if(nicknameColor != 0)
						{
							g_ItemNicknameColor.insert(pair<INT32, DWORD>(ItemID, nicknameColor));
						}
						if(nicknameColor2 != 0)
						{
							g_ItemNicknameColor2.insert(pair<INT32, DWORD>(ItemID, nicknameColor2));
						}
						if(titleColor != 0)
						{
							g_ItemTitleColor.insert(pair<INT32, DWORD>(ItemID, titleColor));
						}
						pData->Set(ItemID, ShadowTime, ReuseGroup);
						mData.insert(pair<int, CItemDataEx*>(ItemID, pData));
					}else
						g_Log.Add(CLog::Error, "[%s] Cannot allocate memory for CItemDataEx!",__FUNCTION__);
				}

			}
		}
		Unlock();
		g_Log.Add(CLog::Blue, "[%s] Done. [%d] Items in database and [%d] item with skills.", __FUNCTION__, mData.size(), g_ItemExSkillList.size());
	}else
		g_Log.Add(CLog::Error, "[%s] missing file [..\\Script\\ItemDataEx.txt]!", __FUNCTION__);
}

CItemDataEx* CItemDBEx::GetItemDataEx(int item_id)
{
	CItemDataEx *pData = NULL;
	map<int, CItemDataEx*>::iterator Iter = mData.find(item_id);
	if(Iter!=mData.end())
		pData = Iter->second;
	return pData;
}

UINT CItemDBEx::GetLifeTime(int itemId)
{
	guard;
	UINT ot = 0;
	map<INT32, UINT>::iterator it = m_LifeTime.find(itemId);
	if(it!=m_LifeTime.end())
	{
		ot = it->second;
	}
	unguard;
	return ot;
}

/* New Parser for Getting Items Information for Auction */

void CItemDBEx::ReadDataItemPch()
{
	//[small_sword] = 1
	wstring wData = ReadFileW(g_ChangeFolders.item_pch_txt);
	wstringstream wsstr;
	wsstr << wData;
	wstring wLine;
	int ItemsLoaded = 0;
	while(getline(wsstr, wLine))
	{
		if(wLine.find(L"//") == 0)
			continue;

		wstringstream itemData;
		wstring lineData = Parser::Replace(wLine, L'=', L' ');
		itemData << lineData;
		wstring wName;
		UINT ItemID = 0;
		itemData >> wName >> ItemID;

		if(ItemID > 0)
		{
			m_ItemPch.insert(pair<INT32, wstring>(ItemID, wName));
			ItemsLoaded++;
		}
	}
	g_Log.Add(CLog::Blue, "[%s] Loaded [%d] items from Item_Pch.", __FUNCTION__, ItemsLoaded);
}

void CItemDBEx::ReadDataItemData()
{
	//load npcdata
	wstringstream itemDataStream(ReadFileW(g_ChangeFolders.ItemData_txt));
	wstring line;
	UINT lineCounter = 0;
	while(getline(itemDataStream, line))
	{
		if(line.find(L"//") == 0)
			continue;

		//item_begin	weapon	1	[small_sword]	item_type=weapon	slot_bit_type={rhand}	armor_type=none	etcitem_type=none	recipe_id=0	blessed=0	weight=1600	default_action=action_equip	consume_type=consume_type_normal	initial_count=1	maximum_count=1	soulshot_count=1	spiritshot_count=1	reduced_soulshot={}	reduced_spiritshot={}	reduced_mp_consume={}	immediate_effect=1	price=0	default_price=8	item_skill=[none]	critical_attack_skill=[none]	attack_skill=[none]	magic_skill=[none]	item_skill_enchanted_four=[none]	material_type=steel	crystal_type=none	crystal_count=0	is_trade=1	is_drop=1	is_destruct=1	physical_damage=8	random_damage=10	weapon_type=sword	can_penetrate=0	critical=8	hit_modify=0	avoid_modify=0	dual_fhit_rate=0	shield_defense=0	shield_defense_rate=0	attack_range=40	damage_range={0;0;40;120}	attack_speed=379	reuse_delay=0	mp_consume=0	magical_damage=6	durability=95	damaged=0	physical_defense=0	magical_defense=0	mp_bonus=0	category={}	enchanted=0	html=[item_default.htm]	equip_pet={0}	magic_weapon=0	enchant_enable=0	can_equip_sex=-1	can_equip_race={}	can_equip_change_class=-1	can_equip_class={}	can_equip_agit=-1	can_equip_castle=-1	can_equip_castle_num={}	can_equip_clan_leader=-1	can_equip_clan_level=-1	can_equip_hero=-1	can_equip_nobless=-1	can_equip_chaotic=-1	item_end
		if(line.find(L"item_begin") == 0)
		{
			CItemInformation *pInfo = new CItemInformation();
			wstringstream dataStream(line);
			wstring temp;
			INT32 id = 0;
			wstring name;
			if(dataStream >> temp >> temp >> id >> name)
			{
				line = Utils::ReplaceString(line, L"{", L"", true);
				line = Utils::ReplaceString(line, L"}", L"", true);

				name = Utils::ReplaceString(name, L"[", L"", true);
				name = Utils::ReplaceString(name, L"]", L"", true);
				pInfo->id = id;
				pInfo->name = name;
				pInfo->clientname = GetItemName(id);

				//g_Log.Add(CLog::Blue, "[%s] html[%S]!", __FUNCTION__, GetItemName(id).c_str());

				//Weapon - 0, Armor - 1, Accessary - 2, Questitem - 3, Asset - 4, etcitemtype - 5
				wstring item_type = Parser::ParseOptionString(line, L"item_type");
				if(!wcscmp(item_type.c_str(), L"weapon"))
					pInfo->itemtype = ItemTypeWeapon;
				else if(!wcscmp(item_type.c_str(), L"accessary"))
					pInfo->itemtype = ItemTypeAccessory;
				else if(!wcscmp(item_type.c_str(), L"armor"))
					pInfo->itemtype = ItemTypeArmor;
				else if(!wcscmp(item_type.c_str(), L"asset"))
					pInfo->itemtype = ItemTypeAsset;
				else if(!wcscmp(item_type.c_str(), L"questitem"))
					pInfo->itemtype = ItemTypeQuest;
				else //(!wcscmp(item_type, L"etcitem"))
					pInfo->itemtype = ItemTypeEtc;

				wstring slot_type = Parser::ParseOptionString(line, L"slot_bit_type");
				//slot_type = Parser::Replace(slot_type, L'{', L'');
				//slot_type = Parser::Replace(slot_type, L'}', L'');

				if(!wcscmp(slot_type.c_str(), L"rhand"))
					pInfo->slot = SlotRightHand;
				else if(!wcscmp(slot_type.c_str(), L"lrhand"))
					pInfo->slot = SlotRightLeftHand;
				else if(!wcscmp(slot_type.c_str(), L"lhand"))
					pInfo->slot = SlotLeftHand;
				else if(!wcscmp(slot_type.c_str(), L"chest"))
					pInfo->slot = SlotChest;
				else if(!wcscmp(slot_type.c_str(), L"legs"))
					pInfo->slot = SlotLegs;
				else if(!wcscmp(slot_type.c_str(), L"feet"))
					pInfo->slot = SlotFeet;
				else if(!wcscmp(slot_type.c_str(), L"head"))
					pInfo->slot = SlotHead;
				else if(!wcscmp(slot_type.c_str(), L"gloves"))
					pInfo->slot = SlotGloves;
				else if(!wcscmp(slot_type.c_str(), L"back"))
					pInfo->slot = SlotBack;
				else if(!wcscmp(slot_type.c_str(), L"underwear"))
					pInfo->slot = SlotUnderwear;
				else if(!wcscmp(slot_type.c_str(), L"onepiece"))
					pInfo->slot = SlotOnePiece;
				else if(!wcscmp(slot_type.c_str(), L"rear;lear"))
					pInfo->slot = SlotRightEar;
				else if(!wcscmp(slot_type.c_str(), L"rfinger;lfinger"))
					pInfo->slot = SlotRightFinger;
				else if(!wcscmp(slot_type.c_str(), L"neck"))
					pInfo->slot = SlotNeck;
				else if(!wcscmp(slot_type.c_str(), L"hair"))
					pInfo->slot = SlotHair;
				else //if(!wcscmp(slot_type, L"none"))
					pInfo->slot = SlotNone;

				//g_Log.Add(CLog::Blue, "[%s] html[%S]!", __FUNCTION__, slot_type.c_str());

				wstring crystal_type = Parser::ParseOptionString(line, L"crystal_type");
				if(!wcscmp(crystal_type.c_str(), L"d"))
					pInfo->grade = CrystalD;
				else if(!wcscmp(crystal_type.c_str(), L"c"))
					pInfo->grade = CrystalC;
				else if(!wcscmp(crystal_type.c_str(), L"b"))
					pInfo->grade = CrystalB;
				else if(!wcscmp(crystal_type.c_str(), L"a"))
					pInfo->grade = CrystalA;
				else if(!wcscmp(crystal_type.c_str(), L"s"))
					pInfo->grade = CrystalS;
				else //if(!wcscmp(crystal_type, L"none"))
					pInfo->grade = CrystalNone;

				//g_Log.Add(CLog::Blue, "[%s] html[%S]!", __FUNCTION__, crystal_type.c_str());

				wstring etcitemtype = Parser::ParseOptionString(line, L"etcitem_type");

				if(!wcscmp(etcitemtype.c_str(), L"arrow"))
					pInfo->etcitemtype = EtcItemArrow;
				else if(!wcscmp(etcitemtype.c_str(), L"potion"))
					pInfo->etcitemtype = EtcItemPotion;
				else if(!wcscmp(etcitemtype.c_str(), L"scrl_enchant_wp"))
					pInfo->etcitemtype = EtcItemScrollEnchantWeapon;
				else if(!wcscmp(etcitemtype.c_str(), L"scrl_enchant_am"))
					pInfo->etcitemtype = EtcItemScrollEnchantArmor;
				else if(!wcscmp(etcitemtype.c_str(), L"scroll"))
					pInfo->etcitemtype = EtcItemScroll;
				else if(!wcscmp(etcitemtype.c_str(), L"recipe"))
					pInfo->etcitemtype = EtcItemRecipe;
				else if(!wcscmp(etcitemtype.c_str(), L"material"))
					pInfo->etcitemtype = EtcItemMaterial;
				else if(!wcscmp(etcitemtype.c_str(), L"pet_collar"))
					pInfo->etcitemtype = EtcItemPetCollar;
				else if(!wcscmp(etcitemtype.c_str(), L"castle_guard"))
					pInfo->etcitemtype = EtcItemCastleGuard;
				else if(!wcscmp(etcitemtype.c_str(), L"lotto"))
					pInfo->etcitemtype = EtcItemLotto;
				else if(!wcscmp(etcitemtype.c_str(), L"race_ticket"))
					pInfo->etcitemtype = EtcItemRaceTicket;
				else if(!wcscmp(etcitemtype.c_str(), L"dye"))
					pInfo->etcitemtype = EtcItemDye;
				else if(!wcscmp(etcitemtype.c_str(), L"seed"))
					pInfo->etcitemtype = EtcItemSeed;
				else if(!wcscmp(etcitemtype.c_str(), L"crop"))
					pInfo->etcitemtype = EtcItemCrop;
				else if(!wcscmp(etcitemtype.c_str(), L"maturecrop"))
					pInfo->etcitemtype = EtcItemMatureCrop;
				else if(!wcscmp(etcitemtype.c_str(), L"harvest"))
					pInfo->etcitemtype = EtcItemHarvest;
				else if(!wcscmp(etcitemtype.c_str(), L"seed2"))
					pInfo->etcitemtype = EtcItemSeed2;
				else if(!wcscmp(etcitemtype.c_str(), L"ticket_of_lord"))
					pInfo->etcitemtype = EtcItemTicketOfLord;
				else if(!wcscmp(etcitemtype.c_str(), L"lure"))
					pInfo->etcitemtype = EtcItemLure;
				else if(!wcscmp(etcitemtype.c_str(), L"bless_scrl_enchant_wp"))
					pInfo->etcitemtype = EtcItemBlessedScrollEnchantWeapon;
				else if(!wcscmp(etcitemtype.c_str(), L"bless_scrl_enchant_am"))
					pInfo->etcitemtype = EtcItemBlessedScrollEnchantArmor;
				else if(!wcscmp(etcitemtype.c_str(), L"infinity_soulshot"))
					pInfo->etcitemtype = EtcItemInfinitySoulshot;
				else if(!wcscmp(etcitemtype.c_str(), L"infinity_spiritshot"))
					pInfo->etcitemtype = EtcItemInfinitySpiritshot;
				else if(!wcscmp(etcitemtype.c_str(), L"infinity_blessed_spiritshot"))
					pInfo->etcitemtype = EtcItemInfinityBlessedSpiritshot;
				else if(!wcscmp(etcitemtype.c_str(), L"petarmor"))
					pInfo->etcitemtype = EtcItemPetArmor;
				else if(!wcscmp(etcitemtype.c_str(), L"soulcrystal"))
					pInfo->etcitemtype = EtcItemSoulCrystal;
				else if(!wcscmp(etcitemtype.c_str(), L"lifestone"))
					pInfo->etcitemtype = EtcItemLifeStone;
				else if(!wcscmp(etcitemtype.c_str(), L"keymaterial"))
					pInfo->etcitemtype = EtcItemKeyMaterial;
				else //if(!wcscmp(etcitemtype, L"none"))
					pInfo->etcitemtype = EtcItemNone;

				
				wstring weapontype = Parser::ParseOptionString(line, L"weapon_type");

				//WeaponFist

				if(!wcscmp(weapontype.c_str(), L"sword"))
					pInfo->weapontype = WeaponSword;
				else if(!wcscmp(weapontype.c_str(), L"blunt"))
					pInfo->weapontype = WeaponBlunt;
				else if(!wcscmp(weapontype.c_str(), L"dagger"))
					pInfo->weapontype = WeaponDagger;
				else if(!wcscmp(weapontype.c_str(), L"bow"))
					pInfo->weapontype = WeaponBow;
				else if(!wcscmp(weapontype.c_str(), L"pole"))
					pInfo->weapontype = WeaponPole;
				else if(!wcscmp(weapontype.c_str(), L"etc"))
					pInfo->weapontype = WeaponEtc;
				else if(!wcscmp(weapontype.c_str(), L"dualfist"))
					pInfo->weapontype = WeaponDualFist;
				else if(!wcscmp(weapontype.c_str(), L"dual"))
					pInfo->weapontype = WeaponDual;
				else if(!wcscmp(weapontype.c_str(), L"fishingrod"))
					pInfo->weapontype = WeaponFishingRod;
				else //if(!wcscmp(weapontype.c_str(), L"none"))
					pInfo->weapontype = WeaponNone;

				int pdef = Parser::ParseOptionInt(line, L"physical_defense");
				pInfo->pdef = pdef;

				int mdef = Parser::ParseOptionInt(line, L"magical_defense");
				pInfo->mdef = mdef;

				int patk = Parser::ParseOptionInt(line, L"physical_damage");
				pInfo->patk = patk;

				int matk = Parser::ParseOptionInt(line, L"magical_damage");
				pInfo->matk = matk;

				int pdef_sh = Parser::ParseOptionInt(line, L"shield_defense");
				pInfo->pdef_sh = pdef_sh;

				int weight = Parser::ParseOptionInt(line, L"weight");
				pInfo->weight = weight;

				int is_trade = Parser::ParseOptionInt(line, L"is_trade");
				pInfo->is_trade = is_trade;

				int is_drop = Parser::ParseOptionInt(line, L"is_drop");
				pInfo->is_drop = is_drop;

				int is_destruct = Parser::ParseOptionInt(line, L"is_destruct");
				pInfo->is_destruct = is_destruct;

				int magic_wep = Parser::ParseOptionInt(line, L"magic_weapon");
				pInfo->magic_wep = magic_wep;


				if(pInfo->id)
				{
					bool exist = false;
					//check if duplicated

					//vector<pair<UINT, ItemInfo*>> m_Items;
					for(UINT n=0;n<m_Items.size();n++)
					{
						if(m_Items[n].first == pInfo->id)
						{
							exist = true;
							g_Log.Add(CLog::Error, "[%s] Duplicated item[%d] - line[%d]!", __FUNCTION__, pInfo->id, lineCounter);
							break;
						}
					}
					if(!exist)
					{
						//m_Items.push_back(pInfo);
						if( pInfo->itemtype != ItemTypeQuest && pInfo->is_trade == 1 && pInfo->id != 57 )
						{
							m_Items.push_back(pair<UINT, CItemInformation*>(pInfo->id, pInfo));
						}
					}else
					{
						delete pInfo;
					}
				}
			}
		}
		lineCounter++;
	}
	g_Log.Add(CLog::Blue, "[%s] Loaded[%d] Item Auction DB!", __FUNCTION__, m_Items.size() );
}

CItemInformation* CItemDBEx::GetItemInfo(UINT itemID)
{
	guard;

	CItemInformation *pInfo = NULL;
	for(UINT n=0;n<m_Items.size();n++)
	{
		if(m_Items[n].first == itemID)
		{
			pInfo = m_Items[n].second;
		}
	}

	unguard;
	return pInfo;
}

bool CItemDBEx::ItemCanBeSold(UINT itemID)
{
	guard;

	bool canbe = false;
	for(UINT n=0;n<m_Items.size();n++)
	{
		if(m_Items[n].first == itemID)
		{
			canbe = true;
		}
	}

	unguard;
	return canbe;
}
