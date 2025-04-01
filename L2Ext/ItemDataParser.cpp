#include "StdAfx.h"
#include "ItemDataParser.h"

void CItemDataParser::Init()
{
	//initialize
	g_HookManager.WriteCall(0x008E799C, FindInTable, 0);
	g_HookManager.WriteCall(0x008E91B7, FindInTable, 0);
}

INT64 CItemDataParser::FindInTable(ObjectFieldType field, PWCHAR wStr)
{
	typedef INT64 (*_f)(ObjectFieldType, PWCHAR);
	_f f = (_f) 0x008E76F0;

	INT64 n = f(field, wStr);
	if(n == -1)
	{
		if(_wcsicmp(wStr, L"infinity_soulshot") == 0)
			return EtcItemInfinitySoulshot;
		if(_wcsicmp(wStr, L"infinity_spiritshot") == 0)
			return EtcItemInfinitySpiritshot;
		if(_wcsicmp(wStr, L"infinity_blessed_spiritshot") == 0)
			return EtcItemInfinityBlessedSpiritshot;
		if(_wcsicmp(wStr, L"hairdeco") == 0)
			return 0x010000LL; //0x040000LL;  0x010000LL
		if(_wcsicmp(wStr, L"hair2") == 0)
			return 0x040000LL; //0x040000LL;  0x010000LL
		if(_wcsicmp(wStr, L"hairall") == 0)
			return 0x080000LL; //0x080000LL;  0x010000LL
		//New EtcItemTypes
		if(_wcsicmp(wStr, L"petarmor") == 0)
			return EtcItemPetArmor;
		if(_wcsicmp(wStr, L"soulcrystal") == 0)
			return EtcItemSoulCrystal;
		if(_wcsicmp(wStr, L"lifestone") == 0)
			return EtcItemLifeStone;
		else if(_wcsicmp(wStr, L"keymaterial") == 0)
			return EtcItemKeyMaterial;
		//else if(_wcsicmp(wStr, L"back") == 0)
		//	return 0x2000LL; //0x080000LL;  0x010000LL
		
	}

	return n;
}