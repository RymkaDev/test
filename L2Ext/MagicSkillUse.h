#pragma once

#include "ServerPacket.h"

class CMagicSkillUse : public CServerPacket
{
public:
	CMagicSkillUse(int nCasterSID, int targetId, int nSkillID, int nLevel, int nHitTime, int targetSmartID, int x, int y, int z)
	{
		Write((BYTE)0x48);
		Write((DWORD) nCasterSID);
		Write((DWORD) targetId);
		Write((DWORD) nSkillID);
		Write((DWORD) nLevel);
		Write((DWORD) nHitTime);
		Write((DWORD) targetSmartID);
		Write((DWORD) x);
		Write((DWORD) y);
		Write((DWORD) z);
		Write((WORD) 0);
		Write((WORD) 0);
		Write((WORD) 0);
		Write((WORD) 0);
	};
};


class MagicSkillLaunched : public CServerPacket
{
public:
	MagicSkillLaunched(int nCasterSID, int targetId, int nSkillID, int nLevel)
	{
		Write((BYTE)0x76);
		Write((DWORD) nCasterSID);
		Write((DWORD) nSkillID);
		Write((DWORD) nLevel);
		Write((DWORD) 1);
		Write((DWORD) targetId);
	};
};
