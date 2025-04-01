#include "StdAfx.h"
#include "Packets.h"

extern User* g_CharInfoUser[16];

void CPacketFix::DiePacket(CUserSocket *pSocket, const char *format, ...)
{
	User *pUser = 0;
	UINT threadIndex = GetThreadIndex();
	if(threadIndex < 16)
	{
		pUser = g_CharInfoUser[threadIndex];
	}

	CPacket Packet;
	va_list tag;
	va_start(tag, format);

	BYTE opCode = va_arg(tag, BYTE);
	UINT nObjectID = va_arg(tag, DWORD);
	UINT ToVillage = va_arg(tag, DWORD);
	UINT ToClanHall = va_arg(tag, DWORD);
	UINT ToCastle = va_arg(tag, DWORD);
	UINT ToSiegeHQ = va_arg(tag, DWORD);
	UINT SweepEffect = 0;
	UINT Fixed = 0;

	if(pUser == 0)
	{
		pUser = User::GetUserBySID(&nObjectID);
		if(!pUser->ValidUser())
		{
			return;
		}
	}

	TerritoryData& td = pUser->pSD->pExData->territoryData;

	if(td.territoryId[FACTION_ZONE] != 0)
	{
		Fixed = 1;
		SweepEffect = 1; //??
	}

	if(pUser->pED->tvtUser.status == TvT::UserFighting)
	{
		ToVillage = 0;
		ToClanHall = 0;
		ToCastle = 0;
		ToSiegeHQ = 0;
	}

	/*c*/ Packet.WriteC(opCode);
	/*d*/ Packet.WriteD(nObjectID);
	/*d*/ Packet.WriteD(ToVillage);
	/*d*/ Packet.WriteD(ToClanHall);
	/*d*/ Packet.WriteD(ToCastle);
	/*d*/ Packet.WriteD(ToSiegeHQ);
	/*d*/ Packet.WriteD(SweepEffect); //sweep
	/*d*/ Packet.WriteD(Fixed); //custom fixed button

	pSocket->Send("b", Packet.GetSize(), Packet.GetBuff());
}