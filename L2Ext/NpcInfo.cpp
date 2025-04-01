#include "StdAfx.h"
#include "Packets.h"

extern BOOL g_MostrarLevelMobs;
extern BOOL g_MostrarBanderasMobs;

void CPacketFix::SendNpcInfo(CSocket *pSocket, const char *format, ...)
{
	CPacket Packet;
	va_list tag;
	va_start(tag, format);
/*c*/ Packet.WriteC(va_arg(tag, BYTE)); 
		UINT objectId = va_arg(tag, DWORD);
/*d*/ Packet.WriteD(objectId);

	DWORD _idTemplate = va_arg(tag, DWORD);
	if (_idTemplate > 1035800 && _idTemplate < 1035845)
		_idTemplate = 1035724;

/*d*/ Packet.WriteD(_idTemplate);   //_idTemplate + 1000000
/*d*/ Packet.WriteD(va_arg(tag, DWORD));   //_isAttackable
/*d*/ Packet.WriteD(va_arg(tag, DWORD));   //_x
/*d*/ Packet.WriteD(va_arg(tag, DWORD));   //_y
/*d*/ Packet.WriteD(va_arg(tag, DWORD));   //_z
/*d*/ Packet.WriteD(va_arg(tag, DWORD));   //heading
/*d*/ Packet.WriteD(va_arg(tag, DWORD));   //
/*d*/ Packet.WriteD(va_arg(tag, DWORD));   //mAtkSpd
/*d*/ Packet.WriteD(va_arg(tag, DWORD));   //pAtkSpd
/*d*/ Packet.WriteD(va_arg(tag, DWORD));   //runSpd
/*d*/ Packet.WriteD(va_arg(tag, DWORD));   //walkSpd
/*d*/ Packet.WriteD(va_arg(tag, DWORD));   //runSpd
/*d*/ Packet.WriteD(va_arg(tag, DWORD));   //walkSpd
/*d*/ Packet.WriteD(va_arg(tag, DWORD));   //runSpd
/*d*/ Packet.WriteD(va_arg(tag, DWORD));   //walkSpd
/*d*/ Packet.WriteD(va_arg(tag, DWORD));   //runSpd
/*d*/ Packet.WriteD(va_arg(tag, DWORD));   //walkSpd
/*f*/ Packet.WriteF(va_arg(tag, double));  //getMovementSpeedMultiplier
/*f*/ Packet.WriteF(va_arg(tag, double));  //getAttackSpeedMultiplier
/*f*/ Packet.WriteF(va_arg(tag, double));  //collisionRadius
/*f*/ Packet.WriteF(va_arg(tag, double));  //collisionHeight
/*d*/ Packet.WriteD(va_arg(tag, DWORD));   //rhand
/*d*/ Packet.WriteD(va_arg(tag, DWORD));   //chest
/*d*/ Packet.WriteD(va_arg(tag, DWORD));   //lhand
/*c*/ Packet.WriteC(va_arg(tag, BYTE));    //name above char 
/*c*/ Packet.WriteC(va_arg(tag, BYTE));    //isRunning
/*c*/ Packet.WriteC(va_arg(tag, BYTE));    //isInCombat
/*c*/ Packet.WriteC(va_arg(tag, BYTE));    //isAlikeDead
/*c*/ Packet.WriteC(va_arg(tag, BYTE));    //isSummoned 
/*S*/ Packet.WriteS(va_arg(tag, PWCHAR));  //_name
/*S*/ //Packet.WriteS(va_arg(tag, PWCHAR));  //_title

		PWCHAR title  = va_arg(tag, PWCHAR);
		if(CNPC *pNpc = CNPC::GetNPCByServerId(&objectId))
		{
			if((pNpc->pSD->nClass==1 || pNpc->pSD->nClass==81 ||pNpc->pSD->nClass==82) && _idTemplate !=1040000 && g_MostrarLevelMobs)
			{
				int level = pNpc->pSD->nLevel;
				std::wstringstream wss;
				wss << "*Level " << level << "*";
				wstring value = wss.str();
				const WCHAR * value2 = value.c_str();
				/*S*/ Packet.WriteS((PWCHAR)value2);  //_title
			}
			else
			{
				/*S*/ Packet.WriteS(title);  //_title
			}
		}
		else
		{
			/*S*/ Packet.WriteS(title);  //_title
		}

/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//
/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//
/*d*/ Packet.WriteD(va_arg(tag, DWORD));	//
		DWORD AbnormalVisualEffect = va_arg(tag, DWORD);
		if(CNPC *pNpc = CNPC::GetNPCByServerId(&objectId))
		{
			if(pNpc->IsSummon() || pNpc->IsPet())
			{
				User *pMaster = pNpc->CastSummon()->GetMaster();
				if(pMaster->ValidUser())
				{
					if(pMaster->pED->spawnProtection == 2)
					{
						AbnormalVisualEffect |= 0x200000;
					}
				}
			}
		}
/*d*/ Packet.WriteD(AbnormalVisualEffect); //AbnormalEffect

		int PledgeId = va_arg(tag, DWORD);
		int nCrestID = va_arg(tag, DWORD);
		int AllianceId = va_arg(tag, DWORD);
		int AllianceCrestID = va_arg(tag, DWORD);
		if(CNPC *pNpc = CNPC::GetNPCByServerId(&objectId))
		{
			if (g_MostrarBanderasMobs)
			{
				CCastle *pCastle = (CCastle*)g_ResidenceDB.GetResidence(pNpc->pSD->nResidenceID);
				if(pCastle)
				{
					CPledge *pPledge = GetPledgeByID(pCastle->pRD->nPledgeID);
					if(pPledge)
					{
						PledgeId = pCastle->pRD->nPledgeID;
						nCrestID = pPledge->pSD->nCrestID;
						AllianceId = pPledge->GetAllianceID();
						AllianceCrestID = pPledge->GetAllianceCrestID();
					}
				}
			}
		}
		Packet.WriteD(PledgeId);
		Packet.WriteD(nCrestID);
		Packet.WriteD(AllianceId);
		Packet.WriteD(AllianceCrestID);

/*c*/ Packet.WriteC(va_arg(tag, BYTE));    //isFlying
		BYTE bteam = va_arg(tag, BYTE);
		if(CNPC *pNpc = CNPC::GetNPCByServerId(&objectId))
		{
			if(pNpc->pSD->teamType)
			{
				bteam = pNpc->pSD->teamType;
			}
		}
/*c*/ Packet.WriteC(bteam);  //getTeam
/*f*/ Packet.WriteF(va_arg(tag, double));  //collisionRadius
/*f*/ Packet.WriteF(va_arg(tag, double));  //collisionHeight
/*d*/ Packet.WriteD(va_arg(tag, DWORD));   //enchantEffect
	va_end(tag);
//Intelrude
	Packet.WriteD(0); //IsFlying

	if(CNPC *pNpc = CNPC::GetNPCByServerId(&objectId))
	{
		if(pNpc->IsSummon() || pNpc->IsPet())
		{
			User *pMaster = pNpc->CastSummon()->GetMaster();
			if(pMaster->ValidUser())
			{
				TerritoryData& td = pMaster->pSD->pExData->territoryData;
				if(td.territoryId[NOCHARSHOWZONE] != 0)
				{

				}
				else
				{
					pSocket->Send("b", Packet.GetSize(), Packet.GetBuff());
				}
			}
		}
		else
		{
			pSocket->Send("b", Packet.GetSize(), Packet.GetBuff());
		}
	}
	else
	{
		pSocket->Send("b", Packet.GetSize(), Packet.GetBuff());
	}
}

void CPacketFix::BCSendNpcInfo(INT64 dwAddr, int nObjID, int nRange, FVector *pLocation, const char *format, ...)
{
	CPacket Packet;
	va_list tag;
	va_start(tag, format);
/*c*/ Packet.WriteC(va_arg(tag, BYTE)); 
		UINT objectId = va_arg(tag, DWORD);
/*d*/ Packet.WriteD(objectId);
/*d*/ Packet.WriteD(va_arg(tag, DWORD));
/*d*/ Packet.WriteD(va_arg(tag, DWORD));
/*d*/ Packet.WriteD(va_arg(tag, DWORD));
/*d*/ Packet.WriteD(va_arg(tag, DWORD));
/*d*/ Packet.WriteD(va_arg(tag, DWORD));
/*d*/ Packet.WriteD(va_arg(tag, DWORD));
/*d*/ Packet.WriteD(va_arg(tag, DWORD));
/*d*/ Packet.WriteD(va_arg(tag, DWORD));
/*d*/ Packet.WriteD(va_arg(tag, DWORD));
/*d*/ Packet.WriteD(va_arg(tag, DWORD));
/*d*/ Packet.WriteD(va_arg(tag, DWORD));
/*d*/ Packet.WriteD(va_arg(tag, DWORD));
/*d*/ Packet.WriteD(va_arg(tag, DWORD));
/*d*/ Packet.WriteD(va_arg(tag, DWORD));
/*d*/ Packet.WriteD(va_arg(tag, DWORD));
/*d*/ Packet.WriteD(va_arg(tag, DWORD));
/*d*/ Packet.WriteD(va_arg(tag, DWORD));
/*f*/ Packet.WriteF(va_arg(tag, double));
/*f*/ Packet.WriteF(va_arg(tag, double));
/*f*/ Packet.WriteF(va_arg(tag, double));
/*f*/ Packet.WriteF(va_arg(tag, double));
/*d*/ Packet.WriteD(va_arg(tag, DWORD));
/*d*/ Packet.WriteD(va_arg(tag, DWORD));
/*d*/ Packet.WriteD(va_arg(tag, DWORD));
/*c*/ Packet.WriteC(va_arg(tag, BYTE)); 
/*c*/ Packet.WriteC(va_arg(tag, BYTE)); 
/*c*/ Packet.WriteC(va_arg(tag, BYTE)); 
/*c*/ Packet.WriteC(va_arg(tag, BYTE)); 
/*c*/ Packet.WriteC(va_arg(tag, BYTE)); 
/*S*/ Packet.WriteS(va_arg(tag, PWCHAR));
/*S*/ //Packet.WriteS(va_arg(tag, PWCHAR));	//_title

		PWCHAR title  = va_arg(tag, PWCHAR);

		if(CNPC *pNpc = CNPC::GetNPCByServerId(&objectId))
		{
			if((pNpc->pSD->nClass==1 || pNpc->pSD->nClass==81 ||pNpc->pSD->nClass==82)  && g_MostrarLevelMobs)
			{
				int level = pNpc->pSD->nLevel;
				std::wstringstream wss;
				wss << "*Level " << level << "*";
				wstring value = wss.str();
				const WCHAR * value2 = value.c_str();
				/*S*/ Packet.WriteS((PWCHAR)value2);  //_title
			}
			else
			{
				/*S*/ Packet.WriteS(title);  //_title
			}
		}
		else
		{
			/*S*/ Packet.WriteS(title);  //_title
		}

/*d*/ Packet.WriteD(va_arg(tag, DWORD));
/*d*/ Packet.WriteD(va_arg(tag, DWORD));
/*d*/ Packet.WriteD(va_arg(tag, DWORD));
	DWORD AbnormalVisualEffect = va_arg(tag, DWORD);
		if(CNPC *pNpc = CNPC::GetNPCByServerId(&objectId))
		{
			if(pNpc->IsSummon() || pNpc->IsPet())
			{
				User *pMaster = pNpc->CastSummon()->GetMaster();
				if(pMaster->ValidUser())
				{
					if(pMaster->pED->spawnProtection == 2)
					{
						AbnormalVisualEffect |= 0x200000;
					}
				}
			}
		}
/*d*/ Packet.WriteD(AbnormalVisualEffect);

		int PledgeId = va_arg(tag, DWORD);
		int nCrestID = va_arg(tag, DWORD);
		int AllianceId = va_arg(tag, DWORD);
		int AllianceCrestID = va_arg(tag, DWORD);
		if(CNPC *pNpc = CNPC::GetNPCByServerId(&objectId))
		{
			if (g_MostrarBanderasMobs)
			{
				CCastle *pCastle = (CCastle*)g_ResidenceDB.GetResidence(pNpc->pSD->nResidenceID);
				if(pCastle)
				{
					CPledge *pPledge = GetPledgeByID(pCastle->pRD->nPledgeID);
					if(pPledge)
					{
						PledgeId = pCastle->pRD->nPledgeID;
						nCrestID = pPledge->pSD->nCrestID;
						AllianceId = pPledge->GetAllianceID();
						AllianceCrestID = pPledge->GetAllianceCrestID();
					}
				}
			}
		}
		Packet.WriteD(PledgeId);
		Packet.WriteD(nCrestID);
		Packet.WriteD(AllianceId);
		Packet.WriteD(AllianceCrestID);

/*c*/ Packet.WriteC(va_arg(tag, BYTE)); 
		BYTE bteam = va_arg(tag, BYTE);
		if(CNPC *pNpc = CNPC::GetNPCByServerId(&objectId))
		{
			if(pNpc->pSD->teamType)
			{
				bteam = pNpc->pSD->teamType;
			}
		}
/*c*/ Packet.WriteC(bteam);  //getTeam
/*f*/ Packet.WriteF(va_arg(tag, double)); 
/*f*/ Packet.WriteF(va_arg(tag, double)); 
/*d*/ Packet.WriteD(va_arg(tag, DWORD));
	va_end(tag);
//Intelrude
	Packet.WriteD(0); //IsFlying

	if(CNPC *pNpc = CNPC::GetNPCByServerId(&objectId))
	{
		if(pNpc->IsSummon() || pNpc->IsPet())
		{
			User *pMaster = pNpc->CastSummon()->GetMaster();
			if(pMaster->ValidUser())
			{
				TerritoryData& td = pMaster->pSD->pExData->territoryData;
				if(td.territoryId[NOCHARSHOWZONE] != 0)
				{
					
				}
				else
				{
					BroadcastToNeighborExceptSelf(nObjID, nRange, pLocation, (int)Packet.GetSize(), Packet.GetBuff());
				}
			}
			else
			{
				BroadcastToNeighborExceptSelf(nObjID, nRange, pLocation, (int)Packet.GetSize(), Packet.GetBuff());
			}
		}
		else
		{
			BroadcastToNeighborExceptSelf(nObjID, nRange, pLocation, (int)Packet.GetSize(), Packet.GetBuff());
		}
	}
	else
	{
		BroadcastToNeighborExceptSelf(nObjID, nRange, pLocation, (int)Packet.GetSize(), Packet.GetBuff());
	}
}