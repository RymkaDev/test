#include "StdAfx.h"
#include "Packets.h"
#include "AccountDB.h"
#include "SocketDB.h"
#include "OfflineShopRestore.h"

extern INT32 g_AntiBotVersion;

void CPacketFix::CharSelectInfoFix(CUserSocket *pSocket, const char *szFormat, BYTE bOpCode, DWORD dwCharNum, DWORD dwPacketSize, PUCHAR pOldPacket)
{
	if(dwCharNum<=0)
		pSocket->Send(szFormat, bOpCode, dwCharNum, dwPacketSize, pOldPacket);
	else if (pSocket && pOldPacket)
	{
		g_AccountDB.Add(pSocket->accountId, pSocket);

		CPacket OldPacket(pOldPacket);
		CPacket NewPacket;
		for(unsigned int n=0;n<dwCharNum; n++)
		{
			/*S*/ NewPacket.WriteS(OldPacket.ReadS());
				int nCharID = OldPacket.ReadD();
			/*d*/ NewPacket.WriteD(nCharID);
			/*S*/ NewPacket.WriteS(OldPacket.ReadS());	//AccauntName
			/*d*/ NewPacket.WriteD(OldPacket.ReadD());	//SessionID
			/*d*/ NewPacket.WriteD(OldPacket.ReadD());	//ClanID
			/*d*/ NewPacket.WriteD(OldPacket.ReadD());	//Unknown

					UINT sexo = OldPacket.ReadD();		//Sex

					UINT race = OldPacket.ReadD();		//race
					UINT baseClass = OldPacket.ReadD();

			UINT active = OldPacket.ReadD();	//active
			UINT locx = OldPacket.ReadD();		//x
			UINT locy = OldPacket.ReadD();		//y
			UINT locz = OldPacket.ReadD();		//z
			double cur_hp = OldPacket.ReadF();	//cur hp
			double cur_mp = OldPacket.ReadF();	//cur mp
			UINT SP = OldPacket.ReadD();		//SP

			/*Q*/ INT32 nExp = OldPacket.ReadD();		//EXP

			UINT Level = OldPacket.ReadD();	//Level
			UINT Karma = OldPacket.ReadD();	//Karma
			UINT PK = OldPacket.ReadD();	//PK
			UINT Unknown1 = OldPacket.ReadD();	//Unknown1
			UINT Unknown2 = OldPacket.ReadD();	//Unknown2
			UINT Unknown3 = OldPacket.ReadD();	//Unknown3
			UINT Unknown4 = OldPacket.ReadD();	//Unknown4
			UINT Unknown5 = OldPacket.ReadD();	//Unknown5
			UINT Unknown6 = OldPacket.ReadD();	//Unknown6
			UINT Unknown7 = OldPacket.ReadD();	//Unknown7
			UINT Unknown8 = OldPacket.ReadD();	//Unknown8
			UINT Under = OldPacket.ReadD();	//Under
			UINT REar = OldPacket.ReadD();	//REar
			UINT LEar = OldPacket.ReadD();	//LEar
			UINT Neck = OldPacket.ReadD();	//Neck
			UINT RFinger = OldPacket.ReadD();	//RFinger
			UINT LFinger = OldPacket.ReadD();	//LFinger
			UINT Head = OldPacket.ReadD();	//Head
			UINT RHand = OldPacket.ReadD();	//RHand
			UINT LHand = OldPacket.ReadD();	//LHand
			UINT Gloves = OldPacket.ReadD();	//Gloves
			UINT Chest = OldPacket.ReadD();	//Chest
			UINT Legs = OldPacket.ReadD();	//Legs
			UINT Feet = OldPacket.ReadD();	//Feet
			UINT Back = OldPacket.ReadD();	//Back
			UINT LRHand = OldPacket.ReadD();	//LRHand

			int nHairDBID = OldPacket.ReadD();		//Hair Slot dbid
			int nFaceDBID = OldPacket.ReadD();		//Face Slot dbid

			UINT Unknown9 = OldPacket.ReadD();	//Unknown9
			UINT Unknown10 = OldPacket.ReadD();	//Unknown10
			UINT Unknown11 = OldPacket.ReadD();	//Unknown11
			UINT Unknown12 = OldPacket.ReadD();	//Unknown12
			UINT Unknown13 = OldPacket.ReadD();	//Unknown13
			UINT Unknown14 = OldPacket.ReadD();	//Unknown14
			UINT Unknown15 = OldPacket.ReadD();	//Unknown15
			UINT Unknown16 = OldPacket.ReadD();	//Unknown16
			UINT Unknown17 = OldPacket.ReadD();	//Unknown17
			UINT Unknown18 = OldPacket.ReadD();	//Unknown18
			UINT Unknown19 = OldPacket.ReadD();	//Unknown19
			UINT Unknown20 = OldPacket.ReadD();	//Unknown20
			UINT Unknown21 = OldPacket.ReadD();	//Unknown21
			UINT Unknown22 = OldPacket.ReadD();	//Unknown22
			UINT Unknown23 = OldPacket.ReadD();	//Unknown23

			int nHairItemType = OldPacket.ReadD();	//Hair Slot type
			int nFaceItemType = OldPacket.ReadD();	//Face slot type

			UINT HairStyle = OldPacket.ReadD();	//HairStyle
			UINT HairColor = OldPacket.ReadD();	//HairColor
			UINT Face = OldPacket.ReadD();			//Face
			double MaxHP = OldPacket.ReadF();		//MaxHP
			double MaxMP = OldPacket.ReadF();		//MaxMP
			UINT DeleteDays = OldPacket.ReadD();	//DeleteDays
			UINT class_id = OldPacket.ReadD();		//class_id

				//-------------------------------------------------------------------------	
			int customSkin = g_AccountDB.GetCustomSkin(nCharID);
			if (customSkin >-1)
				baseClass =customSkin;

			pSocket->pED->baseClass[n] = baseClass;

			if (baseClass >= 0 && baseClass <= 9 || baseClass >= 88 && baseClass <= 93)	//humano warrior
				race=0;
			if (baseClass >= 10 && baseClass <= 17 || baseClass >= 94 && baseClass <= 98)	//humano mago
				race=0;
			if (baseClass >= 18 && baseClass <= 30 || baseClass >= 99 && baseClass <= 105)	//elf warrior y mago
				race=1;
			if (baseClass >= 31 && baseClass <= 43 || baseClass >= 106 && baseClass <= 112)	//dark elf warrior y mago //aca el 106 lo tenia como 109
				race=2;
			if (baseClass >= 44 && baseClass <= 52 || baseClass >= 113 && baseClass <= 116)	//orco warrior y mago
				race=3;
			if (baseClass >= 53 && baseClass <= 57 || baseClass >= 117 && baseClass <= 118)	// enano
				race=4;

			int custom_sex = g_AccountDB.GetCustomSex(nCharID);
			if (custom_sex >-1)
				sexo = custom_sex;


			/*d*/ NewPacket.WriteD(sexo);				//race
			/*d*/ NewPacket.WriteD(race);				//race
			/*d*/ NewPacket.WriteD(baseClass);			//base class

			/*d*/ NewPacket.WriteD(active);	//active
			/*d*/ NewPacket.WriteD(locx);	//x
			/*d*/ NewPacket.WriteD(locy);	//y
			/*d*/ NewPacket.WriteD(locz);	//z
			/*f*/ NewPacket.WriteF(cur_hp);	//cur hp
			/*f*/ NewPacket.WriteF(cur_mp);	//cur mp
			/*d*/ NewPacket.WriteD(SP);	//SP
			
				  NewPacket.WriteQ(CL2LevelUP::GetExperience(nExp));

			/*d*/ NewPacket.WriteD(Level);	//Level
			/*d*/ NewPacket.WriteD(Karma);	//Karma
			/*d*/ NewPacket.WriteD(PK);	//PK
			/*d*/ NewPacket.WriteD(Unknown1);	//Unknown1
			/*d*/ NewPacket.WriteD(Unknown2);	//Unknown2
			/*d*/ NewPacket.WriteD(Unknown3);	//Unknown3
			/*d*/ NewPacket.WriteD(Unknown4);	//Unknown4
			/*d*/ NewPacket.WriteD(Unknown5);	//Unknown5
			/*d*/ NewPacket.WriteD(Unknown6);	//Unknown6
			/*d*/ NewPacket.WriteD(Unknown7);	//Unknown7
			/*d*/ NewPacket.WriteD(Unknown8);	//Unknown8
			/*d*/ NewPacket.WriteD(Under);	//Under
			/*d*/ NewPacket.WriteD(REar);	//REar
			/*d*/ NewPacket.WriteD(LEar);	//LEar
			/*d*/ NewPacket.WriteD(Neck);	//Neck
			/*d*/ NewPacket.WriteD(RFinger);	//RFinger
			/*d*/ NewPacket.WriteD(LFinger);	//LFinger
			/*d*/ NewPacket.WriteD(Head);	//Head
			/*d*/ NewPacket.WriteD(RHand);	//RHand
			/*d*/ NewPacket.WriteD(LHand);	//LHand
			/*d*/ NewPacket.WriteD(Gloves);	//Gloves
			/*d*/ NewPacket.WriteD(Chest);	//Chest
			/*d*/ NewPacket.WriteD(Legs);	//Legs
			/*d*/ NewPacket.WriteD(Feet);	//Feet
			/*d*/ NewPacket.WriteD(Back);	//Back
			/*d*/ NewPacket.WriteD(LRHand);	//LRHand

			/*d*/ NewPacket.WriteD(nHairDBID);			
			/*d*/ NewPacket.WriteD(nFaceDBID);	

			/*d*/ NewPacket.WriteD(Unknown9);	//Unknown9
			/*d*/ NewPacket.WriteD(Unknown10);	//Unknown10
			/*d*/ NewPacket.WriteD(Unknown11);	//Unknown11
			/*d*/ NewPacket.WriteD(Unknown12);	//Unknown12
			/*d*/ NewPacket.WriteD(Unknown13);	//Unknown13
			/*d*/ NewPacket.WriteD(Unknown14);	//Unknown14
			/*d*/ NewPacket.WriteD(Unknown15);	//Unknown15
			/*d*/ NewPacket.WriteD(Unknown16);	//Unknown16
			/*d*/ NewPacket.WriteD(Unknown17);	//Unknown17
			/*d*/ NewPacket.WriteD(Unknown18);	//Unknown18
			/*d*/ NewPacket.WriteD(Unknown19);	//Unknown19
			/*d*/ NewPacket.WriteD(Unknown20);	//Unknown20
			/*d*/ NewPacket.WriteD(Unknown21);	//Unknown21
			/*d*/ NewPacket.WriteD(Unknown22);	//Unknown22
			/*d*/ NewPacket.WriteD(Unknown23);	//Unknown23

			/*d*/ NewPacket.WriteD(nHairItemType);		
			/*d*/ NewPacket.WriteD(nFaceItemType);	


			/*d*/ NewPacket.WriteD(HairStyle);	//HairStyle
			/*d*/ NewPacket.WriteD(HairColor);	//HairColor
			/*d*/ NewPacket.WriteD(Face);	//Face
			/*f*/ NewPacket.WriteF(MaxHP);	//MaxHP
			/*f*/ NewPacket.WriteF(MaxMP);	//MaxMP
			/*d*/ NewPacket.WriteD(DeleteDays);	//DeleteDays
			/*d*/ NewPacket.WriteD(class_id);	//class_id


			/*d*/ NewPacket.WriteD(OldPacket.ReadD());
			/*c*/ NewPacket.WriteC(OldPacket.ReadC());
			UINT augmentation = OldPacket.ReadD();
			/*d - new*/ NewPacket.WriteD(augmentation); //Augmentation ID

			int EffectiveMana0 = OldPacket.ReadD();
			int EffectiveMana1 = OldPacket.ReadD();
			int EffectiveMana2 = OldPacket.ReadD();
			int EffectiveMana3 = OldPacket.ReadD();
		}
		pSocket->Send(szFormat, bOpCode, dwCharNum, NewPacket.GetSize(), NewPacket.GetBuff());

	}

	NuevasFunciones::EnviarCrackInterfaceCelestine(pSocket);


	NuevasFunciones::EnviarHooksAlCliente(pSocket);

	
	
	g_SocketDB.SetStatus(pSocket, CSocketData::CHAR_SELECTION_SCREEN);

	if (pSocket->pED->is_osr || pSocket->pED->is_osr_buff)
	{
		g_OfflineShopRestore.OnLoadCharacterPacket2(pSocket);
	}
}
