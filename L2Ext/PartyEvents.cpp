#include "StdAfx.h"
#include "PartyEvents.h"
#include "PlayerAction.h"

PartyEvents g_PartyEvents;


void PartyEvents::Init()
{
	LoadINI();
}

/*
[PARTY_EVENTS]
Enabled=1
PartyEvents=1

1_RequiredItemId=57
1_RequiredItemCount=100
1_RewardId=57
1_RewardAmount=200
1_BlueTeamLocation=153256/-154177/-7752
1_RedTeamLocation=154566/-154164/-7752
1_KickOutPos=83380/148184/-3400

*/
void PartyEvents::LoadINI()
{
	g_Log.Add(CLog::Blue, "[Load PartyEvents]");


	m_Info.clear();

	const TCHAR* sectionName = _T("PARTY_EVENTS");
	m_Enable = GetPrivateProfileInt(sectionName, _T("Enabled"), 0, g_CustomConfigFile);
	UINT availableEvents = GetPrivateProfileInt(sectionName, _T("PartyEvents"), 0, g_CustomConfigFile);
	for(UINT n=1;n<=availableEvents;n++)
	{
		PartyEventsInfo pInfo;
		pInfo.id = n;

		int m_bluePosCantidad = 0;
		int m_redPosCantidad = 0;
		int m_bluePosPosicion = 0;
		int m_redPosPosicion = 0;

		{
			TCHAR sTemp[0x8000];
			memset(sTemp, 0, sizeof(sTemp));
			tstringstream skey;
			skey << n << "_BlueTeamLocation";
			if(GetPrivateProfileString(sectionName, skey.str().c_str(), 0, sTemp, 8192, g_CustomConfigFile))
			{
				tstring pos = sTemp;
				pos = Utils::ReplaceString(pos, _T("/"), _T(" "), true);
				tstringstream sstr;
				sstr << pos;
				
				while(sstr >> pInfo.bluePos[m_bluePosCantidad].x >> pInfo.bluePos[m_bluePosCantidad].y >> pInfo.bluePos[m_bluePosCantidad].z)
				{
					m_bluePosCantidad++;
				}
			}else
			{
				pInfo.bluePos[0].x = 0;
				pInfo.bluePos[0].y = 0;
				pInfo.bluePos[0].z = 0;
			}
		}

		{
			TCHAR sTemp[0x8000];
			memset(sTemp, 0, sizeof(sTemp));
			tstringstream skey;
			skey << n << "_RedTeamLocation";
			if(GetPrivateProfileString(sectionName, skey.str().c_str(), 0, sTemp, 8192, g_CustomConfigFile))
			{
				tstring pos = sTemp;
				pos = Utils::ReplaceString(pos, _T("/"), _T(" "), true);
				tstringstream sstr;
				sstr << pos;
				
				while(sstr >> pInfo.redPos[m_redPosCantidad].x >> pInfo.redPos[m_redPosCantidad].y >> pInfo.redPos[m_redPosCantidad].z)
				{
					m_redPosCantidad++;
				}
			}else
			{
				pInfo.redPos[0].x = 0;
				pInfo.redPos[0].y = 0;
				pInfo.redPos[0].z = 0;
			}
		}

		{
			TCHAR sTemp[0x8000];
			memset(sTemp, 0, sizeof(sTemp));
			tstringstream skey;
			skey << n << "_KickOutPos";
			if(GetPrivateProfileString(sectionName, skey.str().c_str(), 0, sTemp, 8192, g_CustomConfigFile))
			{
				tstring pos = sTemp;
				pos = Utils::ReplaceString(pos, _T("/"), _T(" "), true);
				tstringstream sstr;
				sstr << pos;
				sstr >> pInfo.kickOutPos.x >> pInfo.kickOutPos.y >> pInfo.kickOutPos.z;
			}else
			{
				pInfo.kickOutPos.x = 0;
				pInfo.kickOutPos.y = 0;
				pInfo.kickOutPos.z = 0;
			}

		}

		pInfo.m_stateTime = time(NULL);
		m_Info.push_back(pInfo);
	}
}

void PartyEvents::TimerExpired()
{
	guard;

		Lock();
		if(m_Enable)
		{
			time_t currentTime = time(NULL);

			time_t diff = m_stateTime + 10;
			diff -= currentTime;
			if(diff > 0)
			{
				if(diff == 10)
				{
					// BUSCAR m_Partys con las mismas caracteristicas
					for (size_t i = 0; i < m_Partys.size(); ++i)
					{
						for (size_t j = i + 1; j < m_Partys.size(); ++j)
						{
							// Compara los valores de m_Cantidad, m_ApuestaId y m_ApuestaTotal
							if (m_Partys[i].m_Cantidad == m_Partys[j].m_Cantidad &&
								m_Partys[i].m_ApuestaId == m_Partys[j].m_ApuestaId &&
								m_Partys[i].m_ApuestaTotal == m_Partys[j].m_ApuestaTotal &&
								m_Partys[i].m_ObjectID != m_Partys[j].m_ObjectID &&
								m_Partys[i].m_state == Espera && m_Partys[j].m_state == Espera)
							{

								bool party1 = false;
								bool party2 = false;

								//-----PARTY 1
								if(User *pUser = g_UserDB.GetUserByName(m_Partys[i].n_PartyLeader)->SafeCastUser())
								{
									if(pUser->inventory.HaveItemByClassID(m_Partys[i].m_ApuestaId, m_Partys[i].m_ApuestaTotal))
									{
										UINT nPartyID = pUser->pSD->nPartyID;
										CParty *pParty = static_cast<CParty *>(CObject::GetObjectBySID(m_Partys[i].m_ObjectID));
										if(pParty->IsValidParty())
										{	
											if(m_Partys[i].m_Cantidad == pParty->memberCount)
											{
												party1 = true;
											}
											else
											{
												CSystemMessage msg1(SystemMessage::S1_POPUP);
												msg1.AddText(L"La cantidad de players en la party no es la acordada previamente.");
												pUser->pSocket->SendSystemMessage(&msg1);
												//BORRAR PARTY DEL VECTOR
											}

										}
									}
									else
									{
										CSystemMessage msg1(SystemMessage::S1_POPUP);
										msg1.AddText(L"No tienes los items necesarios para cubrir la apuesta.");
										pUser->pSocket->SendSystemMessage(&msg1);
										//BORRAR PARTY DEL VECTOR
									}
								}
								//----------

								//-----PARTY 2
								if(User *pUser = g_UserDB.GetUserByName(m_Partys[j].n_PartyLeader)->SafeCastUser())
								{
									if(pUser->inventory.HaveItemByClassID(m_Partys[j].m_ApuestaId, m_Partys[j].m_ApuestaTotal))
									{
										UINT nPartyID = pUser->pSD->nPartyID;
										CParty *pParty = static_cast<CParty *>(CObject::GetObjectBySID(m_Partys[j].m_ObjectID));
										if(pParty->IsValidParty())
										{	
											if(m_Partys[j].m_Cantidad == pParty->memberCount)
											{
												party2 = true;
											}
											else
											{
												CSystemMessage msg1(SystemMessage::S1_POPUP);
												msg1.AddText(L"La cantidad de players en la party no es la acordada previamente.");
												pUser->pSocket->SendSystemMessage(&msg1);
												//BORRAR PARTY DEL VECTOR
											}

										}
									}
									else
									{
										CSystemMessage msg1(SystemMessage::S1_POPUP);
										msg1.AddText(L"No tienes los items necesarios para cubrir la apuesta.");
										pUser->pSocket->SendSystemMessage(&msg1);
										//BORRAR PARTY DEL VECTOR
									}
								}
								//----------


								if(party1 && party2)
									MandarAPelear(m_Partys[i], m_Partys[j]);
							}
						}
					}
				}
			}
			else
			{
				m_stateTime = time(NULL);
			}

			
			for (size_t i = 0; i < m_Info.size(); ++i)
			{
				if(m_Info[i].m_state != PartyEventStateNone)
				{
					if (m_Info[i].m_state == PartyEventStatePreparation)
					{
						map<wstring, wstring> aiParams;
						aiParams.insert(pair<wstring, wstring>(L"fnHi", L"buffer_npc_torneo.htm"));
						m_Info[i].m_managerServerId = NpcServer::SpawnNpcEx(m_Info[i].BufferNpcClassId, m_Info[i].buffer1_Pos.x, m_Info[i].buffer1_Pos.y, m_Info[i].buffer1_Pos.z, aiParams);
						m_Info[i].m_managerServerId2 = NpcServer::SpawnNpcEx(m_Info[i].BufferNpcClassId, m_Info[i].buffer2_Pos.x, m_Info[i].buffer2_Pos.y, m_Info[i].buffer2_Pos.z, aiParams);

						m_Info[i].m_state = PartyEventStateCountDown;
						continue;
					}
					else if(m_Info[i].m_state == PartyEventStateCountDown)
					{
						time_t diff = m_stateTime + 60;
						diff -= currentTime;
						if(diff > 0)
						{
							if(m_Info[i].fightStartRemindMsg.size() > 0)
							{
								if(diff == 60)
								{
									TCHAR remainSec[16];
									_itot_s(static_cast<int>(diff), remainSec, 16, 10);
									wstring announce = Utils::ReplaceString(m_Info[i].fightStartRemindMsg, _T("[param]"), remainSec);
									SendMessageDist(m_Info[i],announce.c_str());
								}else if(diff == 30)
								{
									TCHAR remainSec[16];
									_itot_s(static_cast<int>(diff), remainSec, 16, 10);
									wstring announce = Utils::ReplaceString(m_Info[i].fightStartRemindMsg, _T("[param]"), remainSec);
									SendMessageDist(m_Info[i],announce.c_str());
								}else if(diff == 15)
								{
									TCHAR remainSec[16];
									_itot_s(static_cast<int>(diff), remainSec, 16, 10);
									wstring announce = Utils::ReplaceString(m_Info[i].fightStartRemindMsg, _T("[param]"), remainSec);
									SendMessageDist(m_Info[i],announce.c_str());
								}else if(diff == 10)
								{
									TCHAR remainSec[16];
									_itot_s(static_cast<int>(diff), remainSec, 16, 10);
									wstring announce = Utils::ReplaceString(m_Info[i].fightStartRemindMsg, _T("[param]"), remainSec);
									SendMessageDist(m_Info[i],announce.c_str());

									if(m_Info[i].m_managerServerId)
									{
										CNPC *pNpc = CNPC::GetNPCByServerId(&m_Info[i].m_managerServerId);
										CNPC *pNpc2 = CNPC::GetNPCByServerId(&m_Info[i].m_managerServerId2);
										if(pNpc)
										{
											if(pNpc->pSD->nAlive)
											{
												pNpc->KillNPC();
											}
										}else
											g_Log.Add(CLog::Error, "[%s] cannot find manager npc", __FUNCTION__);

										if(pNpc2)
										{
											if(pNpc2->pSD->nAlive)
											{
												pNpc2->KillNPC();
											}
										}else
											g_Log.Add(CLog::Error, "[%s] cannot find manager npc", __FUNCTION__);

										m_Info[i].m_managerServerId = 0;
										m_Info[i].m_managerServerId2 = 0;
									}

								}
								else if(diff < 6)
								{
									TCHAR remainSec[16];
									_itot_s(static_cast<int>(diff), remainSec, 16, 10);
									wstring announce = Utils::ReplaceString(m_Info[i].fightStartRemindMsg, _T("[param]"), remainSec);
									SendMessageDist(m_Info[i], announce.c_str());
								}
							}
						}else
						{
							SendMessageDist(m_Info[i], m_Info[i].fightStartRemindMsg2.c_str());
							m_Info[i].m_stateTime = time(NULL);
							m_Info[i].m_state = PartyEventStateFight;
						}

						continue;
					}
					else if(m_Info[i].m_state == PartyEventStateFight)
					{

					}
				}
			}



		}	
		Unlock();

	unguard;
}

void PartyEvents::MandarAPelear(PartyEquipo party1, PartyEquipo party2)
{
	int mapaDisponible = 0;
	for (size_t i = 0; i < m_Info.size(); ++i)
	{
		if (m_Info[i].m_state == PartyEventStateNone)
		{
			mapaDisponible = i;
			break;
		}
	}

	if(mapaDisponible != 0)
	{
		bool party1_cobrado = false;
		bool party2_cobrado = false;

		CParty *pParty1 = static_cast<CParty *>(CObject::GetObjectBySID(party1.m_ObjectID));
		if(pParty1->IsValidParty())
		{	
			if(party1.m_Cantidad == pParty1->memberCount)
			{
				if(pParty1->GetMaster()->DeleteItemInInventory(party1.m_ApuestaId, party1.m_ApuestaTotal))
				{
					party1_cobrado = true;
					UserVector vUsers;
					pParty1->GetAllMembersEx(vUsers);
					for(UINT n=0;n<vUsers.size();n++)
					{
						if(User *pMember = vUsers[n]->SafeCastUser())
						{
							if(!pMember->pSD->nAlive)
								pMember->ResurrectedBy(pMember, 100);

								PlayerAction::OnTeleportToLocation(pMember, m_Info[mapaDisponible].redPos[n].x, m_Info[mapaDisponible].redPos[n].y, m_Info[mapaDisponible].redPos[n].z, false);
								pMember->pSD->teamType = 1;
						}
					}
				}
			}
		}

		CParty *pParty2 = static_cast<CParty *>(CObject::GetObjectBySID(party2.m_ObjectID));
		if(pParty2->IsValidParty())
		{	
			if(party1.m_Cantidad == pParty1->memberCount)
			{
				if(pParty2->GetMaster()->DeleteItemInInventory(party2.m_ApuestaId, party2.m_ApuestaTotal))
				{
					party2_cobrado = true;
					UserVector vUsers;
					pParty2->GetAllMembersEx(vUsers);
					for(UINT n=0;n<vUsers.size();n++)
					{
						if(User *pMember = vUsers[n]->SafeCastUser())
						{
							if(!pMember->pSD->nAlive)
								pMember->ResurrectedBy(pMember, 100);

								PlayerAction::OnTeleportToLocation(pMember, m_Info[mapaDisponible].bluePos[n].x, m_Info[mapaDisponible].bluePos[n].y, m_Info[mapaDisponible].bluePos[n].z, false);
								pMember->pSD->teamType = 2;
						}
					}
				}
			}
		}

		m_Info[mapaDisponible].m_Party1 = party1;
		m_Info[mapaDisponible].m_Party2 = party2;
		m_Info[mapaDisponible].m_PremioId = party1.m_ApuestaId;
		m_Info[mapaDisponible].m_PremioTotal = party1.m_ApuestaTotal * 2;

	}
	else
	{
		//ESPERAR A QUE SE LIBERE UN MAPA
	}
}

void PartyEvents::SendMessageDist(PartyEventsInfo partyevent, const WCHAR* wAnnounce)
{
	CParty *pParty1 = static_cast<CParty *>(CObject::GetObjectBySID(partyevent.m_Party1.m_ObjectID));
	if(pParty1->IsValidParty())
	{	
		UserVector vUsers;
		pParty1->GetAllMembersEx(vUsers);
		for(UINT n=0;n<vUsers.size();n++)
		{
			if(User *pMember = vUsers[n]->SafeCastUser())
			{
				//ENVIAR MENSAJES INDIVIDUALES
			}
		}
	}

	CParty *pParty2 = static_cast<CParty *>(CObject::GetObjectBySID(partyevent.m_Party2.m_ObjectID));
	if(pParty2->IsValidParty())
	{	
		UserVector vUsers;
		pParty2->GetAllMembersEx(vUsers);
		for(UINT n=0;n<vUsers.size();n++)
		{
			if(User *pMember = vUsers[n]->SafeCastUser())
			{
				//ENVIAR MENSAJES INDIVIDUALES
			}
		}
	}


}

bool PartyEvents::CustomsBypass(User* pUser, wstring wBypass)
{
	if( wBypass.find(L"xxxxxxxxxxxxxxxx?") == 0)
	{
		return true;
	}else if(wBypass.find(L"partyevent_register?") == 0)
	{
		int nItemId = -1;

		if( wBypass.find(L"Adena") == 0)
			nItemId = 57;
		if( wBypass.find(L"Donation_Coin") == 0)
			nItemId = 9629;


		UINT apuesta = Parser::GetBypassValueInt(wBypass.c_str(), L"apuesta");

		if(CParty *pParty = pUser->GetParty())
		{
			if( pParty->GetMaster() == pUser )
			{

				for (std::vector<PartyEquipo>::iterator it = g_PartyEvents.m_Partys.begin(); it != g_PartyEvents.m_Partys.end(); ++it) {
					if (it->m_ObjectID == pUser->pSD->nPartyID) {
						g_PartyEvents.m_Partys.erase(it);
						CSystemMessage msg1(SystemMessage::S1_POPUP);
						msg1.AddText(L"Tu party ya se encuentra anotada.");
						pUser->pSocket->SendSystemMessage(&msg1);
						return true;
					}
				}

				if((nItemId > 0 && apuesta > 0))
				{
					if(!pUser->inventory.HaveItemByClassID(nItemId, apuesta))
					{
						CSystemMessage msg1(SystemMessage::S1_POPUP);
						msg1.AddText(L"No tienes los items necesarios para cubrir la apuesta.");
						pUser->pSocket->SendSystemMessage(&msg1);
						return true;
					}

					PartyEquipo equipo;
					equipo.m_state = Espera;

					equipo.m_ApuestaId = nItemId;
					equipo.m_ApuestaTotal = apuesta;
					equipo.m_ObjectID = pParty->nObjectID;
					equipo.m_Cantidad = pParty->memberCount;
					equipo.n_PartyLeader = pUser->pSD->wszName;

					g_PartyEvents.m_Partys.push_back(equipo);

					//MENSAJE QUE YA ESTAN ANOTADOS EN ESPERA
					CSystemMessage msg1(SystemMessage::S1_POPUP);
					msg1.AddText(L"Anotados, ahora deben esperar otra party con las mismas caracteristicas.");
					pUser->pSocket->SendSystemMessage(&msg1);
					return true;
				}
				else
				{
					CSystemMessage msg1(SystemMessage::S1_POPUP);
					msg1.AddText(L"El valor de la apuesta debe ser superior a 0.");
					pUser->pSocket->SendSystemMessage(&msg1);
					return true;
				}
			}
			else
			{
				CSystemMessage msg1(SystemMessage::S1_POPUP);
				msg1.AddText(L"Solo puede anotar el lider de la Party.");
				pUser->pSocket->SendSystemMessage(&msg1);
				return true;
			}
		}

		return true;
	}else if(wBypass.find(L"partyevent_unregister?") == 0)
	{
		UINT nPartyID = pUser->pSD->nPartyID;
		CParty *pParty = static_cast<CParty *>(CObject::GetObjectBySID(nPartyID));
		if(pParty->IsValidParty())
		{	
			for (std::vector<PartyEquipo>::iterator it = g_PartyEvents.m_Partys.begin(); it != g_PartyEvents.m_Partys.end(); ++it) {
				if (it->m_ObjectID == nPartyID) {
					g_PartyEvents.m_Partys.erase(it);
					CSystemMessage msg1(SystemMessage::S1_POPUP);
					msg1.AddText(L"Tu party se ha eliminado de la lista.");
					pUser->pSocket->SendSystemMessage(&msg1);
					break; 
				}
			}
		}

		return true;
	}else if(wBypass.find(L"partyevent_showhtml?") == 0)
	{

		return true;
	}

	return false;
}
