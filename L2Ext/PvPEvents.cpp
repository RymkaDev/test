#include "StdAfx.h"
#include "PvPEvents.h"
#include "TerritoryData.h"
#include "PlayerAction.h"
#include "HTMLCacheManager.h"
#include "HtmlCache.h"
#include "DB.h"

PvPEvents g_PvPEvents;

extern BOOL g_torneo;

void PvPEvents::Init()
{
	m_usersRegister.clear();
	enableRegister = false;
	HwidDetect = false;
	maxPlayers = 64;
	minPlayers = 2;
	registeredPlayers = 0;
	TorneoCategoria = CategoryAll;
	Ronda = 1;
	TorneoComenzado = false;
	n_EventID = 0;
	RequestLoadPvPEvent();
	SleepEntreCadaPeleaTemp=0;
	registroAutomatico = 0;

	inscripcionItemId = 0;
	inscripcionItemCount = 0;

	premioItemId = 0;
	premioItemCount = 0;

	LoadINI();
}

void PvPEvents::LoadINI()
{
	g_Log.Add(CLog::Blue, "[Load PvPEvents]");

	TCHAR sTemp[0x8000];

	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(_T("TORNEO_PVP"), _T("FightStartRemindMessage"), 0, sTemp, 8192, g_CustomConfigFile))
	{
		fightStartRemindMsg = sTemp;
	}
	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(_T("TORNEO_PVP"), _T("FightStartRemindMessage2"), 0, sTemp, 8192, g_CustomConfigFile))
	{
		fightStartRemindMsg2 = sTemp;
	}
	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(_T("TORNEO_PVP"), _T("RegistrationStartMessage1"), 0, sTemp, 8192, g_CustomConfigFile))
	{
		RegistrationStartMessage1 = sTemp;
	}
	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(_T("TORNEO_PVP"), _T("RegistrationStartMessage2"), 0, sTemp, 8192, g_CustomConfigFile))
	{
		RegistrationStartMessage2 = sTemp;
	}
	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(_T("TORNEO_PVP"), _T("RegistrationRemindMessage"), 0, sTemp, 8192, g_CustomConfigFile))
	{
		RegistrationRemindMessage = sTemp;
	}
	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(_T("TORNEO_PVP"), _T("RegistrationEndMessage"), 0, sTemp, 8192, g_CustomConfigFile))
	{
		RegistrationEndMessage = sTemp;
	}
	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(_T("TORNEO_PVP"), _T("EndMessage"), 0, sTemp, 8192, g_CustomConfigFile))
	{
		EndMessage = sTemp;
	}
	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(_T("TORNEO_PVP"), _T("RegistratrionNontEnoughParticipants"), 0, sTemp, 8192, g_CustomConfigFile))
	{
		RegistratrionNontEnoughParticipants = sTemp;
	}
	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(_T("TORNEO_PVP"), _T("PreparationStartMessage"), 0, sTemp, 8192, g_CustomConfigFile))
	{
		PreparationStartMessage = sTemp;
	}
	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(_T("TORNEO_PVP"), _T("PaseLibreMsg"), 0, sTemp, 8192, g_CustomConfigFile))
	{
		PaseLibreMsg = sTemp;
	}
	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(_T("TORNEO_PVP"), _T("PreparationRemindMessage"), 0, sTemp, 8192, g_CustomConfigFile))
	{
		PreparationRemindMessage = sTemp;
	}
	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(_T("TORNEO_PVP"), _T("NingunoDeLosPeronajesOnlineMsg"), 0, sTemp, 8192, g_CustomConfigFile))
	{
		NingunoDeLosPeronajesOnlineMsg = sTemp;
	}
	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(_T("TORNEO_PVP"), _T("PeronajesCharNo1OnlineMsg"), 0, sTemp, 8192, g_CustomConfigFile))
	{
		PeronajesCharNo1OnlineMsg = sTemp;
	}
	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(_T("TORNEO_PVP"), _T("PeronajesCharNo2OnlineMsg"), 0, sTemp, 8192, g_CustomConfigFile))
	{
		PeronajesCharNo2OnlineMsg = sTemp;
	}


	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(_T("TORNEO_PVP"), _T("PDescalificadoPor1HwidMsg"), 0, sTemp, 8192, g_CustomConfigFile))
	{
		PDescalificadoPor1HwidMsg = sTemp;
	}
	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(_T("TORNEO_PVP"), _T("PDescalificadoPor2HwidMsg"), 0, sTemp, 8192, g_CustomConfigFile))
	{
		PDescalificadoPor2HwidMsg = sTemp;
	}

	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(_T("TORNEO_PVP"), _T("HaGanadoLaPeleaPorDanioMsg"), 0, sTemp, 8192, g_CustomConfigFile))
	{
		HaGanadoLaPeleaPorDanioMsg = sTemp;
	}




	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(_T("TORNEO_PVP"), _T("ProximaPeleaMsg"), 0, sTemp, 8192, g_CustomConfigFile))
	{
		ProximaPeleaMsg = sTemp;
	}
	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(_T("TORNEO_PVP"), _T("HaGanadoLaPeleaMsg"), 0, sTemp, 8192, g_CustomConfigFile))
	{
		HaGanadoLaPeleaMsg = sTemp;
	}
	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(_T("TORNEO_PVP"), _T("HaSalidoCampeonMsg"), 0, sTemp, 8192, g_CustomConfigFile))
	{
		HaSalidoCampeonMsg = sTemp;
	}


	

	m_SuperBuffTimestamp = GetPrivateProfileInt(_T("TORNEO_PVP"), _T("SuperSkill_Time"), 30, g_CustomConfigFile);
	m_SuperBuffId = GetPrivateProfileInt(_T("TORNEO_PVP"), _T("SuperSkill_Id"), 30, g_CustomConfigFile);
	m_SuperBuffLevel = GetPrivateProfileInt(_T("TORNEO_PVP"), _T("SuperSkill_Level"), 30, g_CustomConfigFile);

	maxPlayers = GetPrivateProfileInt(_T("TORNEO_PVP"), _T("MaxUsers"), 32, g_CustomConfigFile);
	minPlayers = GetPrivateProfileInt(_T("TORNEO_PVP"), _T("MinUsers"), 2, g_CustomConfigFile);

	MinLevel = GetPrivateProfileInt(_T("TORNEO_PVP"), _T("MinLevel"), 75, g_CustomConfigFile);

	RegisterTime = GetPrivateProfileInt(_T("TORNEO_PVP"), _T("RegisterTime"), 300, g_CustomConfigFile);
	countDownTime = GetPrivateProfileInt(_T("TORNEO_PVP"), _T("CountDownTime"), 30, g_CustomConfigFile);
	fightTime = GetPrivateProfileInt(_T("TORNEO_PVP"), _T("FightTime"), 300, g_CustomConfigFile);

	prepareTime = GetPrivateProfileInt(_T("TORNEO_PVP"), _T("prepareTime"), 60, g_CustomConfigFile);

	SleepEntreCadaPelea = GetPrivateProfileInt(_T("TORNEO_PVP"), _T("SleepEntreCadaPelea"), 10, g_CustomConfigFile);
	

	BufferNpcClassId = GetPrivateProfileInt(_T("TORNEO_PVP"), _T("BufferClassId"), 0, g_CustomConfigFile);


	HwidDetect = GetPrivateProfileInt(_T("TORNEO_PVP"), _T("ControlHWID"), 0, g_CustomConfigFile);

	TorneoCategoria = GetPrivateProfileInt(_T("TORNEO_PVP"), _T("TorneoCategoria"), 0, g_CustomConfigFile);

	sumarpuntos_torneo = GetPrivateProfileInt(_T("TORNEO_PVP"), _T("SumarPuntosTorneo"), 0, g_CustomConfigFile);

	
	inscripcionItemId = GetPrivateProfileInt(_T("TORNEO_PVP"), _T("inscripcionItemId"), 0, g_CustomConfigFile);
	inscripcionItemCount = GetPrivateProfileInt(_T("TORNEO_PVP"), _T("inscripcionItemCount"), 0, g_CustomConfigFile);
	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(_T("TORNEO_PVP"), _T("inscripcionItemName"), 0, sTemp, 8192, g_CustomConfigFile))
	{
		inscripcionItemName = sTemp;
	}
	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(_T("TORNEO_PVP"), _T("inscripcionItemIcon"), 0, sTemp, 8192, g_CustomConfigFile))
	{
		inscripcionItemIcon = sTemp;
	}


	premioItemId = GetPrivateProfileInt(_T("TORNEO_PVP"), _T("premioItemId"), 0, g_CustomConfigFile);
	premioItemCount = GetPrivateProfileInt(_T("TORNEO_PVP"), _T("premioItemCount"), 0, g_CustomConfigFile);
	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(_T("TORNEO_PVP"), _T("premioItemName"), 0, sTemp, 8192, g_CustomConfigFile))
	{
		premioItemName = sTemp;
	}
	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(_T("TORNEO_PVP"), _T("premioItemIcon"), 0, sTemp, 8192, g_CustomConfigFile))
	{
		premioItemIcon = sTemp;
	}


	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(_T("TORNEO_PVP"), _T("KickOutPos"), 0, sTemp, 8192, g_CustomConfigFile))
	{
		tstring pos = sTemp;
		pos = Utils::ReplaceString(pos, _T("/"), _T(" "), true);
		tstringstream sstr;
		sstr << pos;
		sstr >> kickOutPos.x >> kickOutPos.y >> kickOutPos.z;
	}

	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(_T("TORNEO_PVP"), _T("BufferPos_1"), 0, sTemp, 8192, g_CustomConfigFile))
	{
		tstring pos = sTemp;
		pos = Utils::ReplaceString(pos, _T("/"), _T(" "), true);
		tstringstream sstr;
		sstr << pos;
		sstr >> buffer1_Pos.x >> buffer1_Pos.y >> buffer1_Pos.z;
	}

	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(_T("TORNEO_PVP"), _T("BufferPos_2"), 0, sTemp, 8192, g_CustomConfigFile))
	{
		tstring pos = sTemp;
		pos = Utils::ReplaceString(pos, _T("/"), _T(" "), true);
		tstringstream sstr;
		sstr << pos;
		sstr >> buffer2_Pos.x >> buffer2_Pos.y >> buffer2_Pos.z;
	}


	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(_T("TORNEO_PVP"), _T("Player1_Pos"), 0, sTemp, 8192, g_CustomConfigFile))
	{
		tstring pos = sTemp;
		pos = Utils::ReplaceString(pos, _T("/"), _T(" "), true);
		tstringstream sstr;
		sstr << pos;
		sstr >> Player1_Pos.x >> Player1_Pos.y >> Player1_Pos.z;
	}

	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(_T("TORNEO_PVP"), _T("Player2_Pos"), 0, sTemp, 8192, g_CustomConfigFile))
	{
		tstring pos = sTemp;
		pos = Utils::ReplaceString(pos, _T("/"), _T(" "), true);
		tstringstream sstr;
		sstr << pos;
		sstr >> Player2_Pos.x >> Player2_Pos.y >> Player2_Pos.z;
	}



	registroAutomatico = GetPrivateProfileInt(_T("TORNEO_PVP"), _T("registroAutomatico"), FALSE, g_CustomConfigFile);
	if(registroAutomatico)
	{
		HabilitarRegistroAutomatico();
	}
	else
	{
		TerminarTorneo();
	}
}


void PvPEvents::HabilitarRegistro()
{
	m_stateTime = time(NULL);
	enableRegister = true;
	m_lpEvent = true;
	m_state = StateRegistration;

	RequestLoadPvPEvent();

//	n_EventID++;
	m_usersRegister.clear();
	m_usersRounds.clear();
	registeredPlayers = 0;
	Ronda = 1;
	TorneoComenzado = false;

	inscripcionItemId = 0;
	inscripcionItemCount = 0;

	premioItemId = 0;
	premioItemCount = 0;

	Utils::BroadcastToAllUser_Announce(RegistrationStartMessage1.c_str());
	Utils::BroadcastToAllUser_Announce(RegistrationStartMessage2.c_str());
}

void PvPEvents::HabilitarRegistroAutomatico()
{
	m_stateTime = time(NULL);
	m_lpEvent = true;
	m_state = StateRegistrationAutomatico;
	RequestLoadPvPEvent();

	m_usersRegister.clear();
	m_usersRounds.clear();
	registeredPlayers = 0;
	Ronda = 1;
	TorneoComenzado = false;
}


void PvPEvents::CerrarRegistro()
{
	enableRegister = false;
	m_state = StatePrepararInicioTorneo;
}

void PvPEvents::TerminarTorneo()
{
	enableRegister = false;
	m_lpEvent = false;
	m_usersRegister.clear();
	m_usersRounds.clear();
	registeredPlayers = 0;
}


void PvPEvents::SetMaxPlayers(int maxUsers)
{
	maxPlayers = maxUsers;
}

void PvPEvents::SetMinPlayers(int minUsers)
{
	minPlayers = minUsers;
}

void PvPEvents::TimerExpired()
{
	guard; 
		Lock();
		if(m_lpEvent)
		{
			time_t currentTime = time(NULL);

			switch(m_state)
			{
			case StateRegistration:
				{
					time_t diff = m_stateTime + RegisterTime;
					diff -= currentTime;
					if(diff > 0)
					{
						if(RegistrationRemindMessage.size() > 0)
						{
							if(diff == 60)
							{
								TCHAR remainSec[16];
								_itot_s(static_cast<int>(diff), remainSec, 16, 10);
								wstring announce = Utils::ReplaceString(RegistrationRemindMessage, _T("[param]"), remainSec);
								Utils::BroadcastToAllUser_Announce(announce.c_str());
							}else if(diff == 30)
							{
								TCHAR remainSec[16];
								_itot_s(static_cast<int>(diff), remainSec, 16, 10);
								wstring announce = Utils::ReplaceString(RegistrationRemindMessage, _T("[param]"), remainSec);
								Utils::BroadcastToAllUser_Announce(announce.c_str());
							}else if(diff == 10)
							{
								TCHAR remainSec[16];
								_itot_s(static_cast<int>(diff), remainSec, 16, 10);
								wstring announce = Utils::ReplaceString(RegistrationRemindMessage, _T("[param]"), remainSec);
								Utils::BroadcastToAllUser_Announce(announce.c_str());
							}
						}

					}
					else
					{
						CerrarRegistro();
						
						if(RegistrationEndMessage.size() > 0)
						{
							Utils::BroadcastToAllUser_Announce(RegistrationEndMessage.c_str());
						}

						if(minPlayers > 0 && minPlayers > m_usersRegister.size())
						{
							if(RegistratrionNontEnoughParticipants.size() > 0)
							{
								Utils::BroadcastToAllUser_Announce(RegistratrionNontEnoughParticipants.c_str());
							}
							m_state = StateDelete;
							break;
						}

						m_stateTime = time(NULL);
						m_state = StateGenerarFixture;
					}
					break;
				}
			case StateRegistrationAutomatico:
				{
					time_t diff = m_stateTime + 30;
					diff -= currentTime;
					if(diff > 0)
					{
						if(diff == 1)
						{
							int contador = 0;
	
							m_Lock.Enter();
							for (vector<pair<wstring, PVPUser>>::iterator it = m_usersRegister.begin(); it != m_usersRegister.end();) {
								bool condicion_para_borrar = false;
								User* pUser = g_UserDB.GetUserByDBID(it->second.charId)->SafeCastUser();
								if(pUser->ValidUser())
								{
									if(contador < maxPlayers)
									{
										if(pUser->pSD->activateOfflineShopTime == 0)
										{
											if(pUser->inventory.HaveItemByClassID(inscripcionItemId, inscripcionItemCount))
												contador++;
											else
												condicion_para_borrar = true;
										}
										else
											condicion_para_borrar = true;
									}
									else
										condicion_para_borrar = true;
								}
								else
									condicion_para_borrar = true;

								if (condicion_para_borrar) {
									it = m_usersRegister.erase(it);
									registeredPlayers -= 1;
								} else {
									++it;
								}
							}
							m_Lock.Leave();

							if(contador == maxPlayers)
							{
								CerrarRegistro();

								if(RegistrationEndMessage.size() > 0)
								{
									Utils::BroadcastToAllUser_Announce(RegistrationEndMessage.c_str());
								}

								m_Lock.Enter();
								for (vector<pair<wstring, PVPUser>>::iterator it = m_usersRegister.begin(); it != m_usersRegister.end(); ++it) {
									User* pUser = g_UserDB.GetUserByDBID(it->second.charId)->SafeCastUser();
									if(pUser->ValidUser())
									{
										if(pUser->DeleteItemInInventory(inscripcionItemId, inscripcionItemCount))
										{
											g_Logger.Add(L"User[%s] Pago Inscripcion Torneo ItemId[%d] Count[%d]", pUser->pSD->wszName, inscripcionItemId, inscripcionItemCount);
										}
										else
										{
											g_Logger.Add(L"User[%s] !!!NO!!! Pago Inscripcion Torneo ItemId[%d] Count[%d]", pUser->pSD->wszName, inscripcionItemId, inscripcionItemCount);
										}

										PlayerAction::OnTeleportToLocation(pUser, kickOutPos.x, kickOutPos.y, kickOutPos.z, false);
									}
								}
								m_Lock.Leave();


								m_stateTime = time(NULL);
								m_state = StateGenerarFixture;
							}
						}
					}
					else
					{
						m_stateTime = time(NULL);
						m_state = StateRegistrationAutomatico;
					}
					break;
				}
			case StateGenerarFixture:
				{
					time_t diff = m_stateTime + prepareTime;

					diff -= currentTime;

					if(diff > 0)
					{
						if(PreparationRemindMessage.size() > 0)
						{
							if(diff == prepareTime-1)
							{
								std::vector<std::pair<std::wstring, PVPUser> > shuffledMap = m_usersRegister;
								std::vector<std::pair<std::wstring, PVPUser> > elements;

								for (vector<pair<wstring, PVPUser>>::iterator it = shuffledMap.begin(); it != shuffledMap.end(); ++it) {
									elements.push_back(*it);
								}


								std::srand(static_cast<unsigned int>(time(0)));
								std::random_shuffle(elements.begin(), elements.end());

								int cont = 0;

								for (std::vector<std::pair<std::wstring, PVPUser> >::iterator it = elements.begin(); it != elements.end(); ++it) {
									cont++;
									it->second.pos = cont;
									m_usersRounds.push_back(*it);
									RequestSavePvPEvent(it->second.charId, it->second.ronda, it->second.descalificado, it->second.pos);
									Sleep(20);
								}

								m_Lock.Enter();
								m_usersGrillaClientes = m_usersRounds;
								m_Lock.Leave();

								TCHAR FixtureSec[16];
								_itot_s(static_cast<int>(m_usersGrillaClientes.size()), FixtureSec, 16, 10);
								wstring announce = Utils::ReplaceString(L"2902;;;EventPvP: Se ha formado el Fixture con [param] participantes.", _T("[param]"), FixtureSec);
								SendMessageDist(announce.c_str());
								UpdateFixture = true;

							}
							else if(diff == 28)
							{
								TCHAR remainSec[16];
								_itot_s(static_cast<int>(diff), remainSec, 16, 10);
								wstring announce = Utils::ReplaceString(PreparationRemindMessage, _T("[param]"), 30);
								SendMessageDist(announce.c_str());
							}else if(diff == 10)
							{
								TCHAR remainSec[16];
								_itot_s(static_cast<int>(diff), remainSec, 16, 10);
								wstring announce = Utils::ReplaceString(PreparationRemindMessage, _T("[param]"), remainSec);
								SendMessageDist(announce.c_str());
							}
							else if(diff == 5)
							{
								TCHAR remainSec[16];
								_itot_s(static_cast<int>(diff), remainSec, 16, 10);
								wstring announce = Utils::ReplaceString(PreparationRemindMessage, _T("[param]"), remainSec);
								SendMessageDist(announce.c_str());
							}
						}
					}
					else
					{
						m_stateTime = time(NULL);
						m_state = StatePrepararInicioTorneo;
					}
					break;
				}
			case StatePrepararInicioTorneo:
				{
					time_t diff = m_stateTime + SleepEntreCadaPelea;
					diff -= currentTime;

					if(diff == 0)
					{
						TorneoComenzado = true;
						
						peleador1 = NULL;
						peleador2 = NULL;
						peleador1W = L"";
						peleador2W = L"";

						int countZeroValues = 0;
						for (std::vector<std::pair<std::wstring, PVPUser> >::iterator it = m_usersRounds.begin(); it != m_usersRounds.end(); ++it) {
							if (it->second.ronda == Ronda && countZeroValues < 2 && !it->second.descalificado) {
								++countZeroValues;
								if(countZeroValues == 1)
								{
									User* pUser = g_UserDB.GetUserByDBID(it->second.charId)->SafeCastUser();
									if(pUser->ValidUser())
									{
										if(pUser->pSD->activateOfflineShopTime == 0)
										{
											peleador1 = g_UserDB.GetUserByDBID(it->second.charId)->SafeCastUser();

											if(peleador1->pSD->nIsObserver)
											{
												PlayerAction::ObserverEnd(peleador1);
											}
										}
									}

									peleador1W = it->first;
								}
								else if (countZeroValues == 2)
								{
									User* pUser = g_UserDB.GetUserByDBID(it->second.charId)->SafeCastUser();
									if(pUser->ValidUser())
									{
										if(pUser->pSD->activateOfflineShopTime == 0)
											peleador2 = g_UserDB.GetUserByDBID(it->second.charId)->SafeCastUser();

											if(peleador2->pSD->nIsObserver)
											{
												PlayerAction::ObserverEnd(peleador2);
											}
									}

									peleador2W = it->first;
								}
							}
						}

						//g_Log.Add(CLog::Error, "[%s] countZeroValues[%d]", __FUNCTION__, countZeroValues);
						if (countZeroValues == 0)		//PASAR DE RONDA O VERIFICAR SI ES EL CAMPEON
						{
							
							Ronda++;
							User* pUserWinner = NULL;

							int TestcountZeroValues = 0;
							for (std::vector<std::pair<std::wstring, PVPUser> >::iterator it = m_usersRounds.begin(); it != m_usersRounds.end(); ++it) {
								if (it->second.ronda == Ronda && !it->second.descalificado) {
									++TestcountZeroValues;
									pUserWinner = g_UserDB.GetUserByDBID(it->second.charId)->SafeCastUser();
								}
							}

							int TestcountZeroValues2 = 0;
							for (std::vector<std::pair<std::wstring, PVPUser> >::iterator it = m_usersRounds.begin(); it != m_usersRounds.end(); ++it) {
								if (it->second.ronda == Ronda-1 && !it->second.descalificado) {
									++TestcountZeroValues2;
								}
							}

							if(TestcountZeroValues == 1 && TestcountZeroValues2 == 0)
							{
								wstring m_Message = HaSalidoCampeonMsg;
								size_t pos = m_Message.find(L"$charName");
								while(pos != wstring::npos)
								{
									m_Message = m_Message.replace(pos, 9, UltimoGanador);
									pos = m_Message.find(L"$charName");
								}
									
								if(premioItemId > 0 && premioItemCount > 0)
								{
									if(pUserWinner->ValidUser())
									{
										pUserWinner->AddItemToInventory(premioItemId, premioItemCount);
										g_Logger.Add(L"User[%s] Salio Campeon y cobro ItemId[%d] Count[%d]", pUserWinner->pSD->wszName, premioItemId, premioItemCount);
									}
									else
									{
										g_Logger.Add(L"User[%s] Salio Campeon PERO no cobro ItemId[%d] Count[%d]", UltimoGanador.c_str(), premioItemId, premioItemCount);
									}
								}

								Utils::BroadcastToAllUser_Announce(m_Message.c_str());

								if(registroAutomatico)
								{
									HabilitarRegistroAutomatico();
								}
								else
								{
									TerminarTorneo();
								}

							}
							else
							{
								TCHAR RondaSec[16];
								_itot_s(static_cast<int>(Ronda), RondaSec, 16, 10);
								wstring announce = Utils::ReplaceString(L"2902;;;EventPvP: Pasamos a la ronda numero [param].", _T("[param]"), RondaSec);
								SendMessageDist(announce.c_str());
								m_stateTime = time(NULL);
							}
						}
						else if(countZeroValues == 1)	//HACER PASE LIBRE
						{
							EnviarAnnouncePeleaCancelada(PaseLibreMsg);
							UserPasarDeRonda(peleador1W);
							m_stateTime = time(NULL);
						}
						else if(countZeroValues == 2)	//ENVIAR A PELEAR
						{
							if(peleador1->ValidUser() && peleador2->ValidUser())
							{
								//g_Log.Add(CLog::Error, "[%s] peleador1->ValidUser() && peleador2->ValidUser()", __FUNCTION__);
								if(DetectarHwid(peleador1, peleador1W) && DetectarHwid(peleador2, peleador2W))
								{
									EnviarAPelear(peleador1, peleador2);
								}
								else if(!DetectarHwid(peleador1, peleador1W) && !DetectarHwid(peleador2, peleador2W))
								{
									wstring m_Message = L"";
									m_Message = PDescalificadoPor1HwidMsg;
									size_t pos = m_Message.find(L"$char1");
									while(pos != wstring::npos)
									{
										m_Message = m_Message.replace(pos, 6, peleador1W);
										pos = m_Message.find(L"$char1");
									}

									SendMessageDist(m_Message.c_str());

									UserDescalificar(peleador1W);
									UserDescalificar(peleador2W);
									m_stateTime = time(NULL);
								}
								else if(!DetectarHwid(peleador1, peleador1W) && DetectarHwid(peleador2, peleador2W))
								{
									wstring m_Message = L"";
									m_Message = PDescalificadoPor1HwidMsg;
									size_t pos = m_Message.find(L"$char1");
									while(pos != wstring::npos)
									{
										m_Message = m_Message.replace(pos, 6, peleador1W);
										pos = m_Message.find(L"$char1");
									}

									SendMessageDist(m_Message.c_str());


									UserDescalificar(peleador1W);
									UserPasarDeRonda(peleador2W);
									m_stateTime = time(NULL);
								}
								else if(DetectarHwid(peleador1, peleador1W) && !DetectarHwid(peleador2, peleador2W))
								{
									wstring m_Message = L"";
									m_Message = PDescalificadoPor1HwidMsg;
									size_t pos = m_Message.find(L"$char1");
									while(pos != wstring::npos)
									{
										m_Message = m_Message.replace(pos, 6, peleador2W);
										pos = m_Message.find(L"$char1");
									}

									SendMessageDist(m_Message.c_str());

									UserDescalificar(peleador2W);
									UserPasarDeRonda(peleador1W);
									m_stateTime = time(NULL);
								}

							}
							else if(!peleador1->ValidUser() && peleador2->ValidUser())
							{
								//g_Log.Add(CLog::Error, "[%s] else if(!peleador1->ValidUser() && peleador2->ValidUser())", __FUNCTION__);
								//m_Message = L"Evento: La pelea de $char1 y $char2 se cancelo, Y gano $char2 porque $char1 no esta online.";
								EnviarAnnouncePeleaCancelada(PeronajesCharNo1OnlineMsg);
								UserDescalificar(peleador1W);
								UserPasarDeRonda(peleador2W);
								m_stateTime = time(NULL);
							}
							else if(peleador1->ValidUser() && !peleador2->ValidUser())
							{
								//g_Log.Add(CLog::Error, "[%s] else if(peleador1->ValidUser() && !peleador2->ValidUser())", __FUNCTION__);
								//m_Message = L"Evento: La pelea de $char1 y $char2 se cancelo, Y gano $char2 porque $char1 no esta online.";
								EnviarAnnouncePeleaCancelada(PeronajesCharNo2OnlineMsg);
								UserDescalificar(peleador2W);
								UserPasarDeRonda(peleador1W);
								m_stateTime = time(NULL);
							}
							else if(!peleador1->ValidUser() && !peleador2->ValidUser())
							{
								//g_Log.Add(CLog::Error, "[%s] else if(!peleador1->ValidUser() && !peleador2->ValidUser())", __FUNCTION__);
								//m_Message = L"Evento: La pelea de $char1 y $char2 se cancelo, ninguno de los dos personajes esta online.";
								EnviarAnnouncePeleaCancelada(NingunoDeLosPeronajesOnlineMsg);
								UserDescalificar(peleador1W);
								UserDescalificar(peleador2W);
								m_stateTime = time(NULL);
							}
							else
							{
								g_Log.Add(CLog::Error, "[%s] ENTRO EN LA NADA MISMA", __FUNCTION__);
								m_stateTime = time(NULL);
							}
						}
						else
						{
							g_Log.Add(CLog::Error, "[%s] ENTRO EN LA NADA MISMA 2", __FUNCTION__);
						}
					}

					break;
				}
			case StatePrepare:
				{
					if(BufferNpcClassId)
					{
						map<wstring, wstring> aiParams;
						aiParams.insert(pair<wstring, wstring>(L"fnHi", L"buffer_npc_torneo.htm"));
						m_managerServerId = NpcServer::SpawnNpcEx(BufferNpcClassId, buffer1_Pos.x, buffer1_Pos.y, buffer1_Pos.z, aiParams);
						m_managerServerId2 = NpcServer::SpawnNpcEx(BufferNpcClassId, buffer2_Pos.x, buffer2_Pos.y, buffer2_Pos.z, aiParams);
					}

					m_stateTime = time(NULL);
					m_state = StateCountDown;
					break;
				}
			case StateCountDown:
				{
					time_t diff = m_stateTime + countDownTime;
					diff -= currentTime;
					if(diff > 0)
					{
						if(fightStartRemindMsg.size() > 0)
						{
							if(diff == 60)
							{
								TCHAR remainSec[16];
								_itot_s(static_cast<int>(diff), remainSec, 16, 10);
								wstring announce = Utils::ReplaceString(fightStartRemindMsg, _T("[param]"), remainSec);
								SendMessageDist(announce.c_str());
							}else if(diff == 30)
							{
								TCHAR remainSec[16];
								_itot_s(static_cast<int>(diff), remainSec, 16, 10);
								wstring announce = Utils::ReplaceString(fightStartRemindMsg, _T("[param]"), remainSec);
								SendMessageDist(announce.c_str());
							}else if(diff == 15)
							{
								TCHAR remainSec[16];
								_itot_s(static_cast<int>(diff), remainSec, 16, 10);
								wstring announce = Utils::ReplaceString(fightStartRemindMsg, _T("[param]"), remainSec);
								SendMessageDist(announce.c_str());
							}else if(diff == 10)
							{
								TCHAR remainSec[16];
								_itot_s(static_cast<int>(diff), remainSec, 16, 10);
								wstring announce = Utils::ReplaceString(fightStartRemindMsg, _T("[param]"), remainSec);
								SendMessageDist(announce.c_str());

								if(m_managerServerId)
								{
									CNPC *pNpc = CNPC::GetNPCByServerId(&m_managerServerId);
									CNPC *pNpc2 = CNPC::GetNPCByServerId(&m_managerServerId2);
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

									m_managerServerId = 0;
									m_managerServerId2 = 0;
								}

							}
							else if(diff < 6)
							{
								TCHAR remainSec[16];
									_itot_s(static_cast<int>(diff), remainSec, 16, 10);
									wstring announce = Utils::ReplaceString(fightStartRemindMsg, _T("[param]"), remainSec);
									SendMessageDist(announce.c_str());
							}
						}
					}else
					{
						if(EnCondicionesDePelear())
						{
							SendMessageDist(fightStartRemindMsg2.c_str());
							m_stateTime = time(NULL);
							m_state = StateFight;
						}
						else
						{
							m_stateTime = time(NULL);
							m_state = StatePrepararInicioTorneo;
						}
					}
					break;
				}
			case StateFight:
				{
					time_t diff = m_stateTime + fightTime;
					diff -= currentTime;
					if(diff > 0)
					{
						//HACER ALGO DURANTE LA PELEA
						if(!EnCondicionesDePelear())
						{
							m_stateTime = time(NULL);
							m_state = StatePrepararInicioTorneo;
						}
					}else
					{
						m_stateTime = time(NULL);
						m_state = StateFinish;
					}
					break;
				}
			case StateFinish:
				{
					time_t diff = m_stateTime + 8;
					diff -= currentTime;
					if(diff > 0)
					{
						if(diff == 7)
						{
							if(peleador1->ValidUser() && peleador2->ValidUser())
							{
								peleador1->pED->inEventPvpLocked = true;
								peleador2->pED->inEventPvpLocked = true;

								int player1_hp = static_cast<int>((int)peleador1->pSD->fHP);
								int player2_hp = static_cast<int>((int)peleador2->pSD->fHP);

								int player1_damage = static_cast<int>((int)peleador1->pED->EventPvpDanio);
								int player2_damage = static_cast<int>((int)peleador2->pED->EventPvpDanio);

								if(peleador1->pED->inEventPvp && peleador2->pED->inEventPvp)
								{
									if(player1_hp > 0 && player2_hp > 0)
									{
										if (player1_damage > player2_damage)
										{
											OnDie(peleador2, peleador1, true);

											std::wstringstream ss1;
											ss1 << player1_damage; 
											std::wstringstream ss2;
											ss2 << player2_damage; 

											wstring m_Message = HaGanadoLaPeleaPorDanioMsg;
											size_t pos = m_Message.find(L"$val1");
											while(pos != wstring::npos)
											{
												m_Message = m_Message.replace(pos, 5, ss1.str());
												pos = m_Message.find(L"$val1");
											}

											pos = m_Message.find(L"$val2");
											while(pos != wstring::npos)
											{
												m_Message = m_Message.replace(pos, 5, ss2.str());
												pos = m_Message.find(L"$val2");
											}
											SendMessageDist(m_Message.c_str());

										}
										else
										{
											OnDie(peleador1, peleador2, true);

											std::wstringstream ss1;
											ss1 << player1_damage; 
											std::wstringstream ss2;
											ss2 << player2_damage; 

											wstring m_Message = HaGanadoLaPeleaPorDanioMsg;
											size_t pos = m_Message.find(L"$val1");
											while(pos != wstring::npos)
											{
												m_Message = m_Message.replace(pos, 5, ss2.str());
												pos = m_Message.find(L"$val1");
											}

											pos = m_Message.find(L"$val2");
											while(pos != wstring::npos)
											{
												m_Message = m_Message.replace(pos, 5, ss1.str());
												pos = m_Message.find(L"$val2");
											}
											SendMessageDist(m_Message.c_str());
										}
									}
								}
							}
						}
					}
					else
					{
						if(peleador1->ValidUser())
						{
							peleador1->pED->EventPvpDanio = 0;
							peleador1->pED->inEventPvp = 0;

							peleador1->pED->inEventPvpLocked = false;
							PlayerAction::OnTeleportToLocation(peleador1, kickOutPos.x, kickOutPos.y, kickOutPos.z, false);
							peleador1->ResurrectedBy(peleador1, 100);
							peleador1->SetUserInfoChanged();
							peleador1->SetCharInfoChanged();

							peleador1->CastCreature()->abnormalStatusLock.Lock(__FILEW__, __LINE__);
							for(AbnormalDataVector::iterator Iter = peleador1->CastCreature()->vAbnormalStatus.begin();Iter!=peleador1->CastCreature()->vAbnormalStatus.end();Iter++)
							{
								if(Iter->pSI)
								{
									if(Iter->pSI->nAbnormalType == 181)	// 181 = hide_buff
									{
										peleador1->CastCreature()->pSD->DeleteAbnormalStatus(Iter->pSI->nAbnormalType);
										peleador1->CastCreature()->vAbnormalStatus.erase(Iter);
										peleador1->CastCreature()->lpSharedDataLock->Lock(__FILEW__, __LINE__);
										peleador1->CastCreature()->ValidateAllOnSIM();
										peleador1->CastCreature()->lpSharedDataLock->Unlock();
										peleador1->CastCreature()->broadcastInfoPacket = true;
										peleador1->CastCreature()->CheckAbnormalVisualEffect();

										peleador1->RequestUpdateSpelledInfo();
										peleador1->SendAbnormalStatusInfo();
										peleador1->SetUserInfoChanged();
										peleador1->SetCharInfoChanged();
										break;
									}
								}
							}
							peleador1->CastCreature()->abnormalStatusLock.Unlock();
						}

						if(peleador2->ValidUser())
						{
							peleador2->pED->EventPvpDanio = 0;
							peleador2->pED->inEventPvp = 0;

							peleador2->pED->inEventPvpLocked = false;
							PlayerAction::OnTeleportToLocation(peleador2, kickOutPos.x, kickOutPos.y, kickOutPos.z, false);
							peleador2->ResurrectedBy(peleador2, 100);
							peleador2->SetUserInfoChanged();
							peleador2->SetCharInfoChanged();

							peleador2->CastCreature()->abnormalStatusLock.Lock(__FILEW__, __LINE__);
							for(AbnormalDataVector::iterator Iter = peleador2->CastCreature()->vAbnormalStatus.begin();Iter!=peleador2->CastCreature()->vAbnormalStatus.end();Iter++)
							{
								if(Iter->pSI)
								{
									if(Iter->pSI->nAbnormalType == 181)	// 181 = hide_buff
									{
										peleador2->CastCreature()->pSD->DeleteAbnormalStatus(Iter->pSI->nAbnormalType);
										peleador2->CastCreature()->vAbnormalStatus.erase(Iter);
										peleador2->CastCreature()->lpSharedDataLock->Lock(__FILEW__, __LINE__);
										peleador2->CastCreature()->ValidateAllOnSIM();
										peleador2->CastCreature()->lpSharedDataLock->Unlock();
										peleador2->CastCreature()->broadcastInfoPacket = true;
										peleador2->CastCreature()->CheckAbnormalVisualEffect();

										peleador2->RequestUpdateSpelledInfo();
										peleador2->SendAbnormalStatusInfo();
										peleador2->SetUserInfoChanged();
										peleador2->SetCharInfoChanged();
										break;
									}
								}
							}
							peleador2->CastCreature()->abnormalStatusLock.Unlock();
						}

						m_stateTime = time(NULL);
						m_state = StatePrepararInicioTorneo;
					}
					break;
				}
			}
		}
		Unlock();

	unguard;
}

void PvPEvents::EnviarAnnouncePeleaCancelada(wstring m_Message)
{
	size_t pos = m_Message.find(L"$char1");
	while(pos != wstring::npos)
	{
		m_Message = m_Message.replace(pos, 6, peleador1W);
		pos = m_Message.find(L"$char1");
	}
	pos = m_Message.find(L"$char2");
	while(pos != wstring::npos)
	{
		m_Message = m_Message.replace(pos, 6, peleador2W);
		pos = m_Message.find(L"$char2");
	}
	SendMessageDist(m_Message.c_str());
}



bool PvPEvents::EnCondicionesDePelear()
{
	if(peleador1->ValidUser() && peleador2->ValidUser())
	{
		if(peleador1->pED->inZoneCustomEventPvp && peleador2->pED->inZoneCustomEventPvp)	//LISTOS PARA PELEAR
		{
			peleador1->pED->inEventPvpLocked = false;
			peleador2->pED->inEventPvpLocked = false;

			return true;
		}
		else if(!peleador1->pED->inZoneCustomEventPvp && !peleador2->pED->inZoneCustomEventPvp)	//SI NINGUN JUGADOR ESTA
		{
			UserDescalificar(peleador1W);
			UserDescalificar(peleador2W);

			peleador1->pED->inEventPvpLocked = false;
			peleador2->pED->inEventPvpLocked = false;
			peleador1->pED->inEventPvp = 0;
			peleador2->pED->inEventPvp = 0;
		}
		else if(!peleador1->pED->inZoneCustomEventPvp && peleador2->pED->inZoneCustomEventPvp)	//SI NO ESTA EL PLAYER 1 EN LA ZONA
		{
			UserDescalificar(peleador1W);
			UserPasarDeRonda(peleador2W);

			peleador2->pED->inEventPvpLocked = false;
			peleador2->pED->inEventPvp = 0;
			PlayerAction::OnTeleportToLocation(peleador2, kickOutPos.x, kickOutPos.y, kickOutPos.z, false);
			peleador2->SetUserInfoChanged();
			peleador2->SetCharInfoChanged();

			peleador1->pED->inEventPvpLocked = false;
			peleador1->pED->inEventPvp = 0;
			PlayerAction::OnTeleportToLocation(peleador1, kickOutPos.x, kickOutPos.y, kickOutPos.z, false);
			peleador1->SetUserInfoChanged();
			peleador1->SetCharInfoChanged();

		}
		else if(peleador1->pED->inZoneCustomEventPvp && !peleador2->pED->inZoneCustomEventPvp)	//SI NO ESTA EL PLAYER 2 EN LA ZONA
		{
			UserDescalificar(peleador2W);
			UserPasarDeRonda(peleador1W);

			peleador1->pED->inEventPvpLocked = false;
			peleador1->pED->inEventPvp = 0;
			PlayerAction::OnTeleportToLocation(peleador1, kickOutPos.x, kickOutPos.y, kickOutPos.z, false);
			peleador1->SetUserInfoChanged();
			peleador1->SetCharInfoChanged();

			peleador2->pED->inEventPvpLocked = false;
			peleador2->pED->inEventPvp = 0;
			PlayerAction::OnTeleportToLocation(peleador2, kickOutPos.x, kickOutPos.y, kickOutPos.z, false);
			peleador2->SetUserInfoChanged();
			peleador2->SetCharInfoChanged();
		}

	}
	else if(!peleador1->ValidUser() && !peleador2->ValidUser())	//SI NINGUN JUGADOR ESTA
	{
		UserDescalificar(peleador1W);
		UserDescalificar(peleador2W);
		EnviarAnnouncePeleaCancelada(NingunoDeLosPeronajesOnlineMsg);
	}
	else if(!peleador1->ValidUser() && peleador2->ValidUser())	//SI NO ESTA EL PLAYER 1
	{
		UserDescalificar(peleador1W);
		UserPasarDeRonda(peleador2W);
		EnviarAnnouncePeleaCancelada(PeronajesCharNo1OnlineMsg);

		peleador2->pED->inEventPvpLocked = false;
		peleador2->pED->inEventPvp = 0;
		PlayerAction::OnTeleportToLocation(peleador2, kickOutPos.x, kickOutPos.y, kickOutPos.z, false);
		peleador2->SetUserInfoChanged();
		peleador2->SetCharInfoChanged();
	}
	else if(peleador1->ValidUser() && !peleador2->ValidUser())	//SI NO ESTA EL PLAYER 2
	{
		UserDescalificar(peleador2W);
		UserPasarDeRonda(peleador1W);
		EnviarAnnouncePeleaCancelada(PeronajesCharNo2OnlineMsg);

		peleador1->pED->inEventPvpLocked = false;
		peleador1->pED->inEventPvp = 0;
		PlayerAction::OnTeleportToLocation(peleador1, kickOutPos.x, kickOutPos.y, kickOutPos.z, false);
		peleador1->SetUserInfoChanged();
		peleador1->SetCharInfoChanged();
	}

	return false;
}


void PvPEvents::MensajeGanadorPelea(wstring player)
{
	wstring m_Message = HaGanadoLaPeleaMsg;		//wstring m_Message = L"Evento: $charName a ganado la pelea!" ;
	size_t pos = m_Message.find(L"$charName");
	while(pos != wstring::npos)
	{
		m_Message = m_Message.replace(pos, 9, player);
		pos = m_Message.find(L"$charName");
	}
	SendMessageDist(m_Message.c_str());
}

void PvPEvents::UserDescalificar(wstring player)
{
	m_Lock.Enter();
	for (vector<pair<wstring, PVPUser>>::iterator Iter = m_usersRounds.begin(); Iter != m_usersRounds.end(); ++Iter) {
		if (Iter->first == player) {
			Iter->second.descalificado = true;
			RequestSavePvPEvent(Iter->second.charId, Iter->second.ronda, Iter->second.descalificado);
			break;
		}
	}
	m_Lock.Leave();
}

void PvPEvents::UserPasarDeRonda(wstring player)
{
	m_Lock.Enter();
	for (vector<pair<wstring, PVPUser>>::iterator Iter = m_usersRounds.begin(); Iter != m_usersRounds.end(); ++Iter) {
		if (Iter->first == player) {
			Iter->second.ronda++;
			RequestSavePvPEvent(Iter->second.charId, Iter->second.ronda, Iter->second.descalificado);

			User* pUser = g_UserDB.GetUserByDBID(Iter->second.charId)->SafeCastUser();
			if (pUser->ValidUser())
				SumarPunto(pUser);

			break;
		}
	}
	m_Lock.Leave();

	UltimoGanador = player;

	m_Lock.Enter();
	m_usersGrillaClientes = m_usersRounds;
	m_Lock.Leave();
	UpdateFixture = true;
}

bool PvPEvents::DetectarHwid(User* pUser, wstring player)
{
	bool ret = true;

	if(HwidDetect)
	{
		m_Lock.Enter();
		for (vector<pair<wstring, PVPUser>>::iterator iter = m_usersRounds.begin(); iter != m_usersRounds.end(); ++iter) {
			if (iter->first == player) {
				if (!(iter->second.Hwid == pUser->pSocket->pED->longHWID.ToString())) {
					g_Log.Add(CLog::Error, "[%s] [%S] - [%S] - [%S]!", __FUNCTION__, player.c_str(), iter->second.Hwid.c_str(), pUser->pSocket->pED->longHWID.ToString().c_str());
					ret = false;
				}
				break;
			}
		}
		m_Lock.Leave();

//		g_Log.Add(CLog::Error, "[%s] [%S] - [%S] - [%S]!", __FUNCTION__, player.c_str(), iter->second.Hwid.c_str(), pUser->pSocket->pED->longHWID.ToString().c_str());
	}

	return ret;
}


void PvPEvents::OnDie(User *pUser, CCreature *pEnemy, bool empateAtk)
{
	guard;
	if(pUser->ValidUser())
	{
		if(pUser->pED->inEventPvp > 0)
		{
			if(!pEnemy->ValidUser())
			{
				if(peleador1 == pUser)
					pEnemy = peleador2;
				else 
					pEnemy = peleador1;
			}

			if(pEnemy->ValidUser())
			{
				User* pEnemyUser2 = pEnemy->GetUser();
				if(pEnemyUser2->ValidUser())
				{
					if(pUser->pED->inEventPvp > 0 && pEnemyUser2->pED->inEventPvp > 0)
					{
						if(CSkillInfo *pSI = g_SkillDB.GetSkillInfo(2025, 1))
						{
							pSI->ActivateSkill(pEnemyUser2, pEnemyUser2);
							CSkillFx::BroadcastAutoCastSkill(pEnemyUser2->CastCreature()->nObjectID,pEnemyUser2->CastCreature()->nObjectID, 2025, 1, &pEnemyUser2->CastCreature()->pSD->Pos);
						}

						if(pEnemyUser2 == peleador1)
						{
							wstring m_Message = HaGanadoLaPeleaMsg;		//wstring m_Message = L"Evento: $charName a ganado la pelea!" ;
							size_t pos = m_Message.find(L"$charName");
							while(pos != wstring::npos)
							{
								m_Message = m_Message.replace(pos, 9, peleador1W);
								pos = m_Message.find(L"$charName");
							}
							SendMessageDist(m_Message.c_str());

							UserDescalificar(peleador2W);
							UserPasarDeRonda(peleador1W);
						}
						else if(pEnemyUser2 == peleador2)
						{
							wstring m_Message = HaGanadoLaPeleaMsg;		//wstring m_Message = L"Evento: $charName a ganado la pelea!" ;
							size_t pos = m_Message.find(L"$charName");
							while(pos != wstring::npos)
							{
								m_Message = m_Message.replace(pos, 9, peleador2W);
								pos = m_Message.find(L"$charName");
							}
							SendMessageDist(m_Message.c_str());

							UserDescalificar(peleador1W);
							UserPasarDeRonda(peleador2W);
						}

						if(!empateAtk)
						{
							m_stateTime = time(NULL);
							m_state = StateFinish;
						}
					}
				}
			
			}
		}
	}
	unguard;
}

bool PvPEvents::EnviarAPelear(User* pUser1, User* pUser2)
{
	guard;

		pUser1->pED->inEventPvpLocked = true;
		pUser1->pED->inEventPvp = 1;
		CParty *pParty = pUser1->GetParty();
		if(pParty)
		{
			pParty->LeaveParty(pUser1);
		}
		if(pUser1->pSD->nIsObserver)
		{
			PlayerAction::ObserverEnd(pUser1);
		}
		pUser1->ResetSkillReuse();
		pUser1->ResurrectedBy(pUser1, 100);
		PlayerAction::OnTeleportToLocation(pUser1, Player1_Pos.x, Player1_Pos.y, Player1_Pos.z, false);

		pUser2->pED->inEventPvpLocked = true;
		pUser2->pED->inEventPvp = 2;
		CParty *pParty2 = pUser2->GetParty();
		if(pParty2)
		{
			pParty2->LeaveParty(pUser2);
		}
		if(pUser2->pSD->nIsObserver)
		{
			PlayerAction::ObserverEnd(pUser2);
		}
		pUser2->ResetSkillReuse();
		pUser2->ResurrectedBy(pUser2, 100);
		PlayerAction::OnTeleportToLocation(pUser2, Player2_Pos.x, Player2_Pos.y, Player2_Pos.z, false);


		wstring m_Message = ProximaPeleaMsg;		//wstring m_Message = L"Evento: Proxima pelea $char1 VS $char2!" ;
		size_t pos = m_Message.find(L"$char1");
		while(pos != wstring::npos)
		{
			m_Message = m_Message.replace(pos, 6, peleador1W);
			pos = m_Message.find(L"$char1");
		}

		pos = m_Message.find(L"$char2");
		while(pos != wstring::npos)
		{
			m_Message = m_Message.replace(pos, 6, peleador2W);
			pos = m_Message.find(L"$char2");
		}

		SendMessageDist(m_Message.c_str());

		m_stateTime = time(NULL);
		m_state = StatePrepare;

	unguard;
	return true;
}


bool PvPEvents::CommandCacheD(wstring wsParams)
{
	guard;

	unguard;
	return true;
}

void PvPEvents::SendMessageDist(const WCHAR* wAnnounce)
{
	FVector pos;
	pos.x = Player1_Pos.x;
	pos.y = Player1_Pos.y;
	pos.z = Player1_Pos.z;
		
	Utils::BroadcastToAllUser_AnnounceDist(wAnnounce, 20000, pos);
//	L2Server::BroadcastToNeighborDist(NULL, &pos, 40960, msg.GetSize(), msg.GetBuff());
}

void PvPEvents::SumarPunto(User* pUser)
{

	if (sumarpuntos_torneo)
	{
		pUser->pED->EventPvpPointsTotal += 1;
		pUser->pED->EventPvpPointsTemporal += 1;
		//pUser->pED->EventPvpCategoria = Categoria;
		RequestSavePvPEventUserVars(pUser);
	}
}

void PvPEvents::RequestLoadPvPEvent()
{
	g_DB.Send("chd", 0xF9, CI_REQUEST_LOAD_PVPEVENT, 0);		//n_EventID en ves de 0 proximamente para reanudar un torneo tras caida del server
}

void PvPEvents::RequestSavePvPEvent(int charId, int ronda, bool descalificado, int pos)
{
	g_DB.Send("chddddd", 0xF9, CI_REQUEST_SAVE_PVPEVENT, n_EventID, charId, ronda, descalificado, pos);
}

bool PvPEvents::ReplyLoadPvPEvent(CDBSocket *pSocket, const unsigned char* packet, UINT packetId)
{
	INT32 EventId;
	INT32 UsersCount;

	packet = Disassemble(packet, "dd", &EventId, &UsersCount);
	if(UsersCount > 0)
	{
		//AGREGAR USUARIOS AL TORNEO SI LOS HAY
		g_PvPEvents.n_EventID = EventId;
	}
	else
	{
		g_PvPEvents.n_EventID = EventId+1;
	}

	return true;
}


void PvPEvents::RequestLoadPvPEventUserVars(UINT charId)
{
	g_DB.Send("chd", 0xF9, CI_REQUEST_LOAD_PVPEVENT_PLAYER_VARS, charId);
}

bool PvPEvents::ReplyLoadPvPEventUserVars(CDBSocket *pSocket, const unsigned char* packet, UINT packetId)
{
	INT32 charId;
	INT32 PointsTotal;
	INT32 PointsTemporal;
	INT32 Categoria;
	WCHAR wHash[33];

	packet = Disassemble(packet, "ddddS", &charId, &PointsTotal, &PointsTemporal, &Categoria, sizeof(wHash), wHash);

	if(User *pUser = g_UserDB.GetUserByDBID(charId)->SafeCastUser())
	{
		pUser->pED->EventPvpPointsTotal = PointsTotal;
		pUser->pED->EventPvpPointsTemporal = PointsTemporal;
		pUser->pED->EventPvpCategoria = Categoria;

		for(UINT n=0;n<32;n++)
		{
			pUser->pED->EventPvplongHWID.hash[n] = static_cast<BYTE>(wHash[n]);
		}
	}

	return true;
}

void PvPEvents::RequestSavePvPEventUserVars(User* pUser)
{
	if(pUser->ValidUser())
	{
		int charId = pUser->nDBID;
		int puntosTotal = pUser->pED->EventPvpPointsTotal;
		int puntosTemp = pUser->pED->EventPvpPointsTemporal;
		int category = pUser->pED->EventPvpCategoria;

		const WCHAR* hwidReal = pUser->pSocket->pED->longHWID.ToString().c_str();
		if(!(pUser->pED->EventPvplongHWID.ToString() == L"00000000000000000000000000000000"))
			hwidReal = pUser->pED->EventPvplongHWID.ToString().c_str();


		g_DB.Send("chddddS", 0xF9, CI_REQUEST_SAVE_PVPEVENT_PLAYER_VARS, charId, puntosTotal, puntosTemp, category, hwidReal);
	}
}

//	INT32 EventPvpPointsTotal;
//	INT32 EventPvpPointsTemporal;
//	INT32 EventPvpCategoria;


bool PvPEvents::Bypass(User* pUser, wstring wBypass)
{


	if( wBypass.find(L"pvp_event?") == 0)
	{
		UserExCommandPvPEvents(pUser, wBypass);
		return true;
	}else if( wBypass.find(L"pvp_event_register?") == 0)
	{
		Register(pUser);
		return true;
	}else if(wBypass.find(L"pvp_event_unregister?") == 0)
	{
		UnRegister(pUser);
		return true;
	}else if(wBypass.find(L"pvp_event_habilitarRegistro?") == 0)
	{
		HabilitarRegistro();
		return true;
	}else if(wBypass.find(L"pvp_event_cerrarRegistro?") == 0)
	{
		CerrarRegistro();
		return true;
	}else if(wBypass.find(L"pvp_event_set_maxUsers?") == 0)
	{
		UINT maxUsers = Parser::GetBypassValueInt(wBypass.c_str(), L"cantidad");
		SetMaxPlayers(maxUsers);
		return true;
	}else if(wBypass.find(L"pvp_event_terminar?") == 0)
	{
		TerminarTorneo();
		return true;
	}else if(wBypass.find(L"pvp_event_no_sumar?") == 0)
	{
		sumarpuntos_torneo = false;
		pUser->SendSystemMessage(L"EN TORNEO NO SUMARA PUNTOS DE LIGA");
		return true;
	}else if(wBypass.find(L"pvp_event_si_sumar?") == 0)
	{
		sumarpuntos_torneo = true;
		pUser->SendSystemMessage(L"EN TORNEO SI SUMARA PUNTOS DE LIGA");
		return true;
	}else if(wBypass.find(L"pvp_event_forzar_proxima?") == 0)
	{
		pUser->SendSystemMessage(L"FORZANDO Y DEBUG");


		m_stateTime = time(NULL);
		SleepEntreCadaPeleaTemp = 1000;
		m_state = StatePrepararInicioTorneo;
		TorneoComenzado = true;

		return true;
	}else if(wBypass.find(L"pvp_event_get_grilla?") == 0)
	{
		UINT grilla = Parser::GetBypassValueInt(wBypass.c_str(), L"grilla");

		grilla *=64;
		
			//const WCHAR *wHtml = g_HTMLCacheManager.GetHTMLFile( L"torneo_grilla.htm", pUser->pSD->bLang);
			const WCHAR *wHtml = g_HtmlCache.Get(L"torneo_grilla.htm");
			if(wHtml)
			{
				if(UpdateFixture)
				{
					UpdateFixture = false;

					wstring html(wHtml);

					int count = 0;
					m_Lock.Enter();
					//for (std::map<std::wstring, PVPUser>::iterator it = m_usersGrillaClientes.begin(); it != m_usersGrillaClientes.end(); ++it) 
					for (std::vector<std::pair<std::wstring, PVPUser> >::iterator it = m_usersGrillaClientes.begin(); it != m_usersGrillaClientes.end(); ++it)
					{
						wstring playerName = it->first; // Obtener el nombre del jugador

						bool shouldShorten = false; // Bandera para determinar si se debe acortar el nombre

						size_t consecutiveCount = 1; // Contador para caracteres consecutivos
						wchar_t prevChar = playerName[0]; // Carácter previo inicializado con el primer carácter

						for (size_t i = 1; i < playerName.length(); i++) {
							if (playerName[i] == prevChar) {
								consecutiveCount++;
								if (consecutiveCount > 7) {
									shouldShorten = true;
									break;
								}
							} else {
								consecutiveCount = 1;
								prevChar = playerName[i];
							}
						}

						if (shouldShorten) {
							// Acortar el nombre agregando "..." al final
							playerName = playerName.substr(0, 4) + L"...";
						}

						
						if (it->second.ronda >= 1) {
							html = Utils::ReplaceString(html, L"RONDA_1", playerName, false);
						}
						if (it->second.ronda >= 2) {
							html = Utils::ReplaceString(html, L"RONDA_2", playerName, false);
						}
						if (it->second.ronda >= 3) {
							html = Utils::ReplaceString(html, L"RONDA_3", playerName, false);
						}
						if (it->second.ronda >= 4) {
							html = Utils::ReplaceString(html, L"RONDA_4", playerName, false);
						}
						if (it->second.ronda >= 5) {
							html = Utils::ReplaceString(html, L"RONDA_5", playerName, false);
						}
						if (it->second.ronda >= 6) {
							html = Utils::ReplaceString(html, L"RONDA_6", playerName, false);
						}
						if (it->second.ronda >= 7) {
							html = Utils::ReplaceString(html, L"RONDA_7", playerName, false);
						}
					}
					m_Lock.Leave();

					html = Utils::ReplaceString(html, L"RONDA_1", L"", true);
					html = Utils::ReplaceString(html, L"RONDA_2", L"", true);
					html = Utils::ReplaceString(html, L"RONDA_3", L"", true);
					html = Utils::ReplaceString(html, L"RONDA_4", L"", true);
					html = Utils::ReplaceString(html, L"RONDA_5", L"", true);
					html = Utils::ReplaceString(html, L"RONDA_6", L"", true);
					html = Utils::ReplaceString(html, L"RONDA_7", L"", true);

					html_fixture = html;

					ShowBoard(pUser, html.c_str());
				}
				else
				{

					//pUser->ShowBoard(html_fixture.c_str());
					ShowBoard(pUser, html_fixture.c_str());
				}
			}


		return true;
	}

	return false;
}



void PvPEvents::ShowBoard(User* pUser, const WCHAR *wHtml)
{
		wstring html(wHtml);
		html = Utils::ReplaceString(html, L"\t", L"", true);
		size_t html_size = html.size() * 2;

		if(html_size < 8180)
		{
			wstringstream htmlStream1;
			htmlStream1 << L"101" << L"\b" << html.substr(0,4090);
			pUser->pSocket->Send("ccSSSSSSSSS", 0x6E, 0x01, L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", htmlStream1.str().c_str() );
				
			wstringstream htmlStream2;
			htmlStream2 << L"102" << L"\b";
			pUser->pSocket->Send("ccSSSSSSSSS", 0x6E, 0x01, L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", htmlStream2.str().c_str() );

			wstringstream htmlStream3;
			htmlStream3 << L"103" << L"\b";
			pUser->pSocket->Send("ccSSSSSSSSS", 0x6E, 0x01, L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", htmlStream3.str().c_str() );
		}
		else if(html_size < 8180 * 2)
		{
			wstringstream htmlStream1;
			htmlStream1 << L"101" << L"\b" << html.substr(0,4090);
			pUser->pSocket->Send("ccSSSSSSSSS", 0x6E, 0x01, L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", htmlStream1.str().c_str() );
				
			wstringstream htmlStream2;
			htmlStream2 << L"102" << L"\b" << html.substr(4090,html.size());
			pUser->pSocket->Send("ccSSSSSSSSS", 0x6E, 0x01, L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", htmlStream2.str().c_str() );

			wstringstream htmlStream3;
			htmlStream3 << L"103" << L"\b";
			pUser->pSocket->Send("ccSSSSSSSSS", 0x6E, 0x01, L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", htmlStream3.str().c_str() );
		}
		else if(html_size < 8180 * 3)
		{
			wstringstream htmlStream1;
			htmlStream1 << L"101" << L"\b" << html.substr(0,4090);
			pUser->pSocket->Send("ccSSSSSSSSS", 0x6E, 0x01, L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", htmlStream1.str().c_str() );
				
			wstringstream htmlStream2;
			htmlStream2 << L"102" << L"\b" << html.substr(4090,4090);
			pUser->pSocket->Send("ccSSSSSSSSS", 0x6E, 0x01, L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", htmlStream2.str().c_str() );
				
			wstringstream htmlStream3;
			htmlStream3 << L"103" << L"\b" << html.substr(8180,4090);
			pUser->pSocket->Send("ccSSSSSSSSS", 0x6E, 0x01, L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", L"bypass _auction_show", htmlStream3.str().c_str() );
		}
		else
		{
			g_Log.Add(CLog::Error, "[%s] The html is REAL BIG![%d]!", __FUNCTION__, html_size);
		}
}


bool PvPEvents::UnRegister(User *pUser)
{
	guard;

	if(enableRegister || m_state == StateRegistrationAutomatico)
	{
		wstringstream name;
		name << pUser->pSD->wszName;
		wstring charname;
		name >> charname;


//		map<wstring, PVPUser>::iterator Iter = m_usersRegister.find(charname);
//		if(Iter!= m_usersRegister.end())
		m_Lock.Enter();
		for (vector<pair<wstring, PVPUser>>::iterator Iter = m_usersRegister.begin(); Iter != m_usersRegister.end(); ++Iter) {
			if (Iter->first == charname)
			{
				m_usersRegister.erase(Iter);
				registeredPlayers -= 1;
				//RequestSavePvPEventRegister(pUser->pSD->wszName, pUser->pSocket->pED->longHWID.ToWchar(), 2);	//2 eliminar
				pUser->SendSystemMessage(L"Ya no estas anotado al evento!");

				const WCHAR* wHtml = g_HtmlCache.Get(L"pvpevent.htm");
				wstring html(wHtml);
				html = Utils::ReplaceString(html, L"<?playername?>", pUser->pSD->wszName , true);
				html = Utils::ReplaceString(html, L"<?maxPlayers?>", maxPlayers, true);
				html = Utils::ReplaceString(html, L"<?registeredPlayers?>", g_PvPEvents.registeredPlayers, true);

				html = Utils::ReplaceString(html, L"<?InscripcionTorneoCount?>", inscripcionItemCount, true);
				html = Utils::ReplaceString(html, L"<?InscripcionTorneoName?>", inscripcionItemName, true);
				html = Utils::ReplaceString(html, L"<?InscripcionTorneoIcon?>", inscripcionItemIcon, true);

				html = Utils::ReplaceString(html, L"<?PremioTorneoCount?>", premioItemCount, true);
				html = Utils::ReplaceString(html, L"<?PremioTorneoName?>", premioItemName, true);
				html = Utils::ReplaceString(html, L"<?PremioTorneoIcon?>", premioItemIcon, true);

				pUser->ShowHTML(L"pvpevent.htm", html.c_str(), 0);

				m_Lock.Leave();
				unguard;
				return true;
			}
		}
		m_Lock.Leave();
	}

	unguard;
	return false;
}




bool PvPEvents::UserExCommandPvPEvents(User *pUser, wstring params)
{
	guard;
	if(g_torneo)
	{
		if (pUser->pED->tvtUser.status == TvT::UserNone)
		{
			if (g_PvPEvents.enableRegister || g_PvPEvents.m_state == StateRegistrationAutomatico)
			{
				const WCHAR* wHtml = g_HtmlCache.Get(L"pvpevent.htm");
				if(wHtml)
				{

					wstringstream name;
					name << pUser->pSD->wszName;
					wstring charname;
					name >> charname;

					g_PvPEvents.m_Lock.Enter();
					for (vector<pair<wstring, PVPUser>>::iterator Iter = g_PvPEvents.m_usersRegister.begin(); Iter != g_PvPEvents.m_usersRegister.end(); ++Iter) {
						if (Iter->first == charname)
						{
							const WCHAR* wHtml = g_HtmlCache.Get(L"pvpevent_anotado.htm");
							wstring html(wHtml);
							html = Utils::ReplaceString(html, L"<?playername?>", Iter->first , true);
							html = Utils::ReplaceString(html, L"<?maxPlayers?>", g_PvPEvents.maxPlayers, true);
							html = Utils::ReplaceString(html, L"<?registeredPlayers?>", g_PvPEvents.registeredPlayers, true);

							if(g_PvPEvents.TorneoCategoria == 0)
								html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Amateur", true);
							else if(g_PvPEvents.TorneoCategoria == 1)
								html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Segunda", true);
							else if(g_PvPEvents.TorneoCategoria == 2)
								html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Primer", true);
							else if(g_PvPEvents.TorneoCategoria == 3)
								html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Master", true);
							else if(g_PvPEvents.TorneoCategoria == 30)
								html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Todas", true);

							html = Utils::ReplaceString(html, L"<?InscripcionTorneoCount?>", g_PvPEvents.inscripcionItemCount, true);
							html = Utils::ReplaceString(html, L"<?InscripcionTorneoName?>", g_PvPEvents.inscripcionItemName, true);
							html = Utils::ReplaceString(html, L"<?InscripcionTorneoIcon?>", g_PvPEvents.inscripcionItemIcon, true);

							html = Utils::ReplaceString(html, L"<?PremioTorneoCount?>", g_PvPEvents.premioItemCount, true);
							html = Utils::ReplaceString(html, L"<?PremioTorneoName?>", g_PvPEvents.premioItemName, true);
							html = Utils::ReplaceString(html, L"<?PremioTorneoIcon?>", g_PvPEvents.premioItemIcon, true);



							pUser->ShowHTML(L"pvpevent_anotado.htm", html.c_str(), 0);

							g_PvPEvents.m_Lock.Leave();
							unguard;
							return true;
						}
					}
					g_PvPEvents.m_Lock.Leave();

					//for(map<wstring, PVPUser>::iterator Iter = g_PvPEvents.m_usersRegister.begin();Iter!=g_PvPEvents.m_usersRegister.end();Iter++)
					g_PvPEvents.m_Lock.Enter();
					for (vector<pair<wstring, PVPUser>>::iterator Iter = g_PvPEvents.m_usersRegister.begin(); Iter != g_PvPEvents.m_usersRegister.end(); ++Iter) 
					{
						if(Iter->second.Hwid == pUser->pSocket->pED->longHWID.ToString() && g_PvPEvents.HwidDetect)
						{
							const WCHAR* wHtml = g_HtmlCache.Get(L"pvpevent_anotado_hwid.htm");
							wstring html(wHtml);
							html = Utils::ReplaceString(html, L"<?playername?>", Iter->first , true);
							html = Utils::ReplaceString(html, L"<?maxPlayers?>", g_PvPEvents.maxPlayers, true);
							html = Utils::ReplaceString(html, L"<?registeredPlayers?>", g_PvPEvents.registeredPlayers, true);

							if(g_PvPEvents.TorneoCategoria == 0)
								html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Amateur", true);
							else if(g_PvPEvents.TorneoCategoria == 1)
								html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Segunda", true);
							else if(g_PvPEvents.TorneoCategoria == 2)
								html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Primer", true);
							else if(g_PvPEvents.TorneoCategoria == 3)
								html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Master", true);
							else if(g_PvPEvents.TorneoCategoria == 30)
								html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Todas", true);


							html = Utils::ReplaceString(html, L"<?InscripcionTorneoCount?>", g_PvPEvents.inscripcionItemCount, true);
							html = Utils::ReplaceString(html, L"<?InscripcionTorneoName?>", g_PvPEvents.inscripcionItemName, true);
							html = Utils::ReplaceString(html, L"<?InscripcionTorneoIcon?>", g_PvPEvents.inscripcionItemIcon, true);

							html = Utils::ReplaceString(html, L"<?PremioTorneoCount?>", g_PvPEvents.premioItemCount, true);
							html = Utils::ReplaceString(html, L"<?PremioTorneoName?>", g_PvPEvents.premioItemName, true);
							html = Utils::ReplaceString(html, L"<?PremioTorneoIcon?>", g_PvPEvents.premioItemIcon, true);


							pUser->ShowHTML(L"pvpevent_anotado_hwid.htm", html.c_str(), 0);

							g_PvPEvents.m_Lock.Leave();
							unguard;
							return false;
						}
					}
					g_PvPEvents.m_Lock.Leave();

					wstring html(wHtml);
					html = Utils::ReplaceString(html, L"<?maxPlayers?>", g_PvPEvents.maxPlayers, true);
					html = Utils::ReplaceString(html, L"<?registeredPlayers?>", g_PvPEvents.registeredPlayers, true);
					html = Utils::ReplaceString(html, L"<?CategoryPlayer?>", pUser->pED->EventPvpCategoria, true);


					if(g_PvPEvents.TorneoCategoria == 0)
						html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Amateur", true);
					else if(g_PvPEvents.TorneoCategoria == 1)
						html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Segunda", true);
					else if(g_PvPEvents.TorneoCategoria == 2)
						html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Primer", true);
					else if(g_PvPEvents.TorneoCategoria == 3)
						html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Master", true);
					else if(g_PvPEvents.TorneoCategoria == 30)
						html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Todas", true);

					html = Utils::ReplaceString(html, L"<?InscripcionTorneoCount?>", g_PvPEvents.inscripcionItemCount, true);
					html = Utils::ReplaceString(html, L"<?InscripcionTorneoName?>", g_PvPEvents.inscripcionItemName, true);
					html = Utils::ReplaceString(html, L"<?InscripcionTorneoIcon?>", g_PvPEvents.inscripcionItemIcon, true);

					html = Utils::ReplaceString(html, L"<?PremioTorneoCount?>", g_PvPEvents.premioItemCount, true);
					html = Utils::ReplaceString(html, L"<?PremioTorneoName?>", g_PvPEvents.premioItemName, true);
					html = Utils::ReplaceString(html, L"<?PremioTorneoIcon?>", g_PvPEvents.premioItemIcon, true);


					pUser->ShowHTML(L"pvpevent.htm", html.c_str(), 0);
				}else
				{
					g_Log.Add(CLog::Error, "[%s] Cannot find pvpevent.htm!", __FUNCTION__);
				}

			}
			else
			{
				wstring wHtml = g_HtmlCache.Get(L"pvpevent_cerrado.htm");
				PlayerAction::ShowHTML(pUser, L"pvpevent_cerrado.htm", wHtml.c_str(), 0);
			}
		}
		else
		{
			wstring wHtml = g_HtmlCache.Get(L"pvpevent_cerrado.htm");
			PlayerAction::ShowHTML(pUser, L"pvpevent_cerrado.htm", wHtml.c_str(), 0);
		}
	}


	unguard;
	return false;
}

bool PvPEvents::InEvent(User *pUser)
{
	guard;

	wstringstream name;
	name << pUser->pSD->wszName;
	wstring charname;
	name >> charname;

	bool resgistrado = false;

	m_Lock.Enter();

	//map<wstring, PVPUser>::iterator Iter = m_usersRegister.find(charname);
	for (vector<pair<wstring, PVPUser>>::iterator Iter = m_usersRegister.begin(); Iter != m_usersRegister.end(); ++Iter) {
		if (Iter->first == charname)
		{
			resgistrado = true;
		}
	}

	if(resgistrado)
	{
		for (vector<pair<wstring, PVPUser>>::iterator Iter2 = m_usersRounds.begin(); Iter2 != m_usersRounds.end(); ++Iter2) {
			if (Iter2->first == charname) {
				if(!Iter2->second.descalificado)
				{
					m_Lock.Leave();
					unguard;
					return true;
				}
			}
		}
	}
	m_Lock.Leave();

	unguard;
	return false;
}

bool PvPEvents::Register(User *pUser)
{
	guard;

	if(enableRegister || m_state == StateRegistrationAutomatico)
	{

		if(pUser->inventory.HaveItemByClassID(inscripcionItemId, inscripcionItemCount))
		{

			wstringstream name;
			name << pUser->pSD->wszName;
			wstring charname;
			name >> charname;

	//		map<wstring, PVPUser>::iterator Iter = g_PvPEvents.m_usersRegister.find(charname);
	//		if(Iter!= g_PvPEvents.m_usersRegister.end())
			m_Lock.Enter();
			for (vector<pair<wstring, PVPUser>>::iterator Iter = g_PvPEvents.m_usersRegister.begin(); Iter != g_PvPEvents.m_usersRegister.end(); ++Iter) {
				if (Iter->first == charname)
				{
					const WCHAR* wHtml = g_HtmlCache.Get(L"pvpevent_anotado.htm");
					wstring html(wHtml);
					html = Utils::ReplaceString(html, L"<?playername?>", Iter->first , true);
					html = Utils::ReplaceString(html, L"<?maxPlayers?>", g_PvPEvents.maxPlayers, true);
					html = Utils::ReplaceString(html, L"<?registeredPlayers?>", g_PvPEvents.registeredPlayers, true);

					if(g_PvPEvents.TorneoCategoria == 0)
						html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Amateur", true);
					else if(g_PvPEvents.TorneoCategoria == 1)
						html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Segunda", true);
					else if(g_PvPEvents.TorneoCategoria == 2)
						html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Primer", true);
					else if(g_PvPEvents.TorneoCategoria == 3)
						html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Master", true);
					else if(g_PvPEvents.TorneoCategoria == 30)
						html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Todas", true);

					html = Utils::ReplaceString(html, L"<?InscripcionTorneoCount?>", g_PvPEvents.inscripcionItemCount, true);
					html = Utils::ReplaceString(html, L"<?InscripcionTorneoName?>", g_PvPEvents.inscripcionItemName, true);
					html = Utils::ReplaceString(html, L"<?InscripcionTorneoIcon?>", g_PvPEvents.inscripcionItemIcon, true);

					html = Utils::ReplaceString(html, L"<?PremioTorneoCount?>", g_PvPEvents.premioItemCount, true);
					html = Utils::ReplaceString(html, L"<?PremioTorneoName?>", g_PvPEvents.premioItemName, true);
					html = Utils::ReplaceString(html, L"<?PremioTorneoIcon?>", g_PvPEvents.premioItemIcon, true);


					pUser->ShowHTML(L"pvpevent_anotado.htm", html.c_str(), 0);

					m_Lock.Leave();
					unguard;
					return true;
				}
			}
			m_Lock.Leave();

			//for(map<wstring, PVPUser>::iterator Iter = m_usersRegister.begin();Iter!=m_usersRegister.end();Iter++)
			m_Lock.Enter();
			for (vector<pair<wstring, PVPUser>>::iterator Iter = m_usersRegister.begin(); Iter != m_usersRegister.end(); ++Iter)
			{
				if(Iter->second.Hwid == pUser->pSocket->pED->longHWID.ToString() && g_PvPEvents.HwidDetect)
				{
					const WCHAR* wHtml = g_HtmlCache.Get(L"pvpevent_anotado_hwid.htm");
					wstring html(wHtml);
					html = Utils::ReplaceString(html, L"<?playername?>", Iter->first , true);
					html = Utils::ReplaceString(html, L"<?maxPlayers?>", g_PvPEvents.maxPlayers, true);
					html = Utils::ReplaceString(html, L"<?registeredPlayers?>", g_PvPEvents.registeredPlayers, true);

					if(g_PvPEvents.TorneoCategoria == 0)
						html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Amateur", true);
					else if(g_PvPEvents.TorneoCategoria == 1)
						html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Segunda", true);
					else if(g_PvPEvents.TorneoCategoria == 2)
						html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Primer", true);
					else if(g_PvPEvents.TorneoCategoria == 3)
						html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Master", true);
					else if(g_PvPEvents.TorneoCategoria == 30)
						html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Todas", true);

					html = Utils::ReplaceString(html, L"<?InscripcionTorneoCount?>", g_PvPEvents.inscripcionItemCount, true);
					html = Utils::ReplaceString(html, L"<?InscripcionTorneoName?>", g_PvPEvents.inscripcionItemName, true);
					html = Utils::ReplaceString(html, L"<?InscripcionTorneoIcon?>", g_PvPEvents.inscripcionItemIcon, true);

					html = Utils::ReplaceString(html, L"<?PremioTorneoCount?>", g_PvPEvents.premioItemCount, true);
					html = Utils::ReplaceString(html, L"<?PremioTorneoName?>", g_PvPEvents.premioItemName, true);
					html = Utils::ReplaceString(html, L"<?PremioTorneoIcon?>", g_PvPEvents.premioItemIcon, true);


					pUser->ShowHTML(L"pvpevent_anotado_hwid.htm", html.c_str(), 0);

					pUser->SendSystemMessage(L"Ya estas registrado en el evento.");
					m_Lock.Leave();
					unguard;
					return true;
				}
			}
			m_Lock.Leave();

			//g_Log.Add(CLog::Error, "EventPvplongHWID[%S] longHWID[%S]", pUser->pED->EventPvplongHWID.ToString().c_str(), pUser->pSocket->pED->longHWID.ToString().c_str());

			if(!(pUser->pED->EventPvplongHWID.ToString() == L"00000000000000000000000000000000"))
			{
				if(memcmp(pUser->pED->EventPvplongHWID.hash, pUser->pSocket->pED->longHWID.hash, 32) && g_PvPEvents.HwidDetect)
				{
					const WCHAR* wHtml = g_HtmlCache.Get(L"pvpevent_invalidHwid.htm");
					wstring html(wHtml);
					pUser->ShowHTML(L"pvpevent_invalidHwid.htm", html.c_str(), 0);
					pUser->SendSystemMessage(L"No puedes registrar a este Personaje ya que ha jugado su primera ves en una PC diferente.");
					unguard;
					return true;
				}
			}

			if((TorneoCategoria != CategoryAll) && TorneoCategoria != pUser->pED->EventPvpCategoria)
			{
				const WCHAR* wHtml = g_HtmlCache.Get(L"pvpevent_errorCategoria.htm");
				wstring html(wHtml);
				html = Utils::ReplaceString(html, L"<?playername?>", pUser->pSD->wszName , true);
				html = Utils::ReplaceString(html, L"<?CategoryPlayer?>", pUser->pED->EventPvpCategoria, true);

				if(g_PvPEvents.TorneoCategoria == 0)
					html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Amateur", true);
				else if(g_PvPEvents.TorneoCategoria == 1)
					html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Segunda", true);
				else if(g_PvPEvents.TorneoCategoria == 2)
					html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Primera", true);
				else if(g_PvPEvents.TorneoCategoria == 3)
					html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Master", true);

				html = Utils::ReplaceString(html, L"<?InscripcionTorneoCount?>", g_PvPEvents.inscripcionItemCount, true);
				html = Utils::ReplaceString(html, L"<?InscripcionTorneoName?>", g_PvPEvents.inscripcionItemName, true);
				html = Utils::ReplaceString(html, L"<?InscripcionTorneoIcon?>", g_PvPEvents.inscripcionItemIcon, true);

				html = Utils::ReplaceString(html, L"<?PremioTorneoCount?>", g_PvPEvents.premioItemCount, true);
				html = Utils::ReplaceString(html, L"<?PremioTorneoName?>", g_PvPEvents.premioItemName, true);
				html = Utils::ReplaceString(html, L"<?PremioTorneoIcon?>", g_PvPEvents.premioItemIcon, true);


				pUser->ShowHTML(L"pvpevent_errorCategoria.htm", html.c_str(), 0);

				pUser->SendSystemMessage(L"No puedes participar en este torneo.");
				unguard;
				return true;
			}


			if(registeredPlayers < maxPlayers)
			{
				PVPUser mapa;
				mapa.charId = pUser->nDBID;
				mapa.Hwid = pUser->pSocket->pED->longHWID.ToString();
				mapa.descalificado = 0;
				mapa.ronda = 1;

				//m_usersRegister.insert(pair<wstring, PVPUser>(pUser->pSD->wszName, mapa));
				m_usersRegister.push_back(std::make_pair(pUser->pSD->wszName, mapa));

	//			m_usersRegister.push_back(std::make_pair(L"player_1", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_2", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_3", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_4", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_5", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_6", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_7", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_8", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_9", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_10", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_11", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_12", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_13", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_14", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_15", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_16", mapa));

	//			m_usersRegister.push_back(std::make_pair(L"player_17", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_18", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_19", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_20", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_21", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_22", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_23", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_24", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_25", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_26", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_27", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_28", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_29", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_30", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_31", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_32", mapa));

	//			m_usersRegister.push_back(std::make_pair(L"player_33", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_34", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_35", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_36", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_37", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_38", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_39", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_40", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_41", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_42", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_43", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_44", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_45", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_46", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_47", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_48", mapa));

	//			m_usersRegister.push_back(std::make_pair(L"player_49", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_50", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_51", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_52", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_53", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_54", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_55", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_56", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_57", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_58", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_59", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_60", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_61", mapa));
	//			m_usersRegister.push_back(std::make_pair(L"player_62", mapa));




				registeredPlayers += 1;
				//RequestSavePvPEventRegister(pUser->pSD->wszName, pUser->pSocket->pED->longHWID.ToWchar(), 1);	//1 registrar
				pUser->SendSystemMessage(L"Ya te inscribi en el evento. Muchas Suerte!");
				
				RequestSavePvPEventUserVars(pUser);

				const WCHAR* wHtml = g_HtmlCache.Get(L"pvpevent_anotado.htm");
				wstring html(wHtml);
				html = Utils::ReplaceString(html, L"<?playername?>", pUser->pSD->wszName , true);
				html = Utils::ReplaceString(html, L"<?maxPlayers?>", g_PvPEvents.maxPlayers, true);
				html = Utils::ReplaceString(html, L"<?registeredPlayers?>", g_PvPEvents.registeredPlayers, true);


				if(g_PvPEvents.TorneoCategoria == 0)
					html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Amateur", true);
				else if(g_PvPEvents.TorneoCategoria == 1)
					html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Segunda", true);
				else if(g_PvPEvents.TorneoCategoria == 2)
					html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Primer", true);
				else if(g_PvPEvents.TorneoCategoria == 3)
					html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Master", true);
				else if(g_PvPEvents.TorneoCategoria == 30)
					html = Utils::ReplaceString(html, L"<?CategoryTorneo?>", L"Todos", true);

				html = Utils::ReplaceString(html, L"<?InscripcionTorneoCount?>", g_PvPEvents.inscripcionItemCount, true);
				html = Utils::ReplaceString(html, L"<?InscripcionTorneoName?>", g_PvPEvents.inscripcionItemName, true);
				html = Utils::ReplaceString(html, L"<?InscripcionTorneoIcon?>", g_PvPEvents.inscripcionItemIcon, true);

				html = Utils::ReplaceString(html, L"<?PremioTorneoCount?>", g_PvPEvents.premioItemCount, true);
				html = Utils::ReplaceString(html, L"<?PremioTorneoName?>", g_PvPEvents.premioItemName, true);
				html = Utils::ReplaceString(html, L"<?PremioTorneoIcon?>", g_PvPEvents.premioItemIcon, true);


				pUser->ShowHTML(L"pvpevent_anotado.htm", html.c_str(), 0);
			}
			else
			{
				const WCHAR* wHtml = g_HtmlCache.Get(L"pvpevent_agotado.htm");
				wstring html(wHtml);
				pUser->ShowHTML(L"pvpevent_agotado.htm", html.c_str(), 0);
				pUser->SendSystemMessage(L"Ya no queda lugar para continuar registrando.");
			}
		}
		else
		{
			CSystemMessage msg1(SystemMessage::S1_POPUP);
			msg1.AddText(L"No tienes los items necesarios.");
			pUser->pSocket->SendSystemMessage(&msg1);
		}
	}
	unguard;
	return true;
}

bool PvPEvents::BuilderCommand::EventManager(User *pUser, wstring wParams)
{
	guard;
		wstringstream paramStream(wParams);
		int team = 0, x = 0, y = 0, z = 0;
		if(paramStream >> team >> x >> y >> z)
		{
			User *pTarget = User::GetUserBySID(&pUser->targetId);
			if(pTarget->ValidUser())
			{
				pTarget->pED->inEventPvp = team;
				pTarget->SetUserInfoChanged();
				pTarget->SetCharInfoChanged();

				if (team != 0)
					PlayerAction::OnTeleportToLocation(pTarget, (int)x, (int)y, (int)z, false);
			}
			else
				pUser->SendSystemMessage(L"El target no es User*");
		}
		else
			pUser->SendSystemMessage(L"//ep [team 0/1/2] [locX] [locY] [locZ]");
	unguard;
	return true;
}

void PvPEvents::ValidateTerritory(User* pUser)
{
	guard;

	if(pUser->ValidUser())
	{
		TerritoryData& td = pUser->pSD->pExData->territoryData;
		//BlockItems zone
		if(pUser->pSD->nInBlockItemsZone || pUser->pED->inZoneCustomEventPvp)
		{
			//pUser->SendSystemMessage(L"estas adentro");
			if(td.territoryId[EVENT_PVP_ZONE] == 0)
			{
				//pUser->SendSystemMessage(L"salisto 0");
				pUser->pSD->nInBlockItemsZone = 0;
				pUser->pED->inZoneCustomEventPvp = false;
			}
			else
			{
				CEventPvPTerritory *pTerritory = g_TerritoryChecker.GetTerritory(td.territoryId[EVENT_PVP_ZONE])->SafeCastEventPvP();
				if(pTerritory)
				{
					for(int n=0;n<18;n++)
					{
						int nItemIndex = pUser->pSD->nEquipment[n];
						if(nItemIndex > 0)
						{
							CSharedItemData *pSID = CSharedItemData::FromIndex(nItemIndex);
							if(pSID)
							{
								if(CItemInfo *pWI = pSID->GetItemInfo())
								{
									if(pTerritory->IsBlocked(pWI->nCrystalType) && pTerritory->ItemsEscluidos(pSID->nItemID))
									{
										pUser->UnEquipItem(n);
									}
									else if(pTerritory->CanUseEnchant(pSID->nEnchantLevel))
									{
										pUser->UnEquipItem(n);
									}
								}
							}
						}
					}
				}
			}
		}else
		{
			if(td.territoryId[EVENT_PVP_ZONE])
			{
				//pUser->SendSystemMessage(L"Entraste a zona evento");
				pUser->pSD->nInBlockItemsZone = td.territoryId[EVENT_PVP_ZONE];
				pUser->pED->inZoneCustomEventPvp = true;
				//check items
				CEventPvPTerritory *pTerritory = g_TerritoryChecker.GetTerritory(td.territoryId[EVENT_PVP_ZONE])->SafeCastEventPvP();
				if(pTerritory)
				{
					if(!pTerritory->CanEnterLevel(pUser->pSD->nLevel))
					{
						IVector ipos(pTerritory->GetKickOutLocation());
						pUser->SendSystemMessage(L"No tienes el nivel para ingresar a esta zona!");
						PlayerAction::OnTeleportToLocation(pUser, ipos.x, ipos.y, ipos.z, false);
					}

					if(!pTerritory->CanEnterClase(pUser->pSD->nClass))
					{
						IVector ipos(pTerritory->GetKickOutLocation());
						pUser->SendSystemMessage(L"Tu clase no puede ingresar a esta zona!");
						PlayerAction::OnTeleportToLocation(pUser, ipos.x, ipos.y, ipos.z, false);
					}

					if (!pUser->pED->inEventPvp && !pUser->pSD->nBuilder)
					{
						IVector ipos(pTerritory->GetKickOutLocation());
						pUser->SendSystemMessage(L"No puedes ingresar a la zona de arena!");
						PlayerAction::OnTeleportToLocation(pUser, ipos.x, ipos.y, ipos.z, false);
					}

					for(int n=0;n<18;n++)
					{
						int nItemIndex = pUser->pSD->nEquipment[n];
						if(nItemIndex > 0)
						{
							CSharedItemData *pSID = CSharedItemData::FromIndex(nItemIndex);
							if(pSID)
							{
								if(CItemInfo *pWI = pSID->GetItemInfo())
								{
									if(pTerritory->IsBlocked(pWI->nCrystalType) && pTerritory->ItemsEscluidos(pSID->nItemID))
									{
										pUser->UnEquipItem(n);
									}
									else if(pTerritory->CanUseEnchant(pSID->nEnchantLevel))
									{
										pUser->UnEquipItem(n);
									}
								}
							}
						}
					}
				}
			}
		}
	}

	unguard;
}


