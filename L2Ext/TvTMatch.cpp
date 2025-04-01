#include "stdafx.h"
#include "TvTMatch.h"
#include "NpcServer.h"
#include "Door.h"
#include "PlayerAction.h"
#include "TvT.h"
#include "EventStats.h"
#include "DB.h"
#include "Achivments.h"

using namespace TvT;

CMatch::CMatch(TvT::TvTInfo *pInfo) : m_state(TvT::StateNone), m_startTime(0), m_stateTime(0), m_winnerTeam(TvT::TeamNone), m_managerServerId(0), m_managerServerId2(0), m_managerServerId3(0),m_managerServerId12(0), m_managerServerId13(0), m_managerServerId14(0), m_managerServerId15(0) ,m_managerServerId16(0) , m_buffer1(0), m_buffer2(0), m_buffer3(0), m_buffer4(0), m_killCountBlue(0), m_killCountRed(0), m_KoreanBlue(1), m_KoreanRed(1), m_KoreanWinner(0), m_FlagsSpawned(false), m_ctfCaptureCountBlue(0), m_ctfCaptureCountRed(0), m_CtfUserFlag_blue(0), m_CtfUserFlag_red(0), m_winnerTeamCapture(TvT::TeamNone), m_winnerTeamDestroyBase(TvT::TeamNone), m_BaseBlueDestroyed(0), m_BaseRedDestroyed(0), m_winnerTeamCastFortress(TvT::TeamNone), m_tomasCountBlue(0), m_tomasCountRed(0)
{
	InitializeCriticalSection(&m_lock);
	m_lpInfo = pInfo;
}

CMatch::~CMatch()
{
	DeleteCriticalSection(&m_lock);
}

void CMatch::Init()
{
	m_startTime = time(NULL);
	m_stateTime = time(NULL);
	m_state = TvT::StateRegistration;
	if(m_lpInfo && m_lpInfo->enabled)
	{
		if(m_lpInfo->registerNpcClassId)
		{
			//g_Log.Add(CLog::Error, "registerNpcClassId[%d], registerBufferId[%d]", m_lpInfo->registerNpcClassId,m_lpInfo->registerBufferId);
			//spawn npc
			map<wstring, wstring> aiParams;
			map<wstring, wstring> aiParams1;
			//aiParams.insert(pair<wstring, wstring>(L"fnHi", L"tvt_manager_001.htm"));
			aiParams.insert(pair<wstring, wstring>(L"fnHi", m_lpInfo->npchtmfile));
			m_managerServerId = NpcServer::SpawnNpcEx(m_lpInfo->registerNpcClassId, m_lpInfo->registerNpcPos.x, m_lpInfo->registerNpcPos.y, m_lpInfo->registerNpcPos.z, aiParams);
			m_managerServerId2 = NpcServer::SpawnNpcEx(m_lpInfo->registerNpcClassId, m_lpInfo->registerNpcPos1.x, m_lpInfo->registerNpcPos1.y, m_lpInfo->registerNpcPos1.z, aiParams);
			m_managerServerId3 = NpcServer::SpawnNpcEx(m_lpInfo->registerNpcClassId, m_lpInfo->registerNpcPos2.x, m_lpInfo->registerNpcPos2.y, m_lpInfo->registerNpcPos2.z, aiParams);
			aiParams1.insert(pair<wstring, wstring>(L"fnHi", m_lpInfo->npchtmfilebuffer));
			if(m_lpInfo->registerBufferId>0)
			{
				if(m_lpInfo->registerBufferPos1.x != 0)
					m_buffer1 = NpcServer::SpawnNpcEx(m_lpInfo->registerBufferId, m_lpInfo->registerBufferPos1.x, m_lpInfo->registerBufferPos1.y, m_lpInfo->registerBufferPos1.z, aiParams1);
				if(m_lpInfo->registerBufferPos2.x != 0)
					m_buffer2 = NpcServer::SpawnNpcEx(m_lpInfo->registerBufferId, m_lpInfo->registerBufferPos2.x, m_lpInfo->registerBufferPos2.y, m_lpInfo->registerBufferPos2.z, aiParams1);
				if(m_lpInfo->registerBufferPos3.x != 0)
					m_buffer3 = NpcServer::SpawnNpcEx(m_lpInfo->registerBufferId, m_lpInfo->registerBufferPos3.x, m_lpInfo->registerBufferPos3.y, m_lpInfo->registerBufferPos3.z, aiParams1);
				if(m_lpInfo->registerBufferPos4.x != 0)
					m_buffer4 = NpcServer::SpawnNpcEx(m_lpInfo->registerBufferId, m_lpInfo->registerBufferPos4.x, m_lpInfo->registerBufferPos4.y, m_lpInfo->registerBufferPos4.z, aiParams1);
			}

			/*1007023
150890 46888 -3408
150890 46550 -3408

148119 46888 -3408
148119 46550 -3408*/
		}

		if(m_lpInfo->BanderaRedNpcId)
		{
			//CAPTURE THE FLAG
			map<wstring, wstring> aiParams;
		//	aiParams.insert(pair<wstring, wstring>(L"fnHi", L"ctf.htm"));
			m_managerServerId12 = NpcServer::SpawnNpcEx(m_lpInfo->BanderaRedNpcId, m_lpInfo->BanderaRedNpcPos.x, m_lpInfo->BanderaRedNpcPos.y, m_lpInfo->BanderaRedNpcPos.z, aiParams);
			m_lpInfo->m_bluePosPosicion = 0;
			m_lpInfo->m_redPosPosicion = 0;
		}

		if(m_lpInfo->BanderaBlueNpcId)
		{
			//CAPTURE THE FLAG
			map<wstring, wstring> aiParams;
		//	aiParams.insert(pair<wstring, wstring>(L"fnHi", L"ctf.htm"));
			m_managerServerId13 = NpcServer::SpawnNpcEx(m_lpInfo->BanderaBlueNpcId, m_lpInfo->BanderaBlueNpcPos.x, m_lpInfo->BanderaBlueNpcPos.y, m_lpInfo->BanderaBlueNpcPos.z, aiParams);
			m_lpInfo->m_bluePosPosicion = 0;
			m_lpInfo->m_redPosPosicion = 0;
		}

		if(m_lpInfo->DestroyBaseRedNpcId)
		{
			//DESTROY THE BASE
			map<wstring, wstring> aiParams;
		//	aiParams.insert(pair<wstring, wstring>(L"fnHi", L"dtb.htm"));
			m_managerServerId14 = NpcServer::SpawnNpcEx(m_lpInfo->DestroyBaseRedNpcId, m_lpInfo->DestroyBaseRedNpcPos.x, m_lpInfo->DestroyBaseRedNpcPos.y, m_lpInfo->DestroyBaseRedNpcPos.z, aiParams);
			m_lpInfo->m_bluePosPosicion = 0;
			m_lpInfo->m_redPosPosicion = 0;
		}

		if(m_lpInfo->DestroyBaseBlueNpcId)
		{
			//DESTROY THE BASE
			map<wstring, wstring> aiParams;
		//	aiParams.insert(pair<wstring, wstring>(L"fnHi", L"dtb.htm"));
			m_managerServerId15 = NpcServer::SpawnNpcEx(m_lpInfo->DestroyBaseBlueNpcId, m_lpInfo->DestroyBaseBlueNpcPos.x, m_lpInfo->DestroyBaseBlueNpcPos.y, m_lpInfo->DestroyBaseBlueNpcPos.z, aiParams);
			m_lpInfo->m_bluePosPosicion = 0;
			m_lpInfo->m_redPosPosicion = 0;
		}

		if(m_lpInfo->FortressCrystalNpcId)
		{
			//DESTROY THE BASE
			map<wstring, wstring> aiParams;
		//	aiParams.insert(pair<wstring, wstring>(L"fnHi", L"dtb.htm"));
			m_managerServerId16 = NpcServer::SpawnNpcEx(m_lpInfo->FortressCrystalNpcId, m_lpInfo->FortressCrystalNpcPos.x, m_lpInfo->FortressCrystalNpcPos.y, m_lpInfo->FortressCrystalNpcPos.z, aiParams);
			m_lpInfo->m_bluePosPosicion = 0;
			m_lpInfo->m_redPosPosicion = 0;
		}

		if(m_lpInfo->registrationStartMsg1.size() > 0)
		{
			Utils::BroadcastToAllUser_Announce(m_lpInfo->registrationStartMsg1.c_str());
		}
		if(m_lpInfo->registrationStartMsg2.size() > 0)
		{
			Utils::BroadcastToAllUser_Announce(m_lpInfo->registrationStartMsg2.c_str());
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Invalid TvT info!", __FUNCTION__);
		m_state = TvT::StateDelete;
	}
}

void CMatch::OnDelete()
{
	if(m_lpInfo->finishTime > 0)
	{
		for(map<UINT, User*>::iterator Iter = m_users.begin();Iter!=m_users.end();Iter++)
		{
			User *pUser = Iter->second;
			if(pUser->ValidUser())
			{
				if(m_lpInfo->type == TvT::TvTFortress)
					g_TvT.FortressApplySkill(pUser);

				if(pUser->pED->tvtUser.orgPos.x != 0 || pUser->pED->tvtUser.orgPos.y != 0)
				{
					//delete the nobless
					if(m_lpInfo->skillPchId)
					{
						SkillPchId skill(m_lpInfo->skillPchId);
						pUser->DeleteSkill(skill.skillId);
						pUser->ValidateParameters();
					}
					if( m_lpInfo->type == 4 )
					{
						//Delete Protection Skill
						g_TvT.RemoveProtectionSkill(pUser);
					}
					if(!pUser->pSD->nAlive)
					{
						pUser->Revive();
					}

					if(g_EventStats.IsEnabled())
					{
						g_DB.RequestSaveEventStats(pUser->nDBID, pUser->pED->event_kills, pUser->pED->event_deaths);
					}
					pUser->StopMove();
					PlayerAction::OnTeleportToLocation(pUser, pUser->pED->tvtUser.orgPos.x, pUser->pED->tvtUser.orgPos.y, pUser->pED->tvtUser.orgPos.z, false);
				}
			}
		}
	}
	if(m_lpInfo->doorList.size() > 0)
	{
		//open doors
		for(list<wstring>::iterator Iter = m_lpInfo->doorList.begin(); Iter!= m_lpInfo->doorList.end();Iter++)
		{
			CDoor *pDoor = g_DoorDB.GetDoor(Iter->c_str());
			if(pDoor)
			{
				pDoor->Open();
			}
		}
	}

	if(m_lpInfo->MurallasList.size() > 0)
	{
		//close murallas
		for(list<wstring>::iterator Iter = m_lpInfo->MurallasList.begin(); Iter!= m_lpInfo->MurallasList.end();Iter++)
		{
			CDoor *pDoor = g_DoorDB.GetDoor(Iter->c_str());
			if(pDoor)
			{
				pDoor->pSD->hp=5000;
				pDoor->pSD->maxHp=10000;
				pDoor->pSD->breakable=0;
				pDoor->damageGrade = 0;
				pDoor->Close(false);
			}
		}
	}

	if(m_lpInfo->endEventMsg.size() > 0)
	{
		Utils::BroadcastToAllUser_Announce(m_lpInfo->endEventMsg.c_str());
	}

	for(map<UINT, User*>::iterator Iter = m_users.begin();Iter!=m_users.end();Iter++)
	{
		User *pUser = Iter->second;
		if(pUser->ValidUser())
		{
			pUser->pED->tvtUser.Clear();
			pUser->pSD->teamType = 0;
			wcscpy(pUser->wTitle, pUser->pED->OriginalwTitle);
//			pUser->pED->nameColorEx = pUser->pED->OriginalnameColorEx;
			pUser->pED->titleColorEx = pUser->pED->OriginaltitleColorEx;
			pUser->SetUserInfoChanged();
			pUser->SetCharInfoChanged();

		}
	}
	m_users.clear();
	if( m_lpInfo->type == 4 ) { m_Kusers.clear(); }
	//despawn npc
	if(m_managerServerId)
	{
		CNPC *pNpc = CNPC::GetNPCByServerId(&m_managerServerId);
		CNPC *pNpc2 = CNPC::GetNPCByServerId(&m_managerServerId2);
		CNPC *pNpc3 = CNPC::GetNPCByServerId(&m_managerServerId3);
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

		if(pNpc3)
		{
			if(pNpc3->pSD->nAlive)
			{
				pNpc3->KillNPC();
			}
		}else
			g_Log.Add(CLog::Error, "[%s] cannot find manager npc", __FUNCTION__);

		m_managerServerId = 0;
		m_managerServerId2 = 0;
		m_managerServerId3 = 0;
	}


	if(m_managerServerId12)//CAPTURE THE FLAG
	{
		CNPC *pNpc = CNPC::GetNPCByServerId(&m_managerServerId12);
		if(pNpc)
		{
			if(pNpc->pSD->nAlive)
			{
				pNpc->KillNPC();
			}
		}else
			g_Log.Add(CLog::Error, "[%s] cannot find CAPTURE THE FLAG npc", __FUNCTION__);

		m_managerServerId12 = 0;
	}

	if(m_managerServerId13)//CAPTURE THE FLAG
	{
		CNPC *pNpc = CNPC::GetNPCByServerId(&m_managerServerId13);
		if(pNpc)
		{
			if(pNpc->pSD->nAlive)
			{
				pNpc->KillNPC();
			}
		}else
			g_Log.Add(CLog::Error, "[%s] cannot find CAPTURE THE FLAG npc", __FUNCTION__);

		m_managerServerId13 = 0;
	}

	if(m_managerServerId14)//DESTROY THE BASE
	{
		CNPC *pNpc = CNPC::GetNPCByServerId(&m_managerServerId14);
		if(pNpc)
		{
			if(pNpc->pSD->nAlive)
			{
				pNpc->KillNPC();
			}
		}else
			g_Log.Add(CLog::Error, "[%s] cannot find DESTROY THE BASE npc", __FUNCTION__);

		m_managerServerId14 = 0;
	}

	if(m_managerServerId15)//DESTROY THE BASE
	{
		CNPC *pNpc = CNPC::GetNPCByServerId(&m_managerServerId15);
		if(pNpc)
		{
			if(pNpc->pSD->nAlive)
			{
				pNpc->KillNPC();
			}
		}else
			g_Log.Add(CLog::Error, "[%s] cannot find DESTROY THE BASE npc", __FUNCTION__);

		m_managerServerId15 = 0;
	}

	if(m_managerServerId16)//DESTROY THE BASE
	{
		CNPC *pNpc = CNPC::GetNPCByServerId(&m_managerServerId16);
		if(pNpc)
		{
			if(pNpc->pSD->nAlive)
			{
				pNpc->KillNPC();
			}
		}else
			g_Log.Add(CLog::Error, "[%s] cannot find FORTRESS CRYSTAL npc", __FUNCTION__);

		m_managerServerId16 = 0;
	}


}

void CMatch::OnFinish()
{
	m_stateTime = time(NULL);
	if(m_lpInfo->finishTime > 0)
	{
		m_state = TvT::StateFinish;
	}else
	{
		//just end
		m_state = TvT::StateDelete;
	}

	map<User*, UINT> m_winners;		//-----------TOP WINNERS
	for(map<UINT, User*>::iterator Iter = m_users.begin(); Iter!=m_users.end();Iter++)
	{
		User *pUser = Iter->second;
		if(pUser->ValidUser())
		{
			pUser->pED->m_CtfUserFlag = 0;
			if(m_lpInfo->rewardId > 0 && m_lpInfo->rewardCount > 0)
			{
				if(m_winnerTeam != TvT::TeamNone && m_winnerTeam == pUser->pED->tvtUser.team)
				{
					if(pUser->IsNowTrade())
						pUser->TradeCancel();

					double count = static_cast<double>(m_lpInfo->rewardCount);

					if(m_lpInfo->type == TvT::TvTCaptureTheFlag && m_winnerTeamCapture)
					{
						count += static_cast<double>(m_lpInfo->rewardCountForWinCapture);
					}
					if(m_lpInfo->type == TvT::TvTFortress && m_winnerTeamCastFortress)
					{
						count += static_cast<double>(m_lpInfo->rewardCountForWinCastFortress);
					}
					else if(m_lpInfo->type == TvT::TvTDestroyTheBase && m_winnerTeamDestroyBase)
					{
						count += static_cast<double>(m_lpInfo->rewardCountForWinDestroyBase);
						g_Achivments.SetUser_DestroyTheBase(pUser);
					}

					//double count = static_cast<double>(m_lpInfo->rewardCount);
					//count *= pUser->pED->itemBonus.Get(m_lpInfo->rewardId);
					pUser->AddItemToInventory(m_lpInfo->rewardId, m_lpInfo->rewardCount);
					g_Logger.Add(L"TvT Reward[%d][%d] User[%s]", m_lpInfo->rewardId, static_cast<INT32>(count), pUser->pSD->wszName);
					m_winners.insert(pair<User*, UINT>(Iter->second, Iter->first));

					if(m_lpInfo->type == TvT::TvTLastTeamStanding)
						g_Achivments.SetUser_LastTeamStanding(pUser);
				}
				else if(m_winnerTeam != TvT::TeamNone && m_winnerTeam != pUser->pED->tvtUser.team)
				{
					if(pUser->IsNowTrade())
						pUser->TradeCancel();

					double count = static_cast<double>(m_lpInfo->rewardLostCount);
					//count *= pUser->pED->itemBonus.Get(m_lpInfo->rewardLostId);
					pUser->AddItemToInventory(m_lpInfo->rewardLostId, static_cast<INT32>(count));
					g_Logger.Add(L"TvT Lost Reward[%d][%d] User[%s]", m_lpInfo->rewardLostId, static_cast<INT32>(count), pUser->pSD->wszName);
				}
			}
			if(m_lpInfo->rewardIdTie > 0 && m_lpInfo->rewardCountTie > 0)
			{
				if(m_winnerTeam == TvT::TeamNone)
				{
					if(pUser->IsNowTrade())
						pUser->TradeCancel();

					m_winners.insert(pair<User*, UINT>(Iter->second, Iter->first));
					//double count = static_cast<double>(m_lpInfo->rewardCountTie);
					//count *= pUser->pED->itemBonus.Get(m_lpInfo->rewardIdTie);
					pUser->AddItemToInventory(m_lpInfo->rewardId, m_lpInfo->rewardCountTie);
					g_Logger.Add(L"TvT Reward[%d][%d] User[%s]", m_lpInfo->rewardIdTie, m_lpInfo->rewardCountTie, pUser->pSD->wszName);
				}
			}
			pUser->pED->tvtUser.status = TvT::UserFinishing;


			if(m_winnerTeam != TvT::TeamNone && m_winnerTeam == pUser->pED->tvtUser.team)
			{
				if (m_lpInfo->nFireworkId >0)
				{
					if(CSkillInfo *pSI = g_SkillDB.GetSkillInfo(m_lpInfo->nFireworkId, 1))
					{
						pSI->ActivateSkill(pUser, pUser);
						CSkillFx::BroadcastAutoCastSkill(pUser->CastCreature()->nObjectID,pUser->CastCreature()->nObjectID, m_lpInfo->nFireworkId, 1, &pUser->CastCreature()->pSD->Pos);
					}
				}
			}

			if(pUser->pSD->nAlive == 0)
				pUser->Revive();


			if(m_lpInfo->ResetBuffsOnFinish)
				pUser->DispelAllByGM();
		}
	}
	//broadcast who the winner is
	if(m_winnerTeam == TvT::TeamNone)
	{
		if(m_lpInfo->endMsg[0].size() > 0)
		{
			Utils::BroadcastToAllUser_Announce(m_lpInfo->endMsg[0].c_str());
		}
	}else if(m_winnerTeam == TvT::TeamBlue)
	{
		if(m_lpInfo->endMsg[1].size() > 0)
		{
			tstring announce = m_lpInfo->endMsg[3];
			announce = Utils::ReplaceString(announce, _T("[bluekills]"), m_killCountBlue, true);
			announce = Utils::ReplaceString(announce, _T("[redkills]"), m_killCountRed, true);
			Utils::BroadcastToAllUser_Announce(announce.c_str());
			Utils::BroadcastToAllUser_Announce(m_lpInfo->endMsg[1].c_str());
		}
	}if(m_winnerTeam == TvT::TeamRed)
	{
		if(m_lpInfo->endMsg[2].size() > 0)
		{
			tstring announce = m_lpInfo->endMsg[4];
			announce = Utils::ReplaceString(announce, _T("[bluekills]"), m_killCountBlue, true);
			announce = Utils::ReplaceString(announce, _T("[redkills]"), m_killCountRed, true);
			Utils::BroadcastToAllUser_Announce(announce.c_str());
			Utils::BroadcastToAllUser_Announce(m_lpInfo->endMsg[2].c_str());
		}
	}

//-----------TOP WINNERS


	int nWinnerKill_1 = 0;
	int nWinnerKill_2 = 0;
	int nWinnerKill_3 = 0;
	int nWinnerKill_4 = 0;
	int nWinnerKill_5 = 0;
	User* nWinnerUser_1;
	User* nWinnerUser_2;
	User* nWinnerUser_3;
	User* nWinnerUser_4;
	User* nWinnerUser_5;

	for(map<UINT, User*>::iterator Iter = m_users.begin(); Iter!=m_users.end();Iter++)
//	for(map<User*, UINT>::iterator Iter = m_winners.begin(); Iter!=m_winners.end();Iter++)
	{
		//User *pUser = Iter->first;
		User *pUser = Iter->second;
		if(pUser->ValidUser())
		{
			if ( pUser->pED->tvtUser.killCount > nWinnerKill_1)
			{
				nWinnerKill_1 = pUser->pED->tvtUser.killCount;
				nWinnerUser_1 = pUser;
			}
		}
	}

	for(map<UINT, User*>::iterator Iter = m_users.begin(); Iter!=m_users.end();Iter++)
//	for(map<User*, UINT>::iterator Iter = m_winners.begin(); Iter!=m_winners.end();Iter++)
	{
		//User *pUser = Iter->first;
		User *pUser = Iter->second;
		if(pUser->ValidUser())
		{
			if ( pUser->pED->tvtUser.killCount > nWinnerKill_2 && pUser != nWinnerUser_1)
			{
				nWinnerKill_2 = pUser->pED->tvtUser.killCount;
				nWinnerUser_2 = pUser;
			}
		}
	}

	for(map<UINT, User*>::iterator Iter = m_users.begin(); Iter!=m_users.end();Iter++)
//	for(map<User*, UINT>::iterator Iter = m_winners.begin(); Iter!=m_winners.end();Iter++)
	{
		//User *pUser = Iter->first;
		User *pUser = Iter->second;
		if(pUser->ValidUser())
		{
			if ( pUser->pED->tvtUser.killCount > nWinnerKill_3 && pUser != nWinnerUser_1 && pUser != nWinnerUser_2)
			{
				nWinnerKill_3 = pUser->pED->tvtUser.killCount;
				nWinnerUser_3 = pUser;
			}
		}
	}

	for(map<UINT, User*>::iterator Iter = m_users.begin(); Iter!=m_users.end();Iter++)
//	for(map<User*, UINT>::iterator Iter = m_winners.begin(); Iter!=m_winners.end();Iter++)
	{
		//User *pUser = Iter->first;
		User *pUser = Iter->second;
		if(pUser->ValidUser())
		{
			if ( pUser->pED->tvtUser.killCount > nWinnerKill_4 && pUser != nWinnerUser_1 && pUser != nWinnerUser_2 && pUser != nWinnerUser_3)
			{
				nWinnerKill_4 = pUser->pED->tvtUser.killCount;
				nWinnerUser_4 = pUser;
			}
		}
	}

	for(map<UINT, User*>::iterator Iter = m_users.begin(); Iter!=m_users.end();Iter++)
//	for(map<User*, UINT>::iterator Iter = m_winners.begin(); Iter!=m_winners.end();Iter++)
	{
		//User *pUser = Iter->first;
		User *pUser = Iter->second;
		if(pUser->ValidUser())
		{
			if ( pUser->pED->tvtUser.killCount > nWinnerKill_5 && pUser != nWinnerUser_1 && pUser != nWinnerUser_2 && pUser != nWinnerUser_3 && pUser != nWinnerUser_4)
			{
				nWinnerKill_5 = pUser->pED->tvtUser.killCount;
				nWinnerUser_5 = pUser;
			}
		}
	}

	if (nWinnerUser_1->ValidUser() && m_lpInfo->rank_rewardId_1 > 0 && m_lpInfo->rank_rewardCount_1 > 0)
	{
		nWinnerUser_1->AddItemToInventory(m_lpInfo->rank_rewardId_1, static_cast<INT32>(m_lpInfo->rank_rewardCount_1));
		if(m_lpInfo->rank_rewardMsg_1.size() > 0)
		{
			tstring announce = m_lpInfo->rank_rewardMsg_1;
			announce = Utils::ReplaceString(announce, _T("[player_name]"), nWinnerUser_1->pSD->wszName, true);
			announce = Utils::ReplaceString(announce, _T("[kills]"), nWinnerUser_1->pED->tvtUser.killCount, true);
			Utils::BroadcastToAllUser_Announce(announce.c_str());
		}
		g_Logger.Add(L"TvT Reward TOP_1 [%d][%d] User[%s]", m_lpInfo->rank_rewardId_1, static_cast<INT32>(m_lpInfo->rank_rewardCount_1), nWinnerUser_1->pSD->wszName);
	}

	if (nWinnerUser_2->ValidUser() && m_lpInfo->rank_rewardId_2 > 0 && m_lpInfo->rank_rewardCount_2 > 0)
	{
		nWinnerUser_2->AddItemToInventory(m_lpInfo->rank_rewardId_2, static_cast<INT32>(m_lpInfo->rank_rewardCount_2));
		if(m_lpInfo->rank_rewardMsg_2.size() > 0)
		{
			tstring announce = m_lpInfo->rank_rewardMsg_2;
			announce = Utils::ReplaceString(announce, _T("[player_name]"), nWinnerUser_2->pSD->wszName, true);
			announce = Utils::ReplaceString(announce, _T("[kills]"), nWinnerUser_2->pED->tvtUser.killCount, true);
			Utils::BroadcastToAllUser_Announce(announce.c_str());
			g_Logger.Add(L"TvT Reward TOP_2 [%d][%d] User[%s]", m_lpInfo->rank_rewardId_2, static_cast<INT32>(m_lpInfo->rank_rewardCount_2), nWinnerUser_2->pSD->wszName);
		}
	}

	if (nWinnerUser_3->ValidUser() && m_lpInfo->rank_rewardId_3 > 0 && m_lpInfo->rank_rewardCount_3 > 0)
	{
		nWinnerUser_3->AddItemToInventory(m_lpInfo->rank_rewardId_3, static_cast<INT32>(m_lpInfo->rank_rewardCount_3));
		if(m_lpInfo->rank_rewardMsg_3.size() > 0)
		{
			tstring announce = m_lpInfo->rank_rewardMsg_3;
			announce = Utils::ReplaceString(announce, _T("[player_name]"), nWinnerUser_3->pSD->wszName, true);
			announce = Utils::ReplaceString(announce, _T("[kills]"), nWinnerUser_3->pED->tvtUser.killCount, true);
			Utils::BroadcastToAllUser_Announce(announce.c_str());
		}
		g_Logger.Add(L"TvT Reward TOP_3 [%d][%d] User[%s]", m_lpInfo->rank_rewardId_3, static_cast<INT32>(m_lpInfo->rank_rewardCount_3), nWinnerUser_3->pSD->wszName);
	}

	if (nWinnerUser_4->ValidUser() && m_lpInfo->rank_rewardId_4 > 0 && m_lpInfo->rank_rewardCount_4 > 0)
	{
		nWinnerUser_4->AddItemToInventory(m_lpInfo->rank_rewardId_4, static_cast<INT32>(m_lpInfo->rank_rewardCount_4));
		if(m_lpInfo->rank_rewardMsg_4.size() > 0)
		{
			tstring announce = m_lpInfo->rank_rewardMsg_4;
			announce = Utils::ReplaceString(announce, _T("[player_name]"), nWinnerUser_4->pSD->wszName, true);
			announce = Utils::ReplaceString(announce, _T("[kills]"), nWinnerUser_4->pED->tvtUser.killCount, true);
			Utils::BroadcastToAllUser_Announce(announce.c_str());
		}
		g_Logger.Add(L"TvT Reward TOP_4 [%d][%d] User[%s]", m_lpInfo->rank_rewardId_4, static_cast<INT32>(m_lpInfo->rank_rewardCount_4), nWinnerUser_4->pSD->wszName);
	}

	if (nWinnerUser_5->ValidUser() && m_lpInfo->rank_rewardId_5 > 0 && m_lpInfo->rank_rewardCount_5 > 0)
	{
		nWinnerUser_5->AddItemToInventory(m_lpInfo->rank_rewardId_5, static_cast<INT32>(m_lpInfo->rank_rewardCount_5));
		if(m_lpInfo->rank_rewardMsg_5.size() > 0)
		{
			tstring announce = m_lpInfo->rank_rewardMsg_5;
			announce = Utils::ReplaceString(announce, _T("[player_name]"), nWinnerUser_5->pSD->wszName, true);
			announce = Utils::ReplaceString(announce, _T("[kills]"), nWinnerUser_5->pED->tvtUser.killCount, true);
			Utils::BroadcastToAllUser_Announce(announce.c_str());
		}
		g_Logger.Add(L"TvT Reward TOP_5 [%d][%d] User[%s]", m_lpInfo->rank_rewardId_5, static_cast<INT32>(m_lpInfo->rank_rewardCount_5), nWinnerUser_5->pSD->wszName);
	}
//----END-------TOP WINNERS
}

void CMatch::Broadcast(const char *format, ...)
{
	va_list va;
	va_start(va, format);

	char buff[8190];
	int len = Utils::VAssemble(buff, 8190, format, va);
	va_end(va);

	for(map<UINT, User*>::iterator Iter = m_users.begin();Iter!=m_users.end();Iter++)
	{
		User *pUser = Iter->second;
		if(pUser->ValidUser())
		{
			pUser->pSocket->Send("b", len, buff);
		}
	}
}

bool CMatch::ValidateWinner( bool timeout )
{
	if(m_state == TvT::StateFight)
	{
		UINT blueAlive = 0;
		UINT redAlive = 0;

		try
		{
			for(map<UINT, User*>::iterator Iter = m_users.begin();Iter!=m_users.end();Iter++)
			{
				if(User *pUser = Iter->second->SafeCastUser())
				{
					if(pUser->ValidUser())
					{
						if(pUser->pED)
						{
							if(pUser->pED->tvtUser.status == TvT::UserFighting)
							{
								if(pUser->pED->tvtUser.team == TvT::TeamBlue)
									blueAlive++;
								else if(pUser->pED->tvtUser.team == TvT::TeamRed)
									redAlive++;
							}
						}
					}
				}
			}
		}catch(...)
		{
			//	EXCEPTION_LOG;
		}

		if (m_lpInfo->MaximoVidasPorEquipo > 0)
		{
			if(m_killCountRed >= m_lpInfo->MaximoVidasPorEquipo)
			{
				m_winnerTeam = TvT::TeamRed;
				return true;
			}
			else if(m_killCountBlue >= m_lpInfo->MaximoVidasPorEquipo)
			{
				m_winnerTeam = TvT::TeamBlue;
				return true;
			}
		}

		if(blueAlive == 0 || redAlive == 0)
		{
			if(blueAlive == 0)
				m_winnerTeam = TvT::TeamRed;
			if(redAlive == 0)
				m_winnerTeam = TvT::TeamBlue;
			if(blueAlive == redAlive && blueAlive == 0)
				m_winnerTeam = TvT::TeamNone;

			return true;
		}
		if(timeout)
		{
			if(m_lpInfo->type == TvT::TvTLastTeamStanding)
			{
				if(blueAlive > redAlive)
				{
					m_winnerTeam = TvT::TeamBlue;
				}else if(redAlive > blueAlive)
				{
					m_winnerTeam = TvT::TeamRed;
				}
			}else if(m_lpInfo->type == TvT::TvTDeathMatch || m_lpInfo->type == TvT::TvTCaptureTheFlag || m_lpInfo->type == TvT::TvTCastle)
			{
				if(m_killCountBlue > m_killCountRed)
				{
					m_winnerTeam = TvT::TeamBlue;
				}else if(m_killCountRed > m_killCountBlue)
				{
					m_winnerTeam = TvT::TeamRed;
				}else
				{
					m_winnerTeam = TvT::TeamNone;
				}
			}else if(m_lpInfo->type == TvT::TvTCaptureTheFlag2)
			{
				if(m_ctfCaptureCountBlue > m_ctfCaptureCountRed)
				{
					m_winnerTeam = TvT::TeamBlue;
					m_winnerTeamCapture = TvT::TeamBlue;
				}else if(m_ctfCaptureCountRed > m_ctfCaptureCountBlue)
				{
					m_winnerTeam = TvT::TeamRed;
					m_winnerTeamCapture = TvT::TeamRed;
				}
				else
				{
					if(m_killCountBlue > m_killCountRed)
					{
						m_winnerTeam = TvT::TeamBlue;
						m_winnerTeamCapture = TvT::TeamNone;
					}else if(m_killCountRed > m_killCountBlue)
					{
						m_winnerTeam = TvT::TeamRed;
						m_winnerTeamCapture = TvT::TeamNone;
					}else
					{
						m_winnerTeam = TvT::TeamNone;
						m_winnerTeamCapture = TvT::TeamNone;
					}
				}
			}else if(m_lpInfo->type == TvT::TvTFortress)
			{
				if(m_tomasCountBlue > m_tomasCountRed)
				{
					m_winnerTeam = TvT::TeamBlue;
					m_winnerTeamCastFortress = TvT::TeamBlue;
				}else if(m_tomasCountRed > m_tomasCountBlue)
				{
					m_winnerTeam = TvT::TeamRed;
					m_winnerTeamCastFortress = TvT::TeamRed;
				}
				else
				{
					if(m_killCountBlue > m_killCountRed)
					{
						m_winnerTeam = TvT::TeamBlue;
						m_winnerTeamCastFortress = TvT::TeamNone;
					}else if(m_killCountRed > m_killCountBlue)
					{
						m_winnerTeam = TvT::TeamRed;
						m_winnerTeamCastFortress = TvT::TeamNone;
					}else
					{
						m_winnerTeam = TvT::TeamNone;
						m_winnerTeamCastFortress = TvT::TeamNone;
					}
				}
			}else if(m_lpInfo->type == TvT::TvTDestroyTheBase)
			{
				if(m_BaseBlueDestroyed > m_BaseRedDestroyed)
				{
					m_winnerTeam = TvT::TeamBlue;
					m_winnerTeamDestroyBase = TvT::TeamBlue;
				}else if(m_BaseRedDestroyed > m_BaseBlueDestroyed)
				{
					m_winnerTeam = TvT::TeamRed;
					m_winnerTeamDestroyBase = TvT::TeamRed;
				}
				else
				{
					if(m_killCountBlue > m_killCountRed)
					{
						m_winnerTeam = TvT::TeamBlue;
						m_winnerTeamDestroyBase = TvT::TeamNone;
					}else if(m_killCountRed > m_killCountBlue)
					{
						m_winnerTeam = TvT::TeamRed;
						m_winnerTeamDestroyBase = TvT::TeamNone;
					}else
					{
						m_winnerTeam = TvT::TeamNone;
						m_winnerTeamDestroyBase = TvT::TeamNone;
					}
				}
			}else if(m_lpInfo->type == TvT::TvTFortress)
			{

			}
		}
	}
	return false;
}

void CMatch::RandomizeTeams()
{
	guard;

	size_t total = m_users.size();
	UINT red = 0;
	UINT blue = 0;

	for(map<UINT, User*>::iterator it = m_users.begin();it!=m_users.end();it++)
	{
		if(User *pUser = it->second->SafeCastUser())
		{
			TeamType team = TeamBlue;
			if(red == blue)
			{
				if(g_Random.RandInt(2) == 1)
				{
					team = TeamRed;
				}
			}else if( blue > red)
			{
				team = TeamRed;
			}
			if(team == TeamRed)
				red++;
			else
				blue++;

			pUser->pED->tvtUser.team = team;
		}
	}

	unguard;
}

bool CMatch::PickPlayers(bool nIsCTF)
{
	guard;

	size_t total = m_users.size();
	int red = 0;
	int blue = 0;

	int parti_players = m_lpInfo->participateplayers;
	BOOL finish = false;
	BOOL parti_compl = false;

	if( m_users.size() < 3 )
		return false;

	while( !parti_compl )
	{
		if( m_users.size() > parti_players )
		{
			parti_compl = true;
		}
		else if( m_users.size() < parti_players )
		{
			parti_players = parti_players - 2;
			parti_compl = false;
		}
		else if( m_users.size() == parti_players )
		{
			parti_compl = true;
		}
	}
	m_lpInfo->participateplayers = parti_players;

	int to_red = parti_players / 2;
	int to_blue = parti_players / 2;

	while( !finish )
	{
		for(map<UINT, User*>::iterator it = m_users.begin();it!=m_users.end();it++)
		{
			if(User *pUser = it->second->SafeCastUser())
			{
				if( pUser->pED->tvtUser.team == TeamNone )
				{
					if(g_Random.RandInt(4) == 1)
					{
						if( blue < to_blue)
						{
							blue++;
							pUser->pED->tvtUser.team = TeamBlue;

							//2657	1	a,You have been choosen to play on Korean Event.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
							//pUser->SendSystemMessage(2657);

							if( m_lpInfo->type == TvT::TvTKorean )
								pUser->SendSystemMessageGreen(L"You have been choosen to play on Korean Event.");
							else if(m_lpInfo->type == TvT::TvTCaptureTheFlag)
								pUser->SendSystemMessageGreen(L"You have been choosen to play on CTF Event.");

						}
						else if( red < to_red)
						{
							red++;
							pUser->pED->tvtUser.team = TeamRed;

							//2657	1	a,You have been choosen to play on Korean Event.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
							//pUser->SendSystemMessage(2657);

							if( m_lpInfo->type == TvT::TvTKorean )
								pUser->SendSystemMessageGreen(L"You have been choosen to play on Korean Event.");
							else if(m_lpInfo->type == TvT::TvTCaptureTheFlag)
								pUser->SendSystemMessageGreen(L"You have been choosen to play on CTF Event.");
						}
						else
						{
							//nothing...
						}
					}
				}
			}
			
		}

		if( (blue+red) == parti_players )
		{
			finish = true;
		}
	}

	unguard;

	return finish;
}

bool CMatch::PickPlayersLastMan()
{
	guard;

	size_t total = m_users.size();
	int blue = 0;

	int parti_players = m_lpInfo->participateplayers;
	BOOL finish = false;
	BOOL parti_compl = false;

	if( m_users.size() < 3 )
		return false;

	while( !parti_compl )
	{
		if( m_users.size() > parti_players )
		{
			parti_compl = true;
		}
		else if( m_users.size() < parti_players )
		{
			parti_players = parti_players - 2;
			parti_compl = false;
		}
		else if( m_users.size() == parti_players )
		{
			parti_compl = true;
		}
	}
	m_lpInfo->participateplayers = parti_players;

	int to_blue = parti_players;

	while( !finish )
	{
		for(map<UINT, User*>::iterator it = m_users.begin();it!=m_users.end();it++)
		{
			if(User *pUser = it->second->SafeCastUser())
			{
				if( pUser->pED->tvtUser.team == TeamNone )
				{
					if(g_Random.RandInt(4) == 1)
					{
						blue++;
						pUser->pED->tvtUser.team = TeamBlue;

						//2657	1	a,You have been choosen to play on Korean Event.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
						//pUser->SendSystemMessage(2657);

						if( m_lpInfo->type == TvT::TvTLastManStanding )
							pUser->SendSystemMessageGreen(L"You have been choosen to play on Last Man Standing Event.");
					}
				}
			}
			
		}

		if( blue == parti_players )
		{
			finish = true;
		}
	}

	unguard;

	return finish;
}

void CMatch::RemovePlayers()
{
	guard;

	for(map<UINT, User*>::iterator it = m_users.begin();it!=m_users.end();it++)
	{
		if(User *pUser = it->second->SafeCastUser())
		{
			if(pUser->pED->tvtUser.team == TeamNone)
			{
				pUser->pED->tvtUser.Clear();
				pUser->pSD->teamType = 0;
				//2658	1	a,Unfortunately you wont participate on the event.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
				//pUser->SendSystemMessage(2658);
				pUser->SendSystemMessageRed(L"Unfortunately you wont participate on the event.");
				m_users.erase(it);
			}
		}
	}

	unguard;
}


