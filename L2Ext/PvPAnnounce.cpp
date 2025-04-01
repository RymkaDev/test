#include "stdafx.h"
#include "PvPAnnounce.h"
#include "License.h"

using namespace License;

extern INT32 auraMsgId;

namespace PvP
{
	CPvPAnnounce::CPvPAnnounce() : m_Enabled(false), m_IncludePK(false), m_IncludeBattleZone(false), m_KillReuse(60)
	{

	}

	CPvPAnnounce::CPvPAnnounce(const PvP::CPvPAnnounce &copy)
	{

	}

	CPvPAnnounce& CPvPAnnounce::GetInstance()
	{
		static CPvPAnnounce m_Instance;
		return m_Instance;
	}

	
#pragma optimize("", off)

	void CPvPAnnounce::Init()
	{
		VIRTUALIZER_TIGER_BLACK_START;
		m_Enabled = false;
		if(CLicense::GetInstance().CanUse(License::LicensePvPAnnounce))
		{
			LoadINI();
			if(m_Enabled)
			{
				g_Log.Add(CLog::Blue, "[%s] Feature is enabled, loaded [%d] messages.", __FUNCTION__, m_Messages.size());
			}
		}
		VIRTUALIZER_TIGER_BLACK_END;
	}
/* INI Config
[PvPAnnounce]
Enabled=0
;If set to 1 it will also count pk kills
IncludePK=1
;If set to 1 it will also count kills in PvP Zone / Combat Zone
IncludeBattleZone=1
;Count of custom messages in from client side
MessageCount=6
;6515	1	a,$s1 Killing spree!\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
;6516	1	a,$s1 Rampage!\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
;6517	1	a,$s1 Unstoppable!\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
;6518	1	a,$s1 Dominating!\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
;6519	1	a,$s1 Godlike!\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
;6520	1	a,$s1 Legendary!\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
Message_1_ID=6515
Message_1_KillCount=3
;Range how far the message will be send (0 means to all players in game)
Message_1_Range=6000
Message_2_ID=6516
Message_2_KillCount=5
Message_2_Range=9000
Message_3_ID=6517
Message_3_KillCount=6
Message_3_Range=12000
Message_4_ID=6518
Message_4_KillCount=8
Message_4_Range=24000
Message_5_ID=6519
Message_5_KillCount=10
Message_5_Range=0
Message_6_ID=6520
Message_6_KillCount=15
Message_6_Range=0
*/
	void CPvPAnnounce::LoadINI()
	{
		VIRTUALIZER_TIGER_BLACK_START;
		m_Messages.clear();
		if(CLicense::GetInstance().CanUse(License::LicensePvPAnnounce))
		{
			const TCHAR* section = _T("PvPAnnounce");
			m_Enabled = GetPrivateProfileInt(section, _T("Enabled"), 0, g_ConfigFile) ? true : false;
			m_IncludePK = GetPrivateProfileInt(section, _T("IncludePK"), 0, g_ConfigFile) ? true : false;
			m_IncludeBattleZone = GetPrivateProfileInt(section, _T("IncludeBattleZone"), 0, g_ConfigFile) ? true : false;
			m_KillReuse = GetPrivateProfileInt(section, _T("KillReuse"), 60, g_ConfigFile);
			UINT msgCount = GetPrivateProfileInt(section, _T("MessageCount"), 0, g_ConfigFile);
			while(msgCount > 0)
			{
				wchar_t idParam[32] = { 0 };
				wchar_t mensajeParam[32] = { 0 };
				wchar_t killCountParam[32] = { 0 };
				wchar_t rangeParam[32] = { 0 };
				wchar_t idReward[32] = { 0 };
				wchar_t idQuanity[32] = { 0 };
				wchar_t nMostrarZona[32] = { 0 };
				swprintf(idParam, _countof(idParam), L"Message_%u_ID", msgCount);
				swprintf(mensajeParam, _countof(mensajeParam), L"Message_%u_mensaje", msgCount);
				swprintf(killCountParam, _countof(killCountParam), L"Message_%u_KillCount", msgCount);
				swprintf(rangeParam, _countof(rangeParam), L"Message_%u_Range", msgCount);
				swprintf(idReward, _countof(idReward), L"Message_%u_RewardID", msgCount);
				swprintf(idQuanity, _countof(idQuanity), L"Message_%u_RewardQua", msgCount);

				swprintf(nMostrarZona, _countof(nMostrarZona), L"Message_%u_MostrarZona", msgCount);


				MessageInfo mi;
				mi.messageId = GetPrivateProfileInt(section, idParam, 0, g_ConfigFile);


				TCHAR temp1[8192];
				if(GetPrivateProfileString(section, mensajeParam, 0, temp1, 8190, g_ConfigFile))
					mi.mensaje = temp1;



				mi.killCount = GetPrivateProfileInt(section, killCountParam, 0, g_ConfigFile);


				mi.MostrarZona = GetPrivateProfileInt(section, nMostrarZona, 0, g_ConfigFile);

				mi.range = GetPrivateProfileInt(section, rangeParam, 0, g_ConfigFile);
				if( GetPrivateProfileInt(section, idReward, 0, g_ConfigFile) > 0 && GetPrivateProfileInt(section, idQuanity, 0, g_ConfigFile) > 0 )
				{		
					mi.rewardid = GetPrivateProfileInt(section, idReward, 0, g_ConfigFile);
					mi.rewardquanity = GetPrivateProfileInt(section, idQuanity, 0, g_ConfigFile);
				}
				else
				{
					mi.rewardid = 0;
					mi.rewardquanity = 0;
				}

	//			g_Log.Add(CLog::Blue, "[%s] [%S], [%S], [%S]", __FUNCTION__, idParam, killCountParam, rangeParam);

				if(mi.messageId > 0 && mi.killCount > 0)
				{
					m_Messages.push_back(mi);
				}
				msgCount--;
			}
		}
		VIRTUALIZER_TIGER_BLACK_END;
	}

	
#pragma optimize("", on)

	const CPvPAnnounce::MessageInfo& CPvPAnnounce::GetMessage(INT32 killCount) const
	{
		static MessageInfo empty = { 0, 0, 0 };

		for(size_t n = 0; n < m_Messages.size(); n++)
		{
			if(m_Messages[n].killCount == killCount)
			{
				return m_Messages[n];
			}
		}

		return empty;
	}

	bool CPvPAnnounce::OnKill(User *pKiller, User *pVictim, bool isPK, bool battleZone) const
	{
		bool result = false;

		time_t currentTime = time(0);

//		g_Log.Add(CLog::Blue, "[%s] isPK[%d][%d] battleZone[%d][%d], killReuse[%d]", __FUNCTION__, m_IncludePK, isPK, m_IncludeBattleZone, battleZone, m_KillReuse);
		if(m_IncludePK || !isPK)
		{
			if(m_IncludeBattleZone || !battleZone)
			{
				PvPAnnounceUser& pau = pKiller->pED->pvpAnnUser;
				if( m_KillReuse == 0 || ( (pau.lastKillTime + m_KillReuse) > currentTime ) )
				{
					pau.killCount++;
				}else
				{
					pau.killCount = 1;
				}
				pau.lastKillTime = currentTime;

				const MessageInfo& mi = GetMessage(pau.killCount);
//				g_Log.Add(CLog::Blue, "[%s] msgId[%d] killCount[%d] lkt[%d] ct[%d]", __FUNCTION__, mi.messageId, pau.killCount, pau.lastKillTime, currentTime);
				if(mi.messageId > 0)
				{
					CSystemMessage msg(mi.messageId);

					if (mi.MostrarZona)
					{
						wstringstream name;
						name << pKiller->pSD->wszName;
						wstring charname;
						name >> charname;

						wstringstream name2;
						name2 << pVictim->pSD->wszName;
						wstring charname2;
						name2 >> charname2;

						wstring announce = mi.mensaje.c_str();
						size_t pos = announce.find(L"$charname");
						while(pos != wstring::npos)
						{
							announce = announce.replace(pos, 9, charname);
							pos = announce.find(L"$charname");
						}

						pos = announce.find(L"$charvictim");
						while(pos != wstring::npos)
						{
							announce = announce.replace(pos, 11, charname2);
							pos = announce.find(L"$charvictim");
						}


						msg.AddZone(pKiller->pSD->Pos.x, pKiller->pSD->Pos.y, pKiller->pSD->Pos.z);
						msg.AddText(announce.c_str());
					}
					else
					{
						msg.AddText(pKiller->pSD->wszName);
						msg.AddText(mi.mensaje.c_str());
					}

					if(mi.range > 0)
					{
						FVector pos(pKiller->pSD->Pos);
						L2Server::BroadcastToNeighborDist(pKiller->nObjectID, &pos, mi.range, msg.GetSize(), msg.GetBuff());
					}else
					{
						L2Server::BroadcastToAllUser(msg.GetSize(), msg.GetBuff());
					}

					if(mi.rewardid > 0 && mi.rewardid > 0)
					{
						if(pKiller->pED->tvtUser.status != TvT::UserFighting)
							pKiller->AddItemToInventory(mi.rewardid, mi.rewardquanity);
					}
					if(mi.messageId == auraMsgId)
					{
						pKiller->SocialAction(SocialActionHero);
					}
				}
			}
		}

		return result;
	}
}