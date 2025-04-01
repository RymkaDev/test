#include "stdafx.h"
#include "TvT.h"
#include "UserDb.h"
#include "Door.h"
#include "CNpc.h"
#include "PlayerAction.h"
#include "TerritoryData.h"
#include "HTMLCacheManager.h"
#include "HtmlCache.h"
#include "EventStats.h"
#include "ObjectDB.h"
#include "Achivments.h"
#include "PvPEvents.h"

using namespace TvT;

CTvT g_TvT;

CTvT::CTvT() : m_lpEvent(0), m_enabled(FALSE)
{

}

CTvT::~CTvT()
{

}

void CTvT::Init()
{
	g_Log.Add(CLog::Blue, "[Load TvT]");
	Lock();
	if(!m_lpEvent)
	{
		m_tvtInfo.clear();
		m_enabled = FALSE;
		LoadINI();
		if(m_enabled)
		{
			g_Log.Add(CLog::Blue, "[%S] Feature is enabled, loaded [%d] events", L"TvT", m_tvtInfo.size());
		}
		else
		{
			g_Log.Add(CLog::Blue, "[%S] Feature is Disabled");
		}

	}else
	{
		g_Log.Add(CLog::Error, "[%S] Cannot Init tvt at the moment - please wait till it ends!", L"TvT");
	}
	Unlock();
}

void CTvT::LoadINI()
{
	guard;
	TCHAR g_TvTFile[260];
	GetCurrentDirectory(MAX_PATH,g_TvTFile);

	lstrcat(g_TvTFile, m_ConfigsIlExt);

	lstrcat(g_TvTFile, TEXT("\\TvT.ini"));
	const TCHAR* section = _T("TvTSystem");
	m_enabled = GetPrivateProfileInt(section, _T("Enabled"), FALSE, g_TvTFile);


	m_SumarPvPReward = GetPrivateProfileInt(section, _T("SumarPvPReward"), FALSE, g_TvTFile);


	INT32 count = GetPrivateProfileInt(section, _T("TvTEventCount"), 0, g_TvTFile);
	if(count > 0)
	{
		for(int n=1;n<=count;n++)
		{
			tstringstream sectionEx;
			sectionEx << "TvT_" << n ;
			TvT::TvTInfo* pInfo = new TvT::TvTInfo();
			pInfo->enabled = GetPrivateProfileInt(sectionEx.str().c_str(), _T("Enabled"), FALSE, g_TvTFile);
			TCHAR sTemp[0x8000];
			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("Type"), 0, sTemp, 8192, g_TvTFile))
			{
				tstring type = sTemp;
				if(type == _T("LTS"))
				{
					pInfo->type = TvT::TvTLastTeamStanding;
				}else if(type == _T("DM"))
				{
					pInfo->type = TvT::TvTDeathMatch;
				}else if(type == _T("GMGroup"))
				{
					pInfo->type = TvT::TvTGMReGroup;
				}else if(type == _T("KOREAN"))
				{
					pInfo->type = TvT::TvTKorean;
				}else if(type == _T("LMS"))
				{
					pInfo->type = TvT::TvTLastManStanding;
				}else if(type == _T("CTF"))
				{
					pInfo->type = TvT::TvTCaptureTheFlag;
				}else if(type == _T("CTF2"))
				{
					pInfo->type = TvT::TvTCaptureTheFlag2;
				}else if(type == _T("DTB"))
				{
					pInfo->type = TvT::TvTDestroyTheBase;
				}else if(type == _T("CASTLE"))
				{
					pInfo->type = TvT::TvTCastle;
				}else if(type == _T("FORTRESS"))
				{
					pInfo->type = TvT::TvTFortress;
				}else
				{
					pInfo->type = TvT::TvTNone;
				}
			}

			UINT dayFlag = GetPrivateProfileInt(sectionEx.str().c_str(), _T("DayFlag"), 0, g_TvTFile);
			for(UINT m = 1; m < 8; m++)
			{
				if((dayFlag % 10) == 1)
				{
					pInfo->dayFlag[m-1] = true;
				}else
				{
					pInfo->dayFlag[m-1] = false;
				}
				dayFlag /= 10;
			}
			pInfo->startHour = GetPrivateProfileInt(sectionEx.str().c_str(), _T("StartHour"), 14, g_TvTFile);
			pInfo->startMinute = GetPrivateProfileInt(sectionEx.str().c_str(), _T("StartMinute"), 30, g_TvTFile);
			pInfo->registerTime = GetPrivateProfileInt(sectionEx.str().c_str(), _T("RegisterTime"), 300, g_TvTFile);
			pInfo->prepareTime = GetPrivateProfileInt(sectionEx.str().c_str(), _T("PrepareTime"), 50, g_TvTFile);
			pInfo->countDownTime = GetPrivateProfileInt(sectionEx.str().c_str(), _T("CountDownTime"), 30, g_TvTFile);
			pInfo->fightTime = GetPrivateProfileInt(sectionEx.str().c_str(), _T("FightTime"), 300, g_TvTFile);
			pInfo->finishTime = GetPrivateProfileInt(sectionEx.str().c_str(), _T("FinishTime"), 15, g_TvTFile);
			pInfo->respawnTime = GetPrivateProfileInt(sectionEx.str().c_str(), _T("RespawnTime"), 15, g_TvTFile);
			pInfo->dispelAbnormal = GetPrivateProfileInt(sectionEx.str().c_str(), _T("DispelAbnormal"), 0, g_TvTFile);

			pInfo->rewardId = GetPrivateProfileInt(sectionEx.str().c_str(), _T("RewardId"), 0, g_TvTFile);
			pInfo->rewardCount = GetPrivateProfileInt(sectionEx.str().c_str(), _T("RewardCount"), 0, g_TvTFile);
			pInfo->rewardIdTie = GetPrivateProfileInt(sectionEx.str().c_str(), _T("RewardIdTie"), 0, g_TvTFile);
			pInfo->rewardCountTie = GetPrivateProfileInt(sectionEx.str().c_str(), _T("RewardCountTie"), 0, g_TvTFile);

			pInfo->teleportDelay = GetPrivateProfileInt(sectionEx.str().c_str(), _T("TeleportDelay"), 0, g_TvTFile);

			pInfo->MaximoVidasPorEquipo = GetPrivateProfileInt(sectionEx.str().c_str(), _T("MaximoVidasPorEquipo"), 0, g_TvTFile);


			pInfo->pvpReward = GetPrivateProfileInt(sectionEx.str().c_str(), _T("PvPReward"), 0, g_TvTFile);

			
			//-----------TOP WINNERS

			// TOP1KILLERREWARDID=57
			// TOP2KILLERREWARDID=57
			// TOP3KILLERREWARDID=57
			// TOP4KILLERREWARDID=57
			// TOP5KILLERREWARDID=57
			
			// TOP1KILLERREWARDCOUNT=10000000
			// TOP2KILLERREWARDCOUNT=7500000
			// TOP3KILLERREWARDCOUNT=5000000
			// TOP4KILLERREWARDCOUNT=3000000
			// TOP5KILLERREWARDCOUNT=1000000

			// TOP1KILLERREWARDMSG=Congratulations to [player_name] for being the TOP 1 with [kills] deaths on TvT
			// TOP2KILLERREWARDMSG=Congratulations to [player_name] for being the TOP 2 with [kills] deaths on TvT
			// TOP3KILLERREWARDMSG=Congratulations to [player_name] for being the TOP 3 with [kills] deaths on TvT
			// TOP4KILLERREWARDMSG=Congratulations to [player_name] for being the TOP 4 with [kills] deaths on TvT
			// TOP5KILLERREWARDMSG=Congratulations to [player_name] for being the TOP 5 with [kills] deaths on TvT

			pInfo->rank_rewardId_1 = GetPrivateProfileInt(sectionEx.str().c_str(), _T("TOP1KILLERREWARDID"), 0, g_TvTFile);
			pInfo->rank_rewardCount_1 = GetPrivateProfileInt(sectionEx.str().c_str(), _T("TOP1KILLERREWARDCOUNT"), 0, g_TvTFile);
			pInfo->rank_rewardId_2 = GetPrivateProfileInt(sectionEx.str().c_str(), _T("TOP2KILLERREWARDID"), 0, g_TvTFile);
			pInfo->rank_rewardCount_2 = GetPrivateProfileInt(sectionEx.str().c_str(), _T("TOP2KILLERREWARDCOUNT"), 0, g_TvTFile);
			pInfo->rank_rewardId_3 = GetPrivateProfileInt(sectionEx.str().c_str(), _T("TOP3KILLERREWARDID"), 0, g_TvTFile);
			pInfo->rank_rewardCount_3 = GetPrivateProfileInt(sectionEx.str().c_str(), _T("TOP3KILLERREWARDCOUNT"), 0, g_TvTFile);
			pInfo->rank_rewardId_4 = GetPrivateProfileInt(sectionEx.str().c_str(), _T("TOP4KILLERREWARDID"), 0, g_TvTFile);
			pInfo->rank_rewardCount_4 = GetPrivateProfileInt(sectionEx.str().c_str(), _T("TOP4KILLERREWARDCOUNT"), 0, g_TvTFile);
			pInfo->rank_rewardId_5 = GetPrivateProfileInt(sectionEx.str().c_str(), _T("TOP5KILLERREWARDID"), 0, g_TvTFile);
			pInfo->rank_rewardCount_5 = GetPrivateProfileInt(sectionEx.str().c_str(), _T("TOP5KILLERREWARDCOUNT"), 0, g_TvTFile);

			TCHAR temp1[8192];
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("TOP1KILLERREWARDMSG"), 0, temp1, 8190, g_TvTFile))
				pInfo->rank_rewardMsg_1 = temp1;

			TCHAR temp2[8192];
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("TOP2KILLERREWARDMSG"), 0, temp2, 8190, g_TvTFile))
				pInfo->rank_rewardMsg_2 = temp2;

			TCHAR temp3[8192];
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("TOP3KILLERREWARDMSG"), 0, temp3, 8190, g_TvTFile))
				pInfo->rank_rewardMsg_3 = temp3;

			TCHAR temp4[8192];
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("TOP4KILLERREWARDMSG"), 0, temp4, 8190, g_TvTFile))
				pInfo->rank_rewardMsg_4 = temp4;

			TCHAR temp5[8192];
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("TOP5KILLERREWARDMSG"), 0, temp5, 8190, g_TvTFile))
				pInfo->rank_rewardMsg_5 = temp5;


			TCHAR temp6[8192];
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("PlayerCountsMessage"), 0, temp6, 8190, g_TvTFile))
				pInfo->messagePlayersCouns = temp6;

			pInfo->MostrarMuertesParaElTop = GetPrivateProfileInt(sectionEx.str().c_str(), _T("MostrarMuertesParaElTop"), 0, g_TvTFile);
//----END-------TOP WINNERS

			pInfo->requiredItemId = GetPrivateProfileInt(sectionEx.str().c_str(), _T("RequiredItemId"), 0, g_TvTFile);
			pInfo->requiredItemCount = GetPrivateProfileInt(sectionEx.str().c_str(), _T("RequiredItemCount"), 0, g_TvTFile);

			pInfo->randomizeTeam = GetPrivateProfileInt(sectionEx.str().c_str(), _T("RandomizeTeam"), 0, g_TvTFile);
			pInfo->friendlyFire = GetPrivateProfileInt(sectionEx.str().c_str(), _T("FriendlyFire"), 0, g_TvTFile);
			pInfo->checkHwid = GetPrivateProfileInt(sectionEx.str().c_str(), _T("CheckHWID"), 0, g_TvTFile);
			pInfo->minPlayers = GetPrivateProfileInt(sectionEx.str().c_str(), _T("MinPlayers"), 0, g_TvTFile);
			pInfo->maxPlayers = GetPrivateProfileInt(sectionEx.str().c_str(), _T("MaxPlayers"), 0, g_TvTFile);
			pInfo->minLevel = GetPrivateProfileInt(sectionEx.str().c_str(), _T("MinLevel"), 0, g_TvTFile);
			pInfo->maxLevel = GetPrivateProfileInt(sectionEx.str().c_str(), _T("MaxLevel"), 80, g_TvTFile);
			pInfo->skillPchId = GetPrivateProfileInt(sectionEx.str().c_str(), _T("SkillPchId"), 0, g_TvTFile);


			pInfo->rewardLostId = GetPrivateProfileInt(sectionEx.str().c_str(), _T("RewardLostId"), 0, g_TvTFile);
			pInfo->rewardLostCount = GetPrivateProfileInt(sectionEx.str().c_str(), _T("RewardLostCount"), 0, g_TvTFile);
			pInfo->nFireworkId = GetPrivateProfileInt(sectionEx.str().c_str(), _T("FireworkId"), 0, g_TvTFile);
			pInfo->TimeAfk = GetPrivateProfileInt(sectionEx.str().c_str(), _T("TimeAfk"), 2000, g_TvTFile);
			pInfo->ResetBuffsOnFinish = GetPrivateProfileInt(sectionEx.str().c_str(), _T("ResetBuffsOnFinish"), 0, g_TvTFile);
			pInfo->nResetReuseSkills = GetPrivateProfileInt(sectionEx.str().c_str(), _T("ResetReuseSkills"), 0, g_TvTFile);


			pInfo->registerNpcClassId = GetPrivateProfileInt(sectionEx.str().c_str(), _T("RegisterNpcId"), 0, g_TvTFile);

			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("RegisterNpcPos"), 0, sTemp, 8192, g_TvTFile))
			{
				tstring pos = sTemp;
				pos = Utils::ReplaceString(pos, _T("/"), _T(" "), true);
				tstringstream sstr;
				sstr << pos;
				sstr >> pInfo->registerNpcPos.x >> pInfo->registerNpcPos.y >> pInfo->registerNpcPos.z;
			}else
			{
				pInfo->registerNpcPos.x = 0;
				pInfo->registerNpcPos.y = 0;
				pInfo->registerNpcPos.z = 0;
			}

			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("RegisterNpcPos2"), 0, sTemp, 8192, g_TvTFile))
			{
				tstring pos = sTemp;
				pos = Utils::ReplaceString(pos, _T("/"), _T(" "), true);
				tstringstream sstr;
				sstr << pos;
				sstr >> pInfo->registerNpcPos1.x >> pInfo->registerNpcPos1.y >> pInfo->registerNpcPos1.z;
			}else
			{
				pInfo->registerNpcPos1.x = 0;
				pInfo->registerNpcPos1.y = 0;
				pInfo->registerNpcPos1.z = 0;
			}

			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("RegisterNpcPos3"), 0, sTemp, 8192, g_TvTFile))
			{
				tstring pos = sTemp;
				pos = Utils::ReplaceString(pos, _T("/"), _T(" "), true);
				tstringstream sstr;
				sstr << pos;
				sstr >> pInfo->registerNpcPos2.x >> pInfo->registerNpcPos2.y >> pInfo->registerNpcPos2.z;
			}else
			{
				pInfo->registerNpcPos2.x = 0;
				pInfo->registerNpcPos2.y = 0;
				pInfo->registerNpcPos2.z = 0;
			}

			pInfo->registerBufferId = GetPrivateProfileInt(sectionEx.str().c_str(), _T("RegisterBufferId"), 0, g_TvTFile);

			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("RegisterBufferPos1"), 0, sTemp, 8192, g_TvTFile))
			{
				tstring pos = sTemp;
				pos = Utils::ReplaceString(pos, _T("/"), _T(" "), true);
				tstringstream sstr;
				sstr << pos;
				sstr >> pInfo->registerBufferPos1.x >> pInfo->registerBufferPos1.y >> pInfo->registerBufferPos1.z;
			}else
			{
				pInfo->registerBufferPos1.x = 0;
				pInfo->registerBufferPos1.y = 0;
				pInfo->registerBufferPos1.z = 0;
			}

			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("RegisterBufferPos2"), 0, sTemp, 8192, g_TvTFile))
			{
				tstring pos = sTemp;
				pos = Utils::ReplaceString(pos, _T("/"), _T(" "), true);
				tstringstream sstr;
				sstr << pos;
				sstr >> pInfo->registerBufferPos2.x >> pInfo->registerBufferPos2.y >> pInfo->registerBufferPos2.z;
			}else
			{
				pInfo->registerBufferPos2.x = 0;
				pInfo->registerBufferPos2.y = 0;
				pInfo->registerBufferPos2.z = 0;
			}

			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("RegisterBufferPos3"), 0, sTemp, 8192, g_TvTFile))
			{
				tstring pos = sTemp;
				pos = Utils::ReplaceString(pos, _T("/"), _T(" "), true);
				tstringstream sstr;
				sstr << pos;
				sstr >> pInfo->registerBufferPos3.x >> pInfo->registerBufferPos3.y >> pInfo->registerBufferPos3.z;
			}else
			{
				pInfo->registerBufferPos3.x = 0;
				pInfo->registerBufferPos3.y = 0;
				pInfo->registerBufferPos3.z = 0;
			}

			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("RegisterBufferPos4"), 0, sTemp, 8192, g_TvTFile))
			{
				tstring pos = sTemp;
				pos = Utils::ReplaceString(pos, _T("/"), _T(" "), true);
				tstringstream sstr;
				sstr << pos;
				sstr >> pInfo->registerBufferPos4.x >> pInfo->registerBufferPos4.y >> pInfo->registerBufferPos4.z;
			}else
			{
				pInfo->registerBufferPos4.x = 0;
				pInfo->registerBufferPos4.y = 0;
				pInfo->registerBufferPos4.z = 0;
			}

			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("KickOutPos"), 0, sTemp, 8192, g_TvTFile))
			{
				tstring pos = sTemp;
				pos = Utils::ReplaceString(pos, _T("/"), _T(" "), true);
				tstringstream sstr;
				sstr << pos;
				sstr >> pInfo->kickOutPos.x >> pInfo->kickOutPos.y >> pInfo->kickOutPos.z;
			}else
			{
				pInfo->kickOutPos.x = 0;
				pInfo->kickOutPos.y = 0;
				pInfo->kickOutPos.z = 0;
			}

			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("FightZoneXRange"), 0, sTemp, 8192, g_TvTFile))
			{
				tstring pos = sTemp;
				tstringstream sstr;
				sstr << pos;
				sstr >> pInfo->fightZoneX[0] >> pInfo->fightZoneX[1];
			}else
			{
				pInfo->fightZoneX[0] = 0;
				pInfo->fightZoneX[1] = 0;
			}

			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("FightZoneYRange"), 0, sTemp, 8192, g_TvTFile))
			{
				tstring pos = sTemp;
				tstringstream sstr;
				sstr << pos;
				sstr >> pInfo->fightZoneY[0] >> pInfo->fightZoneY[1];
			}else
			{
				pInfo->fightZoneY[0] = 0;
				pInfo->fightZoneY[1] = 0;
			}

			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("DoorName"), 0, sTemp, 8192, g_TvTFile))
			{
				tstringstream sstr;
				sstr << sTemp;
				wstring doorName;
				while(sstr >> doorName)
				{
					pInfo->doorList.push_back(doorName);
				}
			}

			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("RegistrationStartMessage1"), 0, sTemp, 8192, g_TvTFile))
			{
				pInfo->registrationStartMsg1 = sTemp;
			}
			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("RegistrationStartMessage2"), 0, sTemp, 8192, g_TvTFile))
			{
				pInfo->registrationStartMsg2 = sTemp;
			}
			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("RegistrationRemindMessage"), 0, sTemp, 8192, g_TvTFile))
			{
				pInfo->registrationRemindMsg = sTemp;
			}
			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("RegistrationEndMessage"), 0, sTemp, 8192, g_TvTFile))
			{
				pInfo->registrationEndMsg = sTemp;
			}
			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("RegistratrionNontEnoughParticipants"), 0, sTemp, 8192, g_TvTFile))
			{
				pInfo->registrationNotEnoughParticipantsMsg = sTemp;
			}
			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("PreparationStartMessage"), 0, sTemp, 8192, g_TvTFile))
			{
				pInfo->preparationStartMsg = sTemp;
			}
			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("PreparationRemindMessage"), 0, sTemp, 8192, g_TvTFile))
			{
				pInfo->preparationRemindMsg = sTemp;
			}
			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("FightStartRemindMessage"), 0, sTemp, 8192, g_TvTFile))
			{
				pInfo->fightStartRemindMsg = sTemp;
			}
			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("FightEndRemindMessage"), 0, sTemp, 8192, g_TvTFile))
			{
				pInfo->fightEndRemindMsg = sTemp;
			}
			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("DrawMessage"), 0, sTemp, 8192, g_TvTFile))
			{
				pInfo->endMsg[0] = sTemp;
			}
			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("BlueWinMessage"), 0, sTemp, 8192, g_TvTFile))
			{
				pInfo->endMsg[1] = sTemp;
			}
			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("RedWinMessage"), 0, sTemp, 8192, g_TvTFile))
			{
				pInfo->endMsg[2] = sTemp;
			}
			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("TeleportBackRemindMessage"), 0, sTemp, 8192, g_TvTFile))
			{
				pInfo->teleportBackRemindMsg = sTemp;
			}
			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("EndMessage"), 0, sTemp, 8192, g_TvTFile))
			{
				pInfo->endEventMsg = sTemp;
			}
			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("FightStartMessage"), 0, sTemp, 8192, g_TvTFile))
			{
				pInfo->fightStartMessage = sTemp;
			}

			memset(sTemp, 0, sizeof(sTemp));
			pInfo->blockedSkill.clear();
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("BlockedSkillList"), 0, sTemp, 0x8000, g_TvTFile))
			{
				wstringstream skillStream(sTemp);
				wstring skillName;
				while(skillStream >> skillName)
				{
					INT32 skillId = 0, level = 0;
					g_SkillDB.GetSkillIdLevelByName((PWCHAR)skillName.c_str(), &skillId, &level);
					if(skillId > 0)
					{
						pInfo->blockedSkill.push_back(skillId);
					}			
				}
			}

			memset(sTemp, 0, sizeof(sTemp));
			pInfo->blockedItem.clear();
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("BlockedItemList"), 0, sTemp, 0x8000, g_CustomConfigFile))
			{
				wstring params = Parser::Replace(sTemp, L';', L' ');

				tstringstream sstr;
				sstr << params;
				wstring wName;
				while(sstr >> wName)
				{
					pInfo->blockedItem.push_back(g_ObjectDB.GetClassIdFromName(wName.c_str()));
				}
			}



			memset(sTemp, 0, sizeof(sTemp));
			pInfo->defaultMageBuffs.clear();
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("DefaultMageBuffList"), 0, sTemp, 0x8000, g_TvTFile))
			{
				wstringstream skillStream(sTemp);
				wstring skillName;
				while(skillStream >> skillName)
				{
					INT32 skillId = 0, level = 0;
					g_SkillDB.GetSkillIdLevelByName((PWCHAR)skillName.c_str(), &skillId, &level);
					if(skillId > 0)
					{
						SkillPchId skillPch(skillId,level);
						pInfo->defaultMageBuffs.push_back(skillPch);
					}			
				}
			}



			memset(sTemp, 0, sizeof(sTemp));
			pInfo->defaultFighterBuffs.clear();
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("DefaultFighterBuffList"), 0, sTemp, 0x8000, g_TvTFile))
			{
				wstringstream skillStream(sTemp);
				wstring skillName;
				while(skillStream >> skillName)
				{
					INT32 skillId = 0, level = 0;
					g_SkillDB.GetSkillIdLevelByName((PWCHAR)skillName.c_str(), &skillId, &level);
					if(skillId > 0)
					{
						SkillPchId skillPch(skillId,level);
						pInfo->defaultFighterBuffs.push_back(skillPch);
					}			
				}
			}





			memset(sTemp, 0, sizeof(sTemp));
			memset(pInfo->blockedCrystalType, 0, sizeof(pInfo->blockedCrystalType));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("BlockedCrystalTypeList"), 0, sTemp, 0x8000, g_TvTFile))
			{
				tstringstream sstr;
				sstr << sTemp;
				UINT crystalType = 0;
				while(sstr >> crystalType)
				{
					if(crystalType < 10)
					{
						pInfo->blockedCrystalType[crystalType] = true;
					}else
					{
						g_Log.Add(CLog::Error, "[%s] CrystalType overflow[%d]!", __FUNCTION__, crystalType);
					}
				}
			}
			pInfo->blockAugmentation = GetPrivateProfileInt(sectionEx.str().c_str(), _T("BlockAugmentation"), 0, g_TvTFile);
			pInfo->blockAttribute = GetPrivateProfileInt(sectionEx.str().c_str(), _T("BlockAttribute"), 0, g_TvTFile);
			pInfo->maxArmorEnchant = GetPrivateProfileInt(sectionEx.str().c_str(), _T("MaxArmorEnchant"), 0, g_TvTFile);
			pInfo->maxWeaponEnchant = GetPrivateProfileInt(sectionEx.str().c_str(), _T("MaxWeaponEnchant"), 0, g_TvTFile);

			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("NpcHtmlFile"), 0, sTemp, 8192, g_TvTFile))
			{
				pInfo->npchtmfile = sTemp;
			}

			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("NpcBufferHtmlFile"), 0, sTemp, 8192, g_TvTFile))
			{
				pInfo->npchtmfilebuffer = sTemp;
			}
			//blockedClasses
			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("BlockedClasses"), 0, sTemp, 0x8000, g_TvTFile))
			{
				tstringstream sstr;
				sstr << sTemp;
				INT32 classID = 0;
				while(sstr >> classID)
				{
					pInfo->blockedClasses.push_back(classID);
				}
			}

			pInfo->PartySize = GetPrivateProfileInt(sectionEx.str().c_str(), _T("PartySize"), 0, g_TvTFile);

			pInfo->korean_skillid = GetPrivateProfileInt(sectionEx.str().c_str(), _T("SkillIdProtection"), 0, g_TvTFile);

			pInfo->participateplayers = GetPrivateProfileInt(sectionEx.str().c_str(), _T("ParticipatePlayers"), 0, g_TvTFile);


//-----------------


			pInfo->m_bluePosCantidad = 0;
			pInfo->m_redPosCantidad = 0;
			pInfo->m_bluePosPosicion = 0;
			pInfo->m_redPosPosicion = 0;

			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("BlueTeamLocation"), 0, sTemp, 8192, g_TvTFile))
			{
				tstring pos = sTemp;
				pos = Utils::ReplaceString(pos, _T("/"), _T(" "), true);
				tstringstream sstr;
				sstr << pos;
				
				while(sstr >> pInfo->bluePos[pInfo->m_bluePosCantidad].x >> pInfo->bluePos[pInfo->m_bluePosCantidad].y >> pInfo->bluePos[pInfo->m_bluePosCantidad].z)
				{
					pInfo->m_bluePosCantidad++;
				}
			}else
			{
				pInfo->bluePos[0].x = 0;
				pInfo->bluePos[0].y = 0;
				pInfo->bluePos[0].z = 0;
			}

			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("RedTeamLocation"), 0, sTemp, 8192, g_TvTFile))
			{
				tstring pos = sTemp;
				pos = Utils::ReplaceString(pos, _T("/"), _T(" "), true);
				tstringstream sstr;
				sstr << pos;
				
				while(sstr >> pInfo->redPos[pInfo->m_redPosCantidad].x >> pInfo->redPos[pInfo->m_redPosCantidad].y >> pInfo->redPos[pInfo->m_redPosCantidad].z)
				{
					pInfo->m_redPosCantidad++;
				}
			}else
			{
				pInfo->redPos[0].x = 0;
				pInfo->redPos[0].y = 0;
				pInfo->redPos[0].z = 0;
			}

			if (pInfo->m_bluePosCantidad >0)
				pInfo->m_bluePosCantidad = pInfo->m_bluePosCantidad -1;

			if (pInfo->m_redPosCantidad >0)
				pInfo->m_redPosCantidad = pInfo->m_redPosCantidad -1;



			pInfo->TitleColorBlue = GetPrivateProfileInt(sectionEx.str().c_str(), _T("TitleCustomColorBlue"), 0, g_TvTFile);
			pInfo->TitleColorRed = GetPrivateProfileInt(sectionEx.str().c_str(), _T("TitleCustomColorRed"), 0, g_TvTFile);
			pInfo->MostrarTitlesKills = GetPrivateProfileInt(sectionEx.str().c_str(), _T("MostrarTitlesKills"), 0, g_TvTFile);

			pInfo->MeterAlEventoSiHayCritico = GetPrivateProfileInt(sectionEx.str().c_str(), _T("MeterAlEventoSiHayCritico"), 0, g_TvTFile);

			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("TitleCustomBlue"), 0, sTemp, 8192, g_TvTFile))
			{
				pInfo->TitleCustomBlue = sTemp;
			}
			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("TitleCustomRed"), 0, sTemp, 8192, g_TvTFile))
			{
				pInfo->TitleCustomRed = sTemp;
			}


			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("HelpHtmlFile"), 0, sTemp, 8192, g_TvTFile))
			{
				pInfo->HelpHtmlFile = sTemp;
			}


			//CAPTURE THE FLAG MIO
			memset(sTemp, 0, sizeof(sTemp));
			pInfo->BanderaBlueNpcId = GetPrivateProfileInt(sectionEx.str().c_str(), _T("BanderaBlueNpcId"), 0, g_TvTFile);

			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("BanderaBlueNpcPos"), 0, sTemp, 8192, g_TvTFile))
			{
				tstring pos = sTemp;
				pos = Utils::ReplaceString(pos, _T("/"), _T(" "), true);
				tstringstream sstr;
				sstr << pos;
				sstr >> pInfo->BanderaBlueNpcPos.x >> pInfo->BanderaBlueNpcPos.y >> pInfo->BanderaBlueNpcPos.z;
			}

			memset(sTemp, 0, sizeof(sTemp));
			pInfo->BanderaRedNpcId = GetPrivateProfileInt(sectionEx.str().c_str(), _T("BanderaRedNpcId"), 0, g_TvTFile);
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("BanderaRedNpcPos"), 0, sTemp, 8192, g_TvTFile))
			{
				tstring pos = sTemp;
				pos = Utils::ReplaceString(pos, _T("/"), _T(" "), true);
				tstringstream sstr;
				sstr << pos;
				sstr >> pInfo->BanderaRedNpcPos.x >> pInfo->BanderaRedNpcPos.y >> pInfo->BanderaRedNpcPos.z;
			}

			pInfo->BanderaBlueItemId = GetPrivateProfileInt(sectionEx.str().c_str(), _T("BanderaBlueItemId"), 0, g_TvTFile);
			pInfo->BanderaRedItemId = GetPrivateProfileInt(sectionEx.str().c_str(), _T("BanderaRedItemId"), 0, g_TvTFile);

			pInfo->CaptureFireworkId = GetPrivateProfileInt(sectionEx.str().c_str(), _T("CaptureFireworkId"), 0, g_TvTFile);

			pInfo->rewardCountForWinCapture = GetPrivateProfileInt(sectionEx.str().c_str(), _T("rewardCountForWinCapture"), 0, g_TvTFile);


			//FORTRESS
			pInfo->FortressSkillId = GetPrivateProfileInt(sectionEx.str().c_str(), _T("FortressSkillId"), 0, g_TvTFile);

			pInfo->rewardCountForWinCastFortress = GetPrivateProfileInt(sectionEx.str().c_str(), _T("rewardCountForWinCastFortress"), 0, g_TvTFile);


			pInfo->FortressCrystalNpcId = GetPrivateProfileInt(sectionEx.str().c_str(), _T("FortressCrystalNpcId"), 0, g_TvTFile);

			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("FortressCrystalNpcPos"), 0, sTemp, 8192, g_TvTFile))
			{
				tstring pos = sTemp;
				pos = Utils::ReplaceString(pos, _T("/"), _T(" "), true);
				tstringstream sstr;
				sstr << pos;
				sstr >> pInfo->FortressCrystalNpcPos.x >> pInfo->FortressCrystalNpcPos.y >> pInfo->FortressCrystalNpcPos.z;
			}



			//DESTROY THE BASE
			pInfo->rewardCountForWinDestroyBase = GetPrivateProfileInt(sectionEx.str().c_str(), _T("rewardCountForWinDestroyBase"), 0, g_TvTFile);	

			pInfo->DestroyBaseNpcHP = GetPrivateProfileInt(sectionEx.str().c_str(), _T("DestroyBaseNpcHP"), 100000, g_TvTFile);	


			pInfo->DestroyBaseBlueNpcId = GetPrivateProfileInt(sectionEx.str().c_str(), _T("DestroyBaseBlueNpcId"), 0, g_TvTFile);

			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("DestroyBaseBlueNpcPos"), 0, sTemp, 8192, g_TvTFile))
			{
				tstring pos = sTemp;
				pos = Utils::ReplaceString(pos, _T("/"), _T(" "), true);
				tstringstream sstr;
				sstr << pos;
				sstr >> pInfo->DestroyBaseBlueNpcPos.x >> pInfo->DestroyBaseBlueNpcPos.y >> pInfo->DestroyBaseBlueNpcPos.z;
			}


			pInfo->DestroyBaseRedNpcId = GetPrivateProfileInt(sectionEx.str().c_str(), _T("DestroyBaseRedNpcId"), 0, g_TvTFile);

			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("DestroyBaseRedNpcPos"), 0, sTemp, 8192, g_TvTFile))
			{
				tstring pos = sTemp;
				pos = Utils::ReplaceString(pos, _T("/"), _T(" "), true);
				tstringstream sstr;
				sstr << pos;
				sstr >> pInfo->DestroyBaseRedNpcPos.x >> pInfo->DestroyBaseRedNpcPos.y >> pInfo->DestroyBaseRedNpcPos.z;
			}
			//-----------

			pInfo->InvertirPuestos = GetPrivateProfileInt(sectionEx.str().c_str(), _T("InvertirPuestos"), 0, g_TvTFile);

			memset(sTemp, 0, sizeof(sTemp));
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("DoorWallCastleName"), 0, sTemp, 8192, g_TvTFile))
			{
				tstringstream sstr;
				sstr << sTemp;
				wstring doorName;
				while(sstr >> doorName)
				{
					pInfo->MurallasList.push_back(doorName);
				}
			}

//--------------------------------
			
			//Only For CTF
			pInfo->blueFlagId = GetPrivateProfileInt(sectionEx.str().c_str(), _T("BlueFlagID"), 0, g_TvTFile);
			pInfo->redFlagId = GetPrivateProfileInt(sectionEx.str().c_str(), _T("RedFlagID"), 0, g_TvTFile);
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("BlueFlagPos"), 0, sTemp, 8192, g_TvTFile)) { tstring pos = sTemp; pos = Utils::ReplaceString(pos, _T("/"), _T(" "), true); tstringstream sstr; sstr << pos; sstr >> pInfo->blueFlagPos.x >> pInfo->blueFlagPos.y >> pInfo->blueFlagPos.z; }else { pInfo->blueFlagPos.x = 0; pInfo->blueFlagPos.y = 0; pInfo->blueFlagPos.z = 0; }
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("RedFlagPos"), 0, sTemp, 8192, g_TvTFile)) { tstring pos = sTemp; pos = Utils::ReplaceString(pos, _T("/"), _T(" "), true); tstringstream sstr; sstr << pos; sstr >> pInfo->redFlagPos.x >> pInfo->redFlagPos.y >> pInfo->redFlagPos.z; }else { pInfo->redFlagPos.x = 0; pInfo->redFlagPos.y = 0; pInfo->redFlagPos.z = 0; }

			//New Checks - TODO
			pInfo->BalanceBishops = GetPrivateProfileInt(sectionEx.str().c_str(), _T("BalanceBishops"), 0, g_TvTFile);

			m_tvtInfo.push_back(pInfo);
		}
	}
	unguard;
}

void CTvT::TimerExpired()
{
	guard;
	if(m_enabled)
	{
		Lock();
		if(m_lpEvent)
		{
			time_t currentTime = time(NULL);

			switch(m_lpEvent->m_state)
			{
			case TvT::StateNone:
				{
					m_lpEvent->Init();
				};
			case TvT::StateRegistration:
				{
					time_t diff = m_lpEvent->m_stateTime + m_lpEvent->m_lpInfo->registerTime;
					diff -= currentTime;
					if(diff > 0)
					{
						//broadcast message when it ends
						if(m_lpEvent->m_lpInfo->registrationRemindMsg.size() > 0)
						{
							if(diff == 60)
							{
								TCHAR remainSec[16];
								_itot_s(static_cast<int>(diff), remainSec, 16, 10);
								wstring announce = Utils::ReplaceString(m_lpEvent->m_lpInfo->registrationRemindMsg, _T("[param]"), remainSec);
								Utils::BroadcastToAllUser_Announce(announce.c_str());
							}else if(diff == 30)
							{
								TCHAR remainSec[16];
								_itot_s(static_cast<int>(diff), remainSec, 16, 10);
								wstring announce = Utils::ReplaceString(m_lpEvent->m_lpInfo->registrationRemindMsg, _T("[param]"), remainSec);
								Utils::BroadcastToAllUser_Announce(announce.c_str());
							}else if(diff == 10)
							{
								TCHAR remainSec[16];
								_itot_s(static_cast<int>(diff), remainSec, 16, 10);
								wstring announce = Utils::ReplaceString(m_lpEvent->m_lpInfo->registrationRemindMsg, _T("[param]"), remainSec);
								Utils::BroadcastToAllUser_Announce(announce.c_str());
							}
						}

					}
					else
					{
						m_lpEvent->m_stateTime = time(NULL);
						if(m_lpEvent->m_lpInfo->registrationEndMsg.size() > 0)
						{
							Utils::BroadcastToAllUser_Announce(m_lpEvent->m_lpInfo->registrationEndMsg.c_str());
						}

						//switch to next state if 

	//					g_Log.Add(CLog::Error, L"TVT MIN PLAYERS:[%d] REGISTERED USERS:[%d]", m_lpEvent->m_lpInfo->minPlayers, m_lpEvent->m_users.size());
						if(m_lpEvent->m_lpInfo->minPlayers > 0 && m_lpEvent->m_lpInfo->minPlayers > m_lpEvent->m_users.size())
						{
							if(m_lpEvent->m_lpInfo->registrationNotEnoughParticipantsMsg.size() > 0)
							{
								Utils::BroadcastToAllUser_Announce(m_lpEvent->m_lpInfo->registrationNotEnoughParticipantsMsg.c_str());
							}
							m_lpEvent->m_state = TvT::StateDelete;
							break;
						}

						if(m_lpEvent->m_lpInfo->messagePlayersCouns.size() > 0)
						{
							tstring announce = m_lpEvent->m_lpInfo->messagePlayersCouns;
							announce = Utils::ReplaceString(announce, _T("[players]"), m_lpEvent->m_users.size(), true);
							Utils::BroadcastToAllUser_Announce(announce.c_str());
						}

						//Pick The Users here
						if( m_lpEvent->m_lpInfo->type == TvT::TvTKorean ) //KOREAN OR CTF OR DEATHMATCH
						{

							if( m_lpEvent->PickPlayers() )
							{
								m_lpEvent->RemovePlayers();
							}
							else
							{
								if(m_lpEvent->m_lpInfo->registrationNotEnoughParticipantsMsg.size() > 0)
								{
									Utils::BroadcastToAllUser_Announce(m_lpEvent->m_lpInfo->registrationNotEnoughParticipantsMsg.c_str());
								}
								m_lpEvent->m_state = TvT::StateDelete;
								break;
							}
						}

//						if( m_lpEvent->m_lpInfo->type == TvT::TvTKorean || m_lpEvent->m_lpInfo->type == TvT::TvTCaptureTheFlag || m_lpEvent->m_lpInfo->type == TvT::TvTDeathMatch || m_lpEvent->m_lpInfo->type == TvT::TvTCaptureTheFlag2 || m_lpEvent->m_lpInfo->type == TvT::TvTDestroyTheBase || m_lpEvent->m_lpInfo->type == TvT::TvTCastle) //KOREAN OR CTF OR DEATHMATCH
//						{
//
//							if( m_lpEvent->PickPlayers() )
//							{
//								m_lpEvent->RemovePlayers();
//							}
//							else
//							{
//								if(m_lpEvent->m_lpInfo->registrationNotEnoughParticipantsMsg.size() > 0)
//								{
//									Utils::BroadcastToAllUser_Announce(m_lpEvent->m_lpInfo->registrationNotEnoughParticipantsMsg.c_str());
//								}
//								m_lpEvent->m_state = TvT::StateDelete;
//								break;
//							}
//						}

//						if( m_lpEvent->m_lpInfo->type == TvT::TvTLastManStanding ) //LAST MAN STANDING
//						{
//
//							if( m_lpEvent->PickPlayersLastMan() )
//							{
//								m_lpEvent->RemovePlayers();
//							}
//							else
//							{
//								if(m_lpEvent->m_lpInfo->registrationNotEnoughParticipantsMsg.size() > 0)
//								{
//									Utils::BroadcastToAllUser_Announce(m_lpEvent->m_lpInfo->registrationNotEnoughParticipantsMsg.c_str());
//								}
//								m_lpEvent->m_state = TvT::StateDelete;
//								break;
//							}
//						}

						m_lpEvent->m_state = TvT::StatePreparation;

						if(m_lpEvent->m_lpInfo->preparationStartMsg.size() > 0)
						{
							Utils::BroadcastToAllUser_Announce(m_lpEvent->m_lpInfo->preparationStartMsg.c_str());
						}

						if(m_lpEvent->m_lpInfo->doorList.size() > 0)
						{
							//close doors
							for(list<wstring>::iterator Iter = m_lpEvent->m_lpInfo->doorList.begin(); Iter!= m_lpEvent->m_lpInfo->doorList.end();Iter++)
							{
								CDoor *pDoor = g_DoorDB.GetDoor(Iter->c_str());
								if(pDoor)
								{
									pDoor->Close();
								}
							}
						}

						if(m_lpEvent->m_lpInfo->MurallasList.size() > 0)
						{
							//open murallas
							for(list<wstring>::iterator Iter = m_lpEvent->m_lpInfo->MurallasList.begin(); Iter!= m_lpEvent->m_lpInfo->MurallasList.end();Iter++)
							{
								CDoor *pDoor = g_DoorDB.GetDoor(Iter->c_str());
								if(pDoor)
								{
									pDoor->pSD->hp=5;
									pDoor->pSD->maxHp=10;
									pDoor->pSD->breakable=1;
									pDoor->damageGrade = 6;
									pDoor->Open(false);
								}
							}
						}

						if(m_lpEvent->m_lpInfo->kickOutPos.x != 0 || m_lpEvent->m_lpInfo->kickOutPos.y != 0)
						{
							g_UserDB.KickOutFromRange(m_lpEvent->m_lpInfo->kickOutPos, m_lpEvent->m_lpInfo->fightZoneX[0], m_lpEvent->m_lpInfo->fightZoneX[1], m_lpEvent->m_lpInfo->fightZoneY[0], m_lpEvent->m_lpInfo->fightZoneY[1] );
						}
					}
					break;
				}
			case TvT::StatePreparation:
				{
					time_t diff = m_lpEvent->m_stateTime + m_lpEvent->m_lpInfo->prepareTime;
					diff -= currentTime;
					if(diff > 0)
					{
						if(m_lpEvent->m_lpInfo->preparationRemindMsg.size() > 0)
						{
							if(diff == 30)
							{
								TCHAR remainSec[16];
								_itot_s(static_cast<int>(diff), remainSec, 16, 10);
								wstring announce = Utils::ReplaceString(m_lpEvent->m_lpInfo->preparationRemindMsg, _T("[param]"), remainSec);
								m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", announce.c_str());
							}else if(diff == 10)
							{
								TCHAR remainSec[16];
								_itot_s(static_cast<int>(diff), remainSec, 16, 10);
								wstring announce = Utils::ReplaceString(m_lpEvent->m_lpInfo->preparationRemindMsg, _T("[param]"), remainSec);
								m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", announce.c_str());
							}
							else if(diff == 5)
							{
								TCHAR remainSec[16];
								_itot_s(static_cast<int>(diff), remainSec, 16, 10);
								wstring announce = Utils::ReplaceString(m_lpEvent->m_lpInfo->preparationRemindMsg, _T("[param]"), remainSec);
								m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", announce.c_str());
							}
						}
					}else
					{
						m_lpEvent->m_stateTime = time(NULL);

						if( m_lpEvent->m_lpInfo->type == TvT::TvTGMReGroup)
						{
							m_lpEvent->m_state = TvT::StateDelete;
						}
						else
						{
							m_lpEvent->m_state = TvT::StateCountDown;
						}

						vector<UINT> toDelete;
						for(map<UINT, User*>::iterator Iter = m_lpEvent->m_users.begin(); Iter!=m_lpEvent->m_users.end();Iter++)
						{
							User *pUser = Iter->second;
							if(pUser->ValidUser())
							{
								pUser->pED->m_CtfUserFlag = 0;
								pUser->pED->m_CtfUserFlagWeapon = 0;

								if(pUser->pSD->nKarma)
								{
									//2578	1	a,Only alive players can participe in TvT event.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
									pUser->SendSystemMessage(2578);
									toDelete.push_back(Iter->first);
									continue;
								}

								if(pUser->olympiadUser.GetState() != 0)
								{
									pUser->SendSystemMessage(L"No puedes jugar el tvt porque estas anotado en Olympiadas!");
									toDelete.push_back(Iter->first);
									continue;
								}

								if(!pUser->pSD->nAlive)
								{
									//2578	1	a,Only alive players can participe in TvT event.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
									pUser->SendSystemMessage(2578);
									toDelete.push_back(Iter->first);
									continue;
								}
								if(pUser->pSD->pExData->territoryData.territoryId[BLOCK_TVT_ZONE] != 0)
								{
									//2579	1	a,You cannot participe in TvT event while being in current location!.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
									pUser->SendSystemMessage(2579);
									toDelete.push_back(Iter->first);
									continue;
								}
								if(m_lpEvent->m_lpInfo->dispelAbnormal)
								{
									pUser->DispelAllByGM();
									if(CSummon *pSummon = pUser->GetSummonOrPet())
									{
										pSummon->DispelAllByGM();
									}
								}
								ValidateItems(pUser);
								pUser->pSD->teamType = pUser->pED->tvtUser.team;
								pUser->pED->tvtUser.status = TvT::UserPreparing;

								if (m_lpEvent->m_lpInfo->MeterAlEventoSiHayCritico)
								{
									map<UINT, TvTUser>::iterator Iter2 = m_lpEvent->m_usersBackup.find(pUser->nDBID);
									if(Iter2!=m_lpEvent->m_usersBackup.end())
									{
										Iter2->second = TvTUser(pUser->pED->tvtUser);
									}
								}

								pUser->SetUserInfoChanged();
								pUser->SetCharInfoChanged();
								pUser->preserveAbnormals = true;
							}else
							{
								toDelete.push_back(Iter->first);
							}
						}

						for(INT32 n=0;n<toDelete.size();n++)
						{
							map<UINT, User*>::iterator Iter = m_lpEvent->m_users.find(toDelete[n]);
							if(Iter!=m_lpEvent->m_users.end())
							{
								User *pUser = Iter->second;
								if(pUser->ValidUser())
								{
									pUser->pED->tvtUser.Clear();
									pUser->pSD->teamType = 0;
								}
								m_lpEvent->m_users.erase(Iter);
							}
						}

						//randomize team if needed
						if( m_lpEvent->m_lpInfo->type == TvT::TvTLastTeamStanding || m_lpEvent->m_lpInfo->type == TvT::TvTDeathMatch  || m_lpEvent->m_lpInfo->type == TvT::TvTCaptureTheFlag2  || m_lpEvent->m_lpInfo->type == TvT::TvTCastle  || m_lpEvent->m_lpInfo->type == TvT::TvTDestroyTheBase || m_lpEvent->m_lpInfo->type == TvT::TvTFortress)
						{
							if(m_lpEvent->m_lpInfo->randomizeTeam)
							{
								m_lpEvent->RandomizeTeams();
							}
						}

						for(map<UINT, User*>::iterator Iter = m_lpEvent->m_users.begin(); Iter!=m_lpEvent->m_users.end();Iter++)
						{
							User *pUser = Iter->second;
							if(pUser->ValidUser())
							{
								if(m_lpEvent->m_lpInfo->skillPchId)
								{
									SkillPchId skill(m_lpEvent->m_lpInfo->skillPchId);
									pUser->AcquireSkill(skill.skillId, skill.level);
									pUser->ValidateParameters();
								}
							}
						}

						m_lpEvent->m_lpInfo->m_bluePosPosicion = 0;
						m_lpEvent->m_lpInfo->m_redPosPosicion = 0;

						if ( m_lpEvent->m_lpInfo->type == TvT::TvTLastTeamStanding || m_lpEvent->m_lpInfo->type == TvT::TvTDeathMatch || m_lpEvent->m_lpInfo->type == TvT::TvTCaptureTheFlag || m_lpEvent->m_lpInfo->type == TvT::TvTCaptureTheFlag2 || m_lpEvent->m_lpInfo->type == TvT::TvTDestroyTheBase || m_lpEvent->m_lpInfo->type == TvT::TvTCastle || m_lpEvent->m_lpInfo->type == TvT::TvTFortress)
						{
							if(m_lpEvent->m_lpInfo->bluePos[m_lpEvent->m_lpInfo->m_bluePosPosicion].x != 0 || m_lpEvent->m_lpInfo->bluePos[m_lpEvent->m_lpInfo->m_bluePosPosicion].y != 0)
							{
								//port blue
								for(map<UINT, User*>::iterator Iter = m_lpEvent->m_users.begin(); Iter!=m_lpEvent->m_users.end();Iter++)
								{
									User *pUser = Iter->second;
									if(pUser->ValidUser() && pUser->pED->tvtUser.team == TvT::TeamBlue)
									{
										if(m_lpEvent->m_lpInfo->type == TvT::TvTFortress)
											FortressApplySkill(pUser);

										

										const WCHAR* pFile = g_HTMLCacheManager.GetHTMLFile(m_lpEvent->m_lpInfo->HelpHtmlFile.c_str(), pUser->pSD->bLang);
										if(pFile)
										{
											PlayerAction::ShowHTML(pUser, m_lpEvent->m_lpInfo->HelpHtmlFile.c_str(), pFile, 0);
										}

										pUser->pED->tvtUser.orgPos.x = (INT32)pUser->pSD->Pos.x;
										pUser->pED->tvtUser.orgPos.y = (INT32)pUser->pSD->Pos.y;
										pUser->pED->tvtUser.orgPos.z = (INT32)pUser->pSD->Pos.z;
										pUser->pED->tvtUser.respawnPos.x = m_lpEvent->m_lpInfo->bluePos[m_lpEvent->m_lpInfo->m_bluePosPosicion].x;
										pUser->pED->tvtUser.respawnPos.y = m_lpEvent->m_lpInfo->bluePos[m_lpEvent->m_lpInfo->m_bluePosPosicion].y;
										pUser->pED->tvtUser.respawnPos.z = m_lpEvent->m_lpInfo->bluePos[m_lpEvent->m_lpInfo->m_bluePosPosicion].z;
										pUser->StopMove();
										PlayerAction::OnTeleportToLocation(pUser, m_lpEvent->m_lpInfo->bluePos[m_lpEvent->m_lpInfo->m_bluePosPosicion].x, m_lpEvent->m_lpInfo->bluePos[m_lpEvent->m_lpInfo->m_bluePosPosicion].y, m_lpEvent->m_lpInfo->bluePos[m_lpEvent->m_lpInfo->m_bluePosPosicion].z, false);
										if (m_lpEvent->m_lpInfo->m_bluePosPosicion+1 > m_lpEvent->m_lpInfo->m_bluePosCantidad)
											m_lpEvent->m_lpInfo->m_bluePosPosicion = 0;
										else
											m_lpEvent->m_lpInfo->m_bluePosPosicion++;

										Sleep(m_lpEvent->m_lpInfo->teleportDelay);
									}
								}
							}
							if(m_lpEvent->m_lpInfo->redPos[m_lpEvent->m_lpInfo->m_redPosPosicion].x != 0 || m_lpEvent->m_lpInfo->redPos[m_lpEvent->m_lpInfo->m_redPosPosicion].y != 0)
							{
								//port red
								for(map<UINT, User*>::iterator Iter = m_lpEvent->m_users.begin(); Iter!=m_lpEvent->m_users.end();Iter++)
								{
									User *pUser = Iter->second;
									if(pUser->ValidUser() && pUser->pED->tvtUser.team == TvT::TeamRed)
									{
										if(m_lpEvent->m_lpInfo->type == TvT::TvTFortress)
											FortressApplySkill(pUser);

										const WCHAR* pFile = g_HTMLCacheManager.GetHTMLFile(m_lpEvent->m_lpInfo->HelpHtmlFile.c_str(), pUser->pSD->bLang);
										if(pFile)
										{
											PlayerAction::ShowHTML(pUser, m_lpEvent->m_lpInfo->HelpHtmlFile.c_str(), pFile, 0);
										}

										pUser->pED->tvtUser.orgPos.x = (INT32)pUser->pSD->Pos.x;
										pUser->pED->tvtUser.orgPos.y = (INT32)pUser->pSD->Pos.y;
										pUser->pED->tvtUser.orgPos.z = (INT32)pUser->pSD->Pos.z;
										pUser->pED->tvtUser.respawnPos.x = m_lpEvent->m_lpInfo->redPos[m_lpEvent->m_lpInfo->m_redPosPosicion].x;
										pUser->pED->tvtUser.respawnPos.y = m_lpEvent->m_lpInfo->redPos[m_lpEvent->m_lpInfo->m_redPosPosicion].y;
										pUser->pED->tvtUser.respawnPos.z = m_lpEvent->m_lpInfo->redPos[m_lpEvent->m_lpInfo->m_redPosPosicion].z;
										pUser->StopMove();
										PlayerAction::OnTeleportToLocation(pUser, m_lpEvent->m_lpInfo->redPos[m_lpEvent->m_lpInfo->m_redPosPosicion].x, m_lpEvent->m_lpInfo->redPos[m_lpEvent->m_lpInfo->m_redPosPosicion].y, m_lpEvent->m_lpInfo->redPos[m_lpEvent->m_lpInfo->m_redPosPosicion].z, false);
										if (m_lpEvent->m_lpInfo->m_redPosPosicion+1 > m_lpEvent->m_lpInfo->m_redPosCantidad)
											m_lpEvent->m_lpInfo->m_redPosPosicion = 0;
										else
											m_lpEvent->m_lpInfo->m_redPosPosicion++;

										Sleep(m_lpEvent->m_lpInfo->teleportDelay);
									}
								}
							}
						}
						else if( m_lpEvent->m_lpInfo->type == TvT::TvTKorean )
						{
							int blue = 0;
							int red = 0;
					
							for(map<UINT, User*>::iterator Iter = m_lpEvent->m_users.begin(); Iter!=m_lpEvent->m_users.end();Iter++)
							{
								User *pUser = Iter->second;
								if(pUser->ValidUser())
								{
									//add block skill
									g_TvT.ApplyProtectionSkill(pUser);

									//do the save spots
									pUser->pED->tvtUser.orgPos.x = (INT32)pUser->pSD->Pos.x;
									pUser->pED->tvtUser.orgPos.y = (INT32)pUser->pSD->Pos.y;
									pUser->pED->tvtUser.orgPos.z = (INT32)pUser->pSD->Pos.z;
										
									//Do The Buffs
									if(pUser->ValidUser() && pUser->pSD->nAlive)
									{
										if(CCategoryDataDB::IsInCategory(pUser->pSD->nClass, CCategoryDataDB::MAGE_GROUP))
										{
											for(UINT n=0;n<m_lpEvent->m_lpInfo->defaultMageBuffs.size();n++)
											{
												if(CSkillInfo *pSI = g_SkillDB.GetSkillInfo(m_lpEvent->m_lpInfo->defaultMageBuffs[n].skillId, m_lpEvent->m_lpInfo->defaultMageBuffs[n].level))
												{
													pSI->ActivateSkill(pUser, pUser);
												}
											}
										}else
										{
											for(UINT n=0;n<m_lpEvent->m_lpInfo->defaultFighterBuffs.size();n++)
											{
												if(CSkillInfo *pSI = g_SkillDB.GetSkillInfo(m_lpEvent->m_lpInfo->defaultFighterBuffs[n].skillId, m_lpEvent->m_lpInfo->defaultFighterBuffs[n].level))
												{
													pSI->ActivateSkill(pUser, pUser);
												}
											}
										}
									}

										//teleport to different locations
									pUser->StopMove();
									if( pUser->pED->tvtUser.team == TvT::TeamBlue)
									{
										if(m_lpEvent->m_lpInfo->bluePos[m_lpEvent->m_lpInfo->m_bluePosPosicion].x != 0 || m_lpEvent->m_lpInfo->bluePos[m_lpEvent->m_lpInfo->m_bluePosPosicion].y != 0)
										{
											//port blue
								//			for(map<UINT, User*>::iterator Iter = m_lpEvent->m_users.begin(); Iter!=m_lpEvent->m_users.end();Iter++)
								//			{
												User *pUser = Iter->second;
												if(pUser->ValidUser() && pUser->pED->tvtUser.team == TvT::TeamBlue)
												{
													blue++;
													pUser->pED->tvtUser.korean_par = blue;
													pUser->pED->tvtUser.orgPos.x = (INT32)pUser->pSD->Pos.x;
													pUser->pED->tvtUser.orgPos.y = (INT32)pUser->pSD->Pos.y;
													pUser->pED->tvtUser.orgPos.z = (INT32)pUser->pSD->Pos.z;
													pUser->pED->tvtUser.respawnPos.x = m_lpEvent->m_lpInfo->bluePos[m_lpEvent->m_lpInfo->m_bluePosPosicion].x;
													pUser->pED->tvtUser.respawnPos.y = m_lpEvent->m_lpInfo->bluePos[m_lpEvent->m_lpInfo->m_bluePosPosicion].y;
													pUser->pED->tvtUser.respawnPos.z = m_lpEvent->m_lpInfo->bluePos[m_lpEvent->m_lpInfo->m_bluePosPosicion].z;
													pUser->StopMove();
													PlayerAction::OnTeleportToLocation(pUser, m_lpEvent->m_lpInfo->bluePos[m_lpEvent->m_lpInfo->m_bluePosPosicion].x, m_lpEvent->m_lpInfo->bluePos[m_lpEvent->m_lpInfo->m_bluePosPosicion].y, m_lpEvent->m_lpInfo->bluePos[m_lpEvent->m_lpInfo->m_bluePosPosicion].z, false);
													if (m_lpEvent->m_lpInfo->m_bluePosPosicion+1 > m_lpEvent->m_lpInfo->m_bluePosCantidad)
														m_lpEvent->m_lpInfo->m_bluePosPosicion = 0;
													else
														m_lpEvent->m_lpInfo->m_bluePosPosicion++;

													Sleep(m_lpEvent->m_lpInfo->teleportDelay);
												}
								//			}
										}
									}

									if( pUser->pED->tvtUser.team == TvT::TeamRed)
									{
										if(m_lpEvent->m_lpInfo->redPos[m_lpEvent->m_lpInfo->m_redPosPosicion].x != 0 || m_lpEvent->m_lpInfo->redPos[m_lpEvent->m_lpInfo->m_redPosPosicion].y != 0)
										{
											//port red
								//			for(map<UINT, User*>::iterator Iter = m_lpEvent->m_users.begin(); Iter!=m_lpEvent->m_users.end();Iter++)
								//			{
												User *pUser = Iter->second;
												if(pUser->ValidUser() && pUser->pED->tvtUser.team == TvT::TeamRed)
												{
													red++;
													pUser->pED->tvtUser.korean_par = red;
													pUser->pED->tvtUser.orgPos.x = (INT32)pUser->pSD->Pos.x;
													pUser->pED->tvtUser.orgPos.y = (INT32)pUser->pSD->Pos.y;
													pUser->pED->tvtUser.orgPos.z = (INT32)pUser->pSD->Pos.z;
													pUser->pED->tvtUser.respawnPos.x = m_lpEvent->m_lpInfo->redPos[m_lpEvent->m_lpInfo->m_redPosPosicion].x;
													pUser->pED->tvtUser.respawnPos.y = m_lpEvent->m_lpInfo->redPos[m_lpEvent->m_lpInfo->m_redPosPosicion].y;
													pUser->pED->tvtUser.respawnPos.z = m_lpEvent->m_lpInfo->redPos[m_lpEvent->m_lpInfo->m_redPosPosicion].z;
													pUser->StopMove();
													PlayerAction::OnTeleportToLocation(pUser, m_lpEvent->m_lpInfo->redPos[m_lpEvent->m_lpInfo->m_redPosPosicion].x, m_lpEvent->m_lpInfo->redPos[m_lpEvent->m_lpInfo->m_redPosPosicion].y, m_lpEvent->m_lpInfo->redPos[m_lpEvent->m_lpInfo->m_redPosPosicion].z, false);
													if (m_lpEvent->m_lpInfo->m_redPosPosicion+1 > m_lpEvent->m_lpInfo->m_redPosCantidad)
														m_lpEvent->m_lpInfo->m_redPosPosicion = 0;
													else
														m_lpEvent->m_lpInfo->m_redPosPosicion++;

													Sleep(m_lpEvent->m_lpInfo->teleportDelay);
												}
											}
								//		}
									}
								}
							}
							
							//pUser->SitStand()
							//pUser->IsStanding()
						}
						else if( m_lpEvent->m_lpInfo->type == TvT::TvTLastManStanding )
						{
							int number = 0;
					
							for(map<UINT, User*>::iterator Iter = m_lpEvent->m_users.begin(); Iter!=m_lpEvent->m_users.end();Iter++)
							{
								User *pUser = Iter->second;
								if(pUser->ValidUser())
								{
									//add block skill
									g_TvT.ApplyProtectionSkill(pUser);

									//do the save spots
									pUser->pED->tvtUser.orgPos.x = (INT32)pUser->pSD->Pos.x;
									pUser->pED->tvtUser.orgPos.y = (INT32)pUser->pSD->Pos.y;
									pUser->pED->tvtUser.orgPos.z = (INT32)pUser->pSD->Pos.z;
											
									//Do The Buffs
									if(pUser->ValidUser() && pUser->pSD->nAlive)
									{
										if(CCategoryDataDB::IsInCategory(pUser->pSD->nClass, CCategoryDataDB::MAGE_GROUP))
										{
											for(UINT n=0;n<m_lpEvent->m_lpInfo->defaultMageBuffs.size();n++)
											{
												if(CSkillInfo *pSI = g_SkillDB.GetSkillInfo(m_lpEvent->m_lpInfo->defaultMageBuffs[n].skillId, m_lpEvent->m_lpInfo->defaultMageBuffs[n].level))
												{
													pSI->ActivateSkill(pUser, pUser);
												}
											}
										}else
										{
											for(UINT n=0;n<m_lpEvent->m_lpInfo->defaultFighterBuffs.size();n++)
											{
												if(CSkillInfo *pSI = g_SkillDB.GetSkillInfo(m_lpEvent->m_lpInfo->defaultFighterBuffs[n].skillId, m_lpEvent->m_lpInfo->defaultFighterBuffs[n].level))
												{
													pSI->ActivateSkill(pUser, pUser);
												}
											}
										}
									}
									//teleport to different locations
									pUser->StopMove();
									if( pUser->pED->tvtUser.team == TvT::TeamBlue)
									{
										pUser->pED->tvtUser.respawnPos.x = m_lpEvent->m_lpInfo->bluePos[number].x; 
										pUser->pED->tvtUser.respawnPos.y = m_lpEvent->m_lpInfo->bluePos[number].y; 
										pUser->pED->tvtUser.respawnPos.z = m_lpEvent->m_lpInfo->bluePos[number].z;
										PlayerAction::OnTeleportToLocation(pUser, m_lpEvent->m_lpInfo->bluePos[number].x, m_lpEvent->m_lpInfo->bluePos[number].y, m_lpEvent->m_lpInfo->bluePos[number].z, false);
										number++;

										Sleep(m_lpEvent->m_lpInfo->teleportDelay);
									}
								}
							}
					}
					else
					{
						//do nothing...
					}
				}
				break;
			}
			case TvT::StateCountDown:
				{
					time_t diff = m_lpEvent->m_stateTime + m_lpEvent->m_lpInfo->countDownTime;
					diff -= currentTime;
					if(diff > 0)
					{
						if(m_lpEvent->m_lpInfo->fightStartRemindMsg.size() > 0)
						{
							if(diff == 120)
							{
								TCHAR remainSec[16];
								_itot_s(static_cast<int>(diff), remainSec, 16, 10);
								wstring announce = Utils::ReplaceString(m_lpEvent->m_lpInfo->fightStartRemindMsg, _T("[param]"), remainSec);
								m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", announce.c_str());
							}else if(diff == 90)
							{
								TCHAR remainSec[16];
								_itot_s(static_cast<int>(diff), remainSec, 16, 10);
								wstring announce = Utils::ReplaceString(m_lpEvent->m_lpInfo->fightStartRemindMsg, _T("[param]"), remainSec);
								m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", announce.c_str());
							}else if(diff == 60)
							{
								TCHAR remainSec[16];
								_itot_s(static_cast<int>(diff), remainSec, 16, 10);
								wstring announce = Utils::ReplaceString(m_lpEvent->m_lpInfo->fightStartRemindMsg, _T("[param]"), remainSec);
								m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", announce.c_str());
							}else if(diff == 30)
							{
								TCHAR remainSec[16];
								_itot_s(static_cast<int>(diff), remainSec, 16, 10);
								wstring announce = Utils::ReplaceString(m_lpEvent->m_lpInfo->fightStartRemindMsg, _T("[param]"), remainSec);
								m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", announce.c_str());
							}else if(diff == 15)
							{
								TCHAR remainSec[16];
								_itot_s(static_cast<int>(diff), remainSec, 16, 10);
								wstring announce = Utils::ReplaceString(m_lpEvent->m_lpInfo->fightStartRemindMsg, _T("[param]"), remainSec);
								m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", announce.c_str());
							}else if(diff == 10)
							{
								TCHAR remainSec[16];
								_itot_s(static_cast<int>(diff), remainSec, 16, 10);
								wstring announce = Utils::ReplaceString(m_lpEvent->m_lpInfo->fightStartRemindMsg, _T("[param]"), remainSec);
								m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", announce.c_str());
							}
							else if(diff < 6)
							{
								TCHAR remainSec[16];
								_itot_s(static_cast<int>(diff), remainSec, 16, 10);
								wstring announce = Utils::ReplaceString(m_lpEvent->m_lpInfo->fightStartRemindMsg, _T("[param]"), remainSec);
								m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", announce.c_str());
							}
						}
					}else
					{
						m_lpEvent->m_stateTime = time(NULL);
						m_lpEvent->m_state = TvT::StateFight;
						for(map<UINT, User*>::iterator Iter = m_lpEvent->m_users.begin(); Iter!=m_lpEvent->m_users.end();Iter++)
						{
							User *pUser = Iter->second;
							if(pUser->ValidUser() && pUser->pSD->nAlive)
							{
								pUser->pED->tvtUser.status = TvT::UserFighting;

								if (m_lpEvent->m_lpInfo->MeterAlEventoSiHayCritico)
								{
									map<UINT, TvTUser>::iterator Iter2 = m_lpEvent->m_usersBackup.find(pUser->nDBID);
									if(Iter2!=m_lpEvent->m_usersBackup.end())
									{
										Iter2->second = TvTUser(pUser->pED->tvtUser);
									}
								}

								TvTInfo *pInfo = m_lpEvent->m_lpInfo;
								if(pInfo)
								{
									if(CCategoryDataDB::IsInCategory(pUser->pSD->nClass, CCategoryDataDB::MAGE_GROUP))
									{
										for(UINT n=0;n<pInfo->defaultMageBuffs.size();n++)
										{
											if(CSkillInfo *pSI = g_SkillDB.GetSkillInfo(pInfo->defaultMageBuffs[n].skillId, pInfo->defaultMageBuffs[n].level))
											{
												pSI->ActivateSkill(pUser, pUser);
											}
										}
									}else
									{
										for(UINT n=0;n<pInfo->defaultFighterBuffs.size();n++)
										{
											if(CSkillInfo *pSI = g_SkillDB.GetSkillInfo(pInfo->defaultFighterBuffs[n].skillId, pInfo->defaultFighterBuffs[n].level))
											{
												pSI->ActivateSkill(pUser, pUser);
											}
										}
									}
								}
							}
						}
						if(m_lpEvent->m_lpInfo->type == TvT::TvTFortress )
							FortressTeleports();

						m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", m_lpEvent->m_lpInfo->fightStartMessage.c_str());
					}
					break;
				}
			case TvT::StateFight:
				{
					UINT m_buffer1 = m_lpEvent->m_buffer1;
					UINT m_buffer2 = m_lpEvent->m_buffer2;
					UINT m_buffer3 = m_lpEvent->m_buffer3;
					UINT m_buffer4 = m_lpEvent->m_buffer4;

					if(m_buffer1)
					{
						CNPC *pNpc = CNPC::GetNPCByServerId(&m_buffer1);
						if(pNpc)
						{
							if(pNpc->pSD->nAlive)
							{
								pNpc->KillNPC();
							}
						}
						m_buffer1 = 0;
					}

					if(m_buffer2)
					{
						CNPC *pNpc = CNPC::GetNPCByServerId(&m_buffer2);
						if(pNpc)
						{
							if(pNpc->pSD->nAlive)
							{
								pNpc->KillNPC();
							}
						}
						m_buffer2 = 0;
					}

					if(m_buffer3)
					{
						CNPC *pNpc = CNPC::GetNPCByServerId(&m_buffer3);
						if(pNpc)
						{
							if(pNpc->pSD->nAlive)
							{
								pNpc->KillNPC();
							}
						}
						m_buffer3 = 0;
					}

					if(m_buffer4)
					{
						CNPC *pNpc = CNPC::GetNPCByServerId(&m_buffer4);
						if(pNpc)
						{
							if(pNpc->pSD->nAlive)
							{
								pNpc->KillNPC();
							}
						}
						m_buffer4 = 0;
					}
					//pUser->pED->tvtUser.team == TvT::TeamBlue

					if(!m_lpEvent->m_FlagsSpawned)
					{
	//					map<wstring, wstring> aiParams;
	//					aiParams.insert(pair<wstring, wstring>(L"fnHi", L"nothing.htm"));
	//					m_lpEvent->m_BlueFlag = NpcServer::SpawnNpcEx(m_lpEvent->m_lpInfo->blueFlagId, m_lpEvent->m_lpInfo->blueFlagPos.x, m_lpEvent->m_lpInfo->blueFlagPos.y, m_lpEvent->m_lpInfo->blueFlagPos.z, aiParams);
	//					m_lpEvent->m_RedFlag = NpcServer::SpawnNpcEx(m_lpEvent->m_lpInfo->redFlagId, m_lpEvent->m_lpInfo->redFlagPos.x, m_lpEvent->m_lpInfo->redFlagPos.y, m_lpEvent->m_lpInfo->redFlagPos.z, aiParams);
	//					m_lpEvent->m_FlagsSpawned=true;
					}

					if( (m_lpEvent->m_lpInfo->type == TvT::TvTLastTeamStanding) 
						|| (m_lpEvent->m_lpInfo->type == TvT::TvTDeathMatch) 
						|| (m_lpEvent->m_lpInfo->type == TvT::TvTGMReGroup)
						|| (m_lpEvent->m_lpInfo->type == TvT::TvTCaptureTheFlag)
						|| (m_lpEvent->m_lpInfo->type == TvT::TvTCaptureTheFlag2)
						|| (m_lpEvent->m_lpInfo->type == TvT::TvTDestroyTheBase)
						|| (m_lpEvent->m_lpInfo->type == TvT::TvTCastle)
						|| (m_lpEvent->m_lpInfo->type == TvT::TvTFortress))
					{
						time_t diff = m_lpEvent->m_stateTime + m_lpEvent->m_lpInfo->fightTime;
						diff -= currentTime;
						if(diff > 0)
						{
							if(m_lpEvent->m_lpInfo->fightEndRemindMsg.size() > 0)
							{
								if(diff == m_lpEvent->m_lpInfo->InvertirPuestos && m_lpEvent->m_lpInfo->InvertirPuestos>0)
								{
									m_lpEvent->m_lpInfo->m_bluePosPosicion = 0;
									m_lpEvent->m_lpInfo->m_redPosPosicion = 0;

									if(m_lpEvent->m_lpInfo->bluePos[m_lpEvent->m_lpInfo->m_bluePosPosicion].x != 0 || m_lpEvent->m_lpInfo->bluePos[m_lpEvent->m_lpInfo->m_bluePosPosicion].y != 0)
									{
										//port blue
										for(map<UINT, User*>::iterator Iter = m_lpEvent->m_users.begin(); Iter!=m_lpEvent->m_users.end();Iter++)
										{
											User *pUser = Iter->second;
											if(pUser->ValidUser() && pUser->pED->tvtUser.team == TvT::TeamBlue)
											{
												pUser->pED->tvtUser.respawnPos.x = m_lpEvent->m_lpInfo->redPos[m_lpEvent->m_lpInfo->m_redPosPosicion].x;
												pUser->pED->tvtUser.respawnPos.y = m_lpEvent->m_lpInfo->redPos[m_lpEvent->m_lpInfo->m_redPosPosicion].y;
												pUser->pED->tvtUser.respawnPos.z = m_lpEvent->m_lpInfo->redPos[m_lpEvent->m_lpInfo->m_redPosPosicion].z;

												if (m_lpEvent->m_lpInfo->MeterAlEventoSiHayCritico)
												{
													map<UINT, TvTUser>::iterator Iter2 = m_lpEvent->m_usersBackup.find(pUser->nDBID);
													if(Iter2!=m_lpEvent->m_usersBackup.end())
													{
														Iter2->second = TvTUser(pUser->pED->tvtUser);
													}
												}

												pUser->StopMove();
												PlayerAction::OnTeleportToLocation(pUser, m_lpEvent->m_lpInfo->redPos[m_lpEvent->m_lpInfo->m_redPosPosicion].x, m_lpEvent->m_lpInfo->redPos[m_lpEvent->m_lpInfo->m_redPosPosicion].y, m_lpEvent->m_lpInfo->redPos[m_lpEvent->m_lpInfo->m_redPosPosicion].z, false);
												if (m_lpEvent->m_lpInfo->m_redPosPosicion+1 > m_lpEvent->m_lpInfo->m_redPosCantidad)
													m_lpEvent->m_lpInfo->m_redPosPosicion = 0;
												else
													m_lpEvent->m_lpInfo->m_redPosPosicion++;

												Sleep(m_lpEvent->m_lpInfo->teleportDelay);
											}
										}
									}
									if(m_lpEvent->m_lpInfo->redPos[m_lpEvent->m_lpInfo->m_redPosPosicion].x != 0 || m_lpEvent->m_lpInfo->redPos[m_lpEvent->m_lpInfo->m_redPosPosicion].y != 0)
									{
										//port red
										for(map<UINT, User*>::iterator Iter = m_lpEvent->m_users.begin(); Iter!=m_lpEvent->m_users.end();Iter++)
										{
											User *pUser = Iter->second;
											if(pUser->ValidUser() && pUser->pED->tvtUser.team == TvT::TeamRed)
											{
												pUser->pED->tvtUser.respawnPos.x = m_lpEvent->m_lpInfo->bluePos[m_lpEvent->m_lpInfo->m_bluePosPosicion].x;
												pUser->pED->tvtUser.respawnPos.y = m_lpEvent->m_lpInfo->bluePos[m_lpEvent->m_lpInfo->m_bluePosPosicion].y;
												pUser->pED->tvtUser.respawnPos.z = m_lpEvent->m_lpInfo->bluePos[m_lpEvent->m_lpInfo->m_bluePosPosicion].z;

												if (m_lpEvent->m_lpInfo->MeterAlEventoSiHayCritico)
												{
													map<UINT, TvTUser>::iterator Iter2 = m_lpEvent->m_usersBackup.find(pUser->nDBID);
													if(Iter2!=m_lpEvent->m_usersBackup.end())
													{
														Iter2->second = TvTUser(pUser->pED->tvtUser);
													}
												}

												pUser->StopMove();
												PlayerAction::OnTeleportToLocation(pUser, m_lpEvent->m_lpInfo->bluePos[m_lpEvent->m_lpInfo->m_bluePosPosicion].x, m_lpEvent->m_lpInfo->bluePos[m_lpEvent->m_lpInfo->m_bluePosPosicion].y, m_lpEvent->m_lpInfo->bluePos[m_lpEvent->m_lpInfo->m_bluePosPosicion].z, false);
												if (m_lpEvent->m_lpInfo->m_bluePosPosicion+1 > m_lpEvent->m_lpInfo->m_bluePosCantidad)
													m_lpEvent->m_lpInfo->m_bluePosPosicion = 0;
												else
													m_lpEvent->m_lpInfo->m_bluePosPosicion++;

												Sleep(m_lpEvent->m_lpInfo->teleportDelay);
											}
										}
									}
								}else if(diff == 30)
								{
									TCHAR remainSec[16];
									_itot_s(static_cast<int>(diff), remainSec, 16, 10);
									wstring announce = Utils::ReplaceString(m_lpEvent->m_lpInfo->fightEndRemindMsg, _T("[param]"), remainSec);
									m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", announce.c_str());
								}else if(diff == 10)
								{
									TCHAR remainSec[16];
									_itot_s(static_cast<int>(diff), remainSec, 16, 10);
									wstring announce = Utils::ReplaceString(m_lpEvent->m_lpInfo->fightEndRemindMsg, _T("[param]"), remainSec);
									m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", announce.c_str());
								}
								else if(diff < 6)
								{
									TCHAR remainSec[16];
									_itot_s(static_cast<int>(diff), remainSec, 16, 10);
									wstring announce = Utils::ReplaceString(m_lpEvent->m_lpInfo->fightEndRemindMsg, _T("[param]"), remainSec);
									m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", announce.c_str());
								}
								if(m_lpEvent->ValidateWinner())
								{
									m_lpEvent->OnFinish();
								}

								//----------------------------TITLE TVT
								if (m_lpEvent->m_lpInfo->MostrarTitlesKills)
								{
									WCHAR wTitle_blue[25];
									WCHAR wTitle_red[25];

									int killCountBlue = m_lpEvent->m_killCountBlue;
									int killCountRed = m_lpEvent->m_killCountRed;

									int tomasCountBlue = m_lpEvent->m_tomasCountBlue;
									int tomasCountRed = m_lpEvent->m_tomasCountRed;

									int VidasPorEquipo = m_lpEvent->m_lpInfo->MaximoVidasPorEquipo;

									int ctfCaptureCountBlue = m_lpEvent->m_ctfCaptureCountBlue;
									std::wstringstream wss;

									if (m_lpEvent->m_lpInfo->MaximoVidasPorEquipo == 0)
									{
										if (m_lpEvent->m_lpInfo->type == TvT::TvTDeathMatch || m_lpEvent->m_lpInfo->type == TvT::TvTCastle)
											wss << "Kills " << killCountBlue;
										else if (m_lpEvent->m_lpInfo->type == TvT::TvTCaptureTheFlag2)
											wss << "Cap [" << ctfCaptureCountBlue << "] Kills " << killCountBlue;
										else if (m_lpEvent->m_lpInfo->type == TvT::TvTDestroyTheBase)
											wss << "Kills " << killCountBlue;
										else if (m_lpEvent->m_lpInfo->type == TvT::TvTFortress)
											wss << "Tomas [ " << tomasCountBlue << " ] - Kills:" << killCountBlue;

									}
									else
									{
										wss << "A: " << (VidasPorEquipo - killCountRed) << "/" << VidasPorEquipo << " - " << "R: " << (VidasPorEquipo - killCountBlue) << "/" << VidasPorEquipo;
									}

									wstring value = wss.str();
									const WCHAR * value2 = value.c_str();

									//--------------

									//int killCountRed = m_lpEvent->m_killCountRed;
									int ctfCaptureCountRed = m_lpEvent->m_ctfCaptureCountRed;
									std::wstringstream wss1;

									if (m_lpEvent->m_lpInfo->MaximoVidasPorEquipo == 0)
									{
										if (m_lpEvent->m_lpInfo->type == TvT::TvTDeathMatch || m_lpEvent->m_lpInfo->type == TvT::TvTCastle)
											wss1 << "Kills " << killCountRed;
										else if (m_lpEvent->m_lpInfo->type == TvT::TvTCaptureTheFlag2)
											wss1 << "Cap [" << ctfCaptureCountRed << "] Kills " << killCountRed;
										else if (m_lpEvent->m_lpInfo->type == TvT::TvTDestroyTheBase)
											wss1 << "Kills " << killCountRed;
										else if (m_lpEvent->m_lpInfo->type == TvT::TvTFortress)
											wss1 << "Tomas [ " << tomasCountRed << " ] - Kills:" << killCountRed;
									}
									else
									{
										wss1 << "R: " << (VidasPorEquipo - killCountBlue) << "/" << VidasPorEquipo << " - "  << "A: " << (VidasPorEquipo - killCountRed) << "/" << VidasPorEquipo;
									}

									wstring value20 = wss1.str();
									const WCHAR * value22 = value20.c_str();

									//------------------------

									if (m_lpEvent->m_lpInfo->type == TvT::TvTLastTeamStanding)
									{
										value2 = m_lpEvent->m_lpInfo->TitleCustomBlue.c_str();
										value22 = m_lpEvent->m_lpInfo->TitleCustomRed.c_str();
									}

									if (wcslen(value2) < (sizeof(wTitle_blue)/sizeof(wchar_t)))
										 wcscpy(wTitle_blue, value2);

									if (wcslen(value22) < (sizeof(wTitle_red)/sizeof(wchar_t)))
										  wcscpy(wTitle_red, value22);

									for(map<UINT, User*>::iterator Iter = m_lpEvent->m_users.begin(); Iter!=m_lpEvent->m_users.end();Iter++)
									{
										try
										{
											User *pUser = Iter->second;
											if(pUser->ValidUser() && pUser->pED->tvtUser.team == TvT::TeamBlue)
											{
											//	pUser->pED->nameColorEx = 16725257;
												pUser->pED->titleColorEx = m_lpEvent->m_lpInfo->TitleColorBlue;
												
												if (m_lpEvent->m_lpInfo->MostrarMuertesParaElTop)
												{
													std::wstringstream wss;
													wss << wTitle_blue << " [ " << pUser->pED->tvtUser.killCount << " ]";
													wstring value = wss.str();
													const WCHAR * value2 = value.c_str();

													wcscpy(pUser->wTitle, value2);
												}
												else
													wcscpy(pUser->wTitle, wTitle_blue);

												pUser->SetUserInfoChanged();
												pUser->SetCharInfoChanged();
											}
											else if(pUser->ValidUser() && pUser->pED->tvtUser.team == TvT::TeamRed)
											{
											//	pUser->pED->nameColorEx = 1114876;
												pUser->pED->titleColorEx = m_lpEvent->m_lpInfo->TitleColorRed;

												if (m_lpEvent->m_lpInfo->MostrarMuertesParaElTop)
												{
													std::wstringstream wss;
													wss << wTitle_red << " [ " << pUser->pED->tvtUser.killCount << " ]";
													wstring value = wss.str();
													const WCHAR * value2 = value.c_str();

													wcscpy(pUser->wTitle, value2);
												}
												else
													wcscpy(pUser->wTitle, wTitle_red);

												pUser->SetUserInfoChanged();
												pUser->SetCharInfoChanged();

											}
										}
										catch(...)
										{

										}
									}
								}
								//----------------------------TITLE TVT

							}
						}else
						{
							m_lpEvent->ValidateWinner(true);
							m_lpEvent->OnFinish();
						}
					}
					else if(m_lpEvent->m_lpInfo->type == TvT::TvTKorean)
					{
						//main routine
						if(g_TvT.PickPlayersForMatchKorean())
						{
							//Give Prize to winner
							m_lpEvent->OnFinish();
						}

					}
					else
					{
						//nothing?
					}

					break;
				}
			case TvT::StateFinish:
				{
					time_t diff = m_lpEvent->m_stateTime + m_lpEvent->m_lpInfo->finishTime;
					diff -= currentTime;
					if(diff > 0)
					{
						if(m_lpEvent->m_lpInfo->teleportBackRemindMsg.size() > 0)
						{
							if(diff == 10)
							{
								TCHAR remainSec[16];
								_itot_s(static_cast<int>(diff), remainSec, 16, 10);
								wstring announce = Utils::ReplaceString(m_lpEvent->m_lpInfo->teleportBackRemindMsg, _T("[param]"), remainSec);
								m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", announce.c_str());
							}else if(diff < 6)
							{
								TCHAR remainSec[16];
								_itot_s(static_cast<int>(diff), remainSec, 16, 10);
								wstring announce = Utils::ReplaceString(m_lpEvent->m_lpInfo->teleportBackRemindMsg, _T("[param]"), remainSec);
								m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", announce.c_str());
							}
						}
					}else
					{
						m_lpEvent->m_stateTime = time(NULL);

						if(m_lpEvent->m_lpInfo->type == TvT::TvTCaptureTheFlag)
						{
							if(m_lpEvent->m_BlueFlag)
							{
								CNPC *pNpc = CNPC::GetNPCByServerId(&m_lpEvent->m_BlueFlag);
								if(pNpc)
								{
									if(pNpc->pSD->nAlive)
									{
										pNpc->KillNPC();
									}
								}
								m_lpEvent->m_BlueFlag = 0;
							}

							if(m_lpEvent->m_RedFlag)
							{
								CNPC *pNpc = CNPC::GetNPCByServerId(&m_lpEvent->m_RedFlag);
								if(pNpc)
								{
									if(pNpc->pSD->nAlive)
									{
										pNpc->KillNPC();
									}
								}
								m_lpEvent->m_RedFlag = 0;
							}
						}
						m_lpEvent->m_state = TvT::StateDelete;
					}
					break;
				}
			case TvT::StateDelete:
				{
					m_lpEvent->OnDelete();
					delete m_lpEvent;
					m_lpEvent = 0;
					break;
				};
			};
		}else
		{
			tm ti; time_t rawtime;
			time ( &rawtime );
			localtime_s(&ti, &rawtime );

			for(list<TvT::TvTInfo*>::iterator Iter = m_tvtInfo.begin();Iter!=m_tvtInfo.end();Iter++)
			{
				TvT::TvTInfo *pInfo = (*Iter);
				if(pInfo)
				{
					if(pInfo->enabled)
					{
						if(pInfo->dayFlag[ti.tm_wday])
						{
							if(pInfo->startHour == ti.tm_hour && pInfo->startMinute == ti.tm_min)
							{
								m_lpEvent = new CMatch(pInfo);
								break;
							}
						}
					}
				}
			}
		}
		Unlock();
	}
	unguard;
}

void CTvT::Unregister(User *pUser)
{
	if(!m_enabled)
		return;

	if(pUser->ValidUser())
	{
		if(pUser->pED->tvtUser.status != TvT::UserNone)
		{
			Lock();
			if(m_lpEvent)
			{
				if(m_lpEvent->m_state == TvT::StateRegistration)
				{
					if(m_lpEvent->m_lpInfo->type == 3)
					{
						//Check if has party
						CParty *pParty = pUser->GetParty();
						if(pParty)
						{
							//Check if it is leader
							User *pPartyLeader = pParty->GetMaster();
							if(pPartyLeader == pUser)
							{
								//register party
								UserVector vUsers;
								pParty->GetAllMembersEx(vUsers);
								UserVector::iterator Iter = vUsers.begin();
								for(;Iter!=vUsers.end();Iter++)
								{
									User *pMember = *Iter;
									if(pMember->ValidUser())
									{

										map<UINT, User*>::iterator Iter = m_lpEvent->m_users.find(pMember->nDBID);
										if(Iter!= m_lpEvent->m_users.end())
										{
											m_lpEvent->m_users.erase(Iter);
									
											//2653	1	a,Your party has been un-registered into the event.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
											pUser->pSocket->SendSystemMessage(2653);
										}

										if (m_lpEvent->m_lpInfo->MeterAlEventoSiHayCritico)
										{
											map<UINT, TvTUser>::iterator Iter2 = m_lpEvent->m_usersBackup.find(pMember->nDBID);
											if(Iter2!=m_lpEvent->m_usersBackup.end())
											{
												m_lpEvent->m_usersBackup.erase(Iter2);
											}
										}
									}
								}
							}
							else
							{
								//2652	1	a,Only Party Leader can un-register on event.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
								pUser->pSocket->SendSystemMessage(2652);
							}
						}
						else
						{
							//2651	1	a,You don't have any party in order to un-register on event.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
							pUser->pSocket->SendSystemMessage(2651);
						}
					}
					else
					{
						map<UINT, User*>::iterator Iter = m_lpEvent->m_users.find(pUser->nDBID);
						if(Iter!= m_lpEvent->m_users.end())
						{
							m_lpEvent->m_users.erase(Iter);
							//2580	1	a,You've been unregistered from TvT event.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
							pUser->pSocket->SendSystemMessage(2580);
							if(m_lpEvent->m_lpInfo->requiredItemId > 0)
							{
								pUser->AddItemToInventory(m_lpEvent->m_lpInfo->requiredItemId, m_lpEvent->m_lpInfo->requiredItemCount);
							}
						}

						if (m_lpEvent->m_lpInfo->MeterAlEventoSiHayCritico)
						{
							map<UINT, TvTUser>::iterator Iter2 = m_lpEvent->m_usersBackup.find(pUser->nDBID);
							if(Iter2!=m_lpEvent->m_usersBackup.end())
							{
								m_lpEvent->m_usersBackup.erase(Iter2);
							}
						}

						pUser->pED->m_CtfUserFlag = 0;
						pUser->pED->m_CtfUserFlagWeapon = 0;
					}
				}else
				{
					//2581	1	a,You cannot unregister from TvT event at the moment.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
					pUser->pSocket->SendSystemMessage(2581);
				}
			}
			Unlock();
			pUser->pED->tvtUser.Clear();
			pUser->pSD->teamType = 0;
		}
	}
}

void CTvT::Register(User *pUser, int team)
{
	CTL;

	if(!m_enabled)
		return;

	if(pUser->olympiadUser.GetState() != 0)
	{
		pUser->SendSystemMessage(L"No puedes anotarte porque estas anotado en Olympiadas!");
		return;
	}

	if(pUser->pED->tvtUser.status == TvT::UserNone)
	{
		if(pUser->pSD->nCursedOwner)
		{
			//2582	1	a,The Cursed Weapon owner cannot participe in TvT event.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
			pUser->pSocket->SendSystemMessage(2582);
			return;
		}
		if(pUser->pSD->nKarma)
		{
			pUser->pSocket->SendSystemMessage(2582);
			return;
		}
		if(pUser->pSD->nAlive == 0)
		{
			//2578	1	a,Only alive players can participe in TvT event.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
			pUser->SendSystemMessage(2578);
			return;
		}
		if(pUser->pSD->pExData->territoryData.territoryId[BLOCK_TVT_ZONE] != 0)
		{
			//2579	1	a,You cannot participe in TvT event while being in current location!\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
			pUser->pSocket->SendSystemMessage(2579);
			return;
		}

		if(pUser->pED->aioId > 0)
		{
			pUser->SendSystemMessage(2578);
			return;
		}

		Lock();
		if(m_lpEvent)
		{
			if(m_lpEvent->m_state == TvT::StateRegistration)
			{
				if(g_PvPEvents.InEvent(pUser))
				{
					Unlock();
					pUser->SendSystemMessage(L"Ya estas anotado en otro evento");
					return;
				}



				if(pUser->pSD->nLevel >= m_lpEvent->m_lpInfo->minLevel)
				{
					if(pUser->pSD->nLevel <= m_lpEvent->m_lpInfo->maxLevel || pUser->pSD->nSubJobClass[1] != -1)
					{
						if(m_lpEvent->m_users.size() < m_lpEvent->m_lpInfo->maxPlayers)
						{
							if(team == 0)
							{
								team = 1 + g_Random.RandInt(1);
							}
							if(m_lpEvent->m_lpInfo->checkHwid)
							{
								UINT ip = pUser->pSocket->addr.S_un.S_addr;
								for(map<UINT, User*>::iterator Iter = m_lpEvent->m_users.begin();Iter!=m_lpEvent->m_users.end();Iter++)
								{
									if(User *pOther = Iter->second->GetUser())
									{
										if(pOther->pSocket->addr.S_un.S_addr == ip && !memcmp(pOther->pSocket->pED->longHWID.hash, pUser->pSocket->pED->longHWID.hash, 32))
										{
											Unlock();
											//2583	1	a,You cannot register more than one character in TvT event.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
											pUser->SendSystemMessage(2583); 
											return;
										}
									}
								}
							}
							
							for(UINT n=0;n<m_lpEvent->m_lpInfo->blockedClasses.size();n++)
							{
								if(m_lpEvent->m_lpInfo->blockedClasses[n] == pUser->pSD->nClass)
								{
									Unlock();
									//2642	1	Your class isn't allowed on that TvT Event!	0	79	9B	B0	FF			0	0	0	0	0		none
									pUser->pSocket->SendSystemMessage(2642);
									return;
								}
							}

							if(m_lpEvent->m_lpInfo->requiredItemId == 0 || pUser->inventory.HaveItemByClassID(m_lpEvent->m_lpInfo->requiredItemId, m_lpEvent->m_lpInfo->requiredItemCount))
							{	
								if(m_lpEvent->m_lpInfo->requiredItemId > 0)
								{
									pUser->DeleteItemInInventory(m_lpEvent->m_lpInfo->requiredItemId, m_lpEvent->m_lpInfo->requiredItemCount);
								}

								if(team == 1 || team == 2)
								{
									if(m_lpEvent->m_lpInfo->type == TvT::TvTGMReGroup)
									{
										//Check if has party
										CParty *pParty = pUser->GetParty();
										if(pParty)
										{
											//Check if it is leader
											User *pPartyLeader = pParty->GetMaster();
											if(pPartyLeader == pUser)
											{
												if(pParty->GetMembersAmount() == m_lpEvent->m_lpInfo->PartySize)
												{
													//register party
													UserVector vUsers;
													pParty->GetAllMembersEx(vUsers);
													UserVector::iterator Iter = vUsers.begin();
													for(;Iter!=vUsers.end();Iter++)
													{
														User *pMember = *Iter;
														if(pMember->ValidUser())
														{
															wcscpy(pMember->pED->OriginalwTitle, pMember->wTitle);
												//			pUser->pED->OriginalnameColorEx = pUser->pED->nameColorEx;
															pMember->pED->OriginaltitleColorEx = pMember->pED->titleColorEx;

															pMember->pED->m_CtfUserFlag = 0;
															pMember->pED->m_CtfUserFlagWeapon = 0;

															pMember->pED->tvtUser.status = TvT::UserRegistered;
															m_lpEvent->m_users.insert(pair<UINT, User*>(pMember->nDBID, pMember));
															pMember->pED->tvtUser.friendlyFire = 1;

															m_lpEvent->m_usersBackup.insert(pair<UINT, TvTUser>(pUser->nDBID, TvTUser(pMember->pED->tvtUser)));
															

															//2650	1	a,Your party has been registered into the event.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
															pUser->pSocket->SendSystemMessage(2650);
														}
													}
												}
												else
												{
													//2654	1	a,Your party members number must be $s1.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
													CSystemMessage msg(2654);
													msg.AddNumber(m_lpEvent->m_lpInfo->PartySize);
													pUser->SendSystemMessage(&msg);
												}
											}
											else
											{
												//2649	1	a,Only Party Leader can register on event.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
												pUser->pSocket->SendSystemMessage(2649);
											}
										}
										else
										{
											//2648	1	a,You don't have any party in order to register on event.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
											pUser->pSocket->SendSystemMessage(2648);
										}
									}
									else if(m_lpEvent->m_lpInfo->type == TvT::TvTKorean || m_lpEvent->m_lpInfo->type == TvT::TvTCaptureTheFlag || m_lpEvent->m_lpInfo->type == TvT::TvTDeathMatch || m_lpEvent->m_lpInfo->type == TvT::TvTLastManStanding || m_lpEvent->m_lpInfo->type == TvT::TvTCaptureTheFlag2 || m_lpEvent->m_lpInfo->type == TvT::TvTDestroyTheBase || m_lpEvent->m_lpInfo->type == TvT::TvTCastle || m_lpEvent->m_lpInfo->type == TvT::TvTFortress)
									{
										pUser->pED->tvtUser.status = TvT::UserRegistered;
										pUser->pED->tvtUser.team = TeamNone;


										wcscpy(pUser->pED->OriginalwTitle, pUser->wTitle);
							//			pUser->pED->OriginalnameColorEx = pUser->pED->nameColorEx;
										pUser->pED->OriginaltitleColorEx = pUser->pED->titleColorEx;

										pUser->pED->m_CtfUserFlag = 0;
										pUser->pED->m_CtfUserFlagWeapon = 0;

										m_lpEvent->m_users.insert(pair<UINT, User*>(pUser->nDBID, pUser));
										pUser->pED->tvtUser.friendlyFire = m_lpEvent->m_lpInfo->friendlyFire;

										m_lpEvent->m_usersBackup.insert(pair<UINT, TvTUser>(pUser->nDBID, TvTUser(pUser->pED->tvtUser)));

										//2654	1	a,You've been registered in Korean Event.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
										//pUser->pSocket->SendSystemMessage(2654);
										if( m_lpEvent->m_lpInfo->type == TvT::TvTKorean )
											pUser->SendSystemMessageGreen(L"You've been registered in Korean Event.");
										else if(m_lpEvent->m_lpInfo->type == TvT::TvTCaptureTheFlag)
											pUser->SendSystemMessageGreen(L"You've been registered in CTF Event.");
										else if(m_lpEvent->m_lpInfo->type == TvT::TvTDeathMatch)
											pUser->SendSystemMessageGreen(L"You've been registered in TvT Event.");
										else if(m_lpEvent->m_lpInfo->type == TvT::TvTLastManStanding)
										{
											pUser->pED->tvtUser.friendlyFire = true;
											pUser->SendSystemMessageGreen(L"You've been registered in Last Man Standing Event.");
										}
										else if(m_lpEvent->m_lpInfo->type == TvT::TvTCaptureTheFlag2)
											pUser->SendSystemMessageGreen(L"You've been registered in CTF Event.");
										else if(m_lpEvent->m_lpInfo->type == TvT::TvTDestroyTheBase)
											pUser->SendSystemMessageGreen(L"You've been registered in Destroy The Base Event.");
										else if(m_lpEvent->m_lpInfo->type == TvT::TvTCastle)
											pUser->SendSystemMessageGreen(L"You've been registered in TvT Castle Event.");
										else if(m_lpEvent->m_lpInfo->type == TvT::TvTFortress)
											pUser->SendSystemMessageGreen(L"You've been registered in TvT Fortress Event.");

									}
									/*else if(m_lpEvent->m_lpInfo->type == TvT::TvTLastTeamStanding ) //mby?
									{
										pUser->pED->tvtUser.status = TvT::UserRegistered;
										pUser->pED->tvtUser.team = team;
										m_lpEvent->m_users.insert(pair<UINT, User*>(pUser->nObjectID, pUser));
										pUser->pED->tvtUser.friendlyFire = m_lpEvent->m_lpInfo->friendlyFire;

										pUser->SendSystemMessageGreen(L"You've been registered in Last Team Standing Event.");
									}*/
									else
									{
										pUser->pED->tvtUser.status = TvT::UserRegistered;
										if(team == 1)
											pUser->pED->tvtUser.team = TvT::TeamBlue;
										else
											pUser->pED->tvtUser.team = TvT::TeamRed;

										wcscpy(pUser->pED->OriginalwTitle, pUser->wTitle);
							//			pUser->pED->OriginalnameColorEx = pUser->pED->nameColorEx;
										pUser->pED->OriginaltitleColorEx = pUser->pED->titleColorEx;

										pUser->pED->m_CtfUserFlag = 0;
										pUser->pED->m_CtfUserFlagWeapon = 0;

										m_lpEvent->m_users.insert(pair<UINT, User*>(pUser->nDBID, pUser));
										pUser->pED->tvtUser.friendlyFire = m_lpEvent->m_lpInfo->friendlyFire;

										m_lpEvent->m_usersBackup.insert(pair<UINT, TvTUser>(pUser->nDBID, TvTUser(pUser->pED->tvtUser)));

										//2584	1	a,You've been registered in TvT event.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
										pUser->pSocket->SendSystemMessage(2584);
									}
								}else
								{
									g_Log.Add(CLog::Error, "[%s] Invalid team[%d] - user[%S]", __FUNCTION__, team, pUser->pSD->wszName);
								}
							}else
							{
								if(m_lpEvent->m_lpInfo->requiredItemId > 0)
								{
									//2585	1	a,You don't have enough item(s).\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
									pUser->pSocket->SendSystemMessage(2585);
								}
							}
						}else
						{
							//2586	1	a,There are no empty slots in TvT event, please come back later..\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
							pUser->pSocket->SendSystemMessage(2586);
						}
					}else
					{
						//2587	1	a,Your level is too high to participe in TvT event.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
						pUser->pSocket->SendSystemMessage(2587);
					}
				}else
				{
					//2588	1	a,Your level is too low to participe in TvT event.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
					pUser->pSocket->SendSystemMessage(2588);
				}
			}else
			{
				//2577	1	a,You cannot participe in TvT event at the moment.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
				pUser->pSocket->SendSystemMessage(2577);
			}
		}else
		{
			//2577	1	a,You cannot participe in TvT event at the moment.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
			pUser->pSocket->SendSystemMessage(2577);
		}
		Unlock();
	}else
	{
		//2589	1	a,You already are participing in TvT event.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
		pUser->pSocket->SendSystemMessage(2589);
	}
}

void CTvT::OnDie(User *pUser, CCreature *pKiller)
{
	if(m_enabled)
	{
		if(pUser->ValidUser())
		{
			if(pUser->pED->tvtUser.status == TvT::UserFighting)
			{
				//TODO BROADCAST TEAM WHO DIED
				/*
				for(map<UINT, User*>::iterator Iter = m_lpEvent->m_users.begin(); Iter!=m_lpEvent->m_users.end();Iter++)
				{
					User *pUser = Iter->second;
					if(pUser->ValidUser() && pUser->pED->tvtUser.team == TvT::TeamRed) //TeamBlue
					{

					}
				}*/

				Lock();
				if(m_lpEvent->m_lpInfo->type == TvT::TvTLastTeamStanding)
				{
					pUser->pED->tvtUser.status = TvT::UserFinishing;
					if(m_lpEvent->ValidateWinner())
					{
						m_lpEvent->OnFinish();
					}
				}else if(m_lpEvent->m_lpInfo->type == TvT::TvTDeathMatch || m_lpEvent->m_lpInfo->type == TvT::TvTCastle || m_lpEvent->m_lpInfo->type == TvT::TvTFortress)
				{
					if(User *pUK = pKiller->GetUser())
					{
						if(pUK->pED->tvtUser.status == TvT::UserFighting)
						{
							if(pUser->pED->tvtUser.team == TvT::TeamBlue && pUK->pED->tvtUser.team == TvT::TeamRed)
							{
								m_lpEvent->m_killCountRed++;
								pUK->pED->tvtUser.killCount++;
							}else if(pUser->pED->tvtUser.team == TvT::TeamRed && pUK->pED->tvtUser.team == TvT::TeamBlue)
							{
								m_lpEvent->m_killCountBlue++;
								pUK->pED->tvtUser.killCount++;
							}

							g_Achivments.SetUser_DeathMatch(pUK);

						}
					}

					pUser->preserveAbnormals = true;

					if(m_lpEvent->m_lpInfo->nResetReuseSkills)
						pUser->ResetSkillReuse();

					pUser->pED->tvtUser.respawnTick = m_lpEvent->m_lpInfo->respawnTime;
					pUser->pSD->pExData->m_TimeTvTAfk=0;
				}
				else if(m_lpEvent->m_lpInfo->type == TvT::TvTCaptureTheFlag)
				{
					if(User *pUK = pKiller->GetUser())
					{
						if(pUK->pED->tvtUser.status == TvT::UserFighting)
						{
							if(pUser->pED->tvtUser.flag)
							{
								g_Achivments.SetUser_SavesCaptureTheFlag(pUK);

								pUser->pED->tvtUser.flag = false;
								pUser->SendSystemMessageRed(L"You Lost The Flag!");
								pUser->SetUserInfoChanged();
								pUser->SetCharInfoChanged();
							}
						}
					}
					if(m_lpEvent->m_lpInfo->nResetReuseSkills)
						pUser->ResetSkillReuse();

					pUser->pED->tvtUser.respawnTick = m_lpEvent->m_lpInfo->respawnTime;
					pUser->pSD->pExData->m_TimeTvTAfk=0;
				}
				else if(m_lpEvent->m_lpInfo->type == TvT::TvTCaptureTheFlag2)
				{
					pUser->preserveAbnormals = true;
					pUser->pED->tvtUser.respawnTick = m_lpEvent->m_lpInfo->respawnTime;
					pUser->pSD->pExData->m_TimeTvTAfk=0;
					pUser->pED->m_CtfUserFlag = 0;
					pUser->SetUserInfoChanged();
					pUser->SetCharInfoChanged();

					if(m_lpEvent->m_state == TvT::StateFight)
					{
						if(User *pUK = pKiller->GetUser())
						{
							if(pUK->pED->tvtUser.status == TvT::UserFighting)
							{
								if(pUser->pED->tvtUser.team == TvT::TeamBlue && pUK->pED->tvtUser.team == TvT::TeamRed)
								{
									m_lpEvent->m_killCountRed++;
									pUK->pED->tvtUser.killCount++;
								}else if(pUser->pED->tvtUser.team == TvT::TeamRed && pUK->pED->tvtUser.team == TvT::TeamBlue)
								{
									m_lpEvent->m_killCountBlue++;
									pUK->pED->tvtUser.killCount++;
								}
							}
						}

						if(pUser->nDBID == m_lpEvent->m_CtfUserFlag_red)
						{
							m_lpEvent->m_CtfUserFlag_red = 0;
							m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", L"El equipo Rojo ha perdido la bandera.");

							CItem *pWeapon = pUser->inventory.GetItemBySID(pUser->pED->m_CtfUserFlagWeapon);
							if(pWeapon->IsValidItem())
							{
								pUser->UseItem(pWeapon,true);
							}
							pUser->pED->m_CtfUserFlagWeapon = 0;
							pUser->pED->m_CtfUserFlag = 0;

							if(User *pUK = pKiller->GetUser())
								g_Achivments.SetUser_SavesCaptureTheFlag(pUK);

						}else if(pUser->nDBID == m_lpEvent->m_CtfUserFlag_blue)
						{
							m_lpEvent->m_CtfUserFlag_blue = 0;
							m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", L"El equipo Azul ha perdido la bandera.");

							CItem *pWeapon = pUser->inventory.GetItemBySID(pUser->pED->m_CtfUserFlagWeapon);
							if(pWeapon->IsValidItem())
							{
								pUser->UseItem(pWeapon,true);
							}
							pUser->pED->m_CtfUserFlagWeapon = 0;
							pUser->pED->m_CtfUserFlag = 0;


							if(User *pUK = pKiller->GetUser())
								g_Achivments.SetUser_SavesCaptureTheFlag(pUK);
						}

						if(m_lpEvent->m_lpInfo->nResetReuseSkills)
							pUser->ResetSkillReuse();

						pUser->pSD->pExData->m_TimeTvTAfk=0;
					}
				}else if(m_lpEvent->m_lpInfo->type == TvT::TvTDestroyTheBase)
				{
					if(User *pUK = pKiller->GetUser())
					{
						if(pUK->pED->tvtUser.status == TvT::UserFighting)
						{
							if(pUser->pED->tvtUser.team == TvT::TeamBlue && pUK->pED->tvtUser.team == TvT::TeamRed)
							{
								m_lpEvent->m_killCountRed++;
								pUK->pED->tvtUser.killCount++;
							}else if(pUser->pED->tvtUser.team == TvT::TeamRed && pUK->pED->tvtUser.team == TvT::TeamBlue)
							{
								m_lpEvent->m_killCountBlue++;
								pUK->pED->tvtUser.killCount++;
							}
						}
					}
					pUser->preserveAbnormals = true;
					pUser->pED->tvtUser.respawnTick = m_lpEvent->m_lpInfo->respawnTime;
					pUser->pSD->pExData->m_TimeTvTAfk=0;

					if(m_lpEvent->m_lpInfo->nResetReuseSkills)
						pUser->ResetSkillReuse();

				}

				if(g_EventStats.IsEnabled())
				{
					pUser->pED->event_kills++;
					if(User *pUK = pKiller->GetUser())
					{
						pUser->pED->event_deaths++;
					}
				}
				Unlock();
			}
		}
	}
}

void CTvT::OnExit(User *pUser)
{
	if(m_enabled)
	{
		if(pUser->ValidUser())
		{
			if(m_lpEvent->m_lpInfo->type == TvT::TvTFortress)
				FortressApplySkill(pUser);

			if(pUser->pED->tvtUser.status != TvT::UserNone)
			{
				Lock();
				if(m_lpEvent)
				{
					map<UINT, User*>::iterator Iter = m_lpEvent->m_users.find(pUser->nDBID);
					if(Iter!=m_lpEvent->m_users.end())
					{
						m_lpEvent->m_users.erase(Iter);
					}

					if(m_lpEvent->m_lpInfo->type == TvT::TvTLastTeamStanding)
					{
						if(m_lpEvent->ValidateWinner())
						{
							m_lpEvent->OnFinish();
						}
					}
				}

				Unlock();
				pUser->StopMove();
				
				if(pUser->pED->tvtUser.orgPos.x != 0 || pUser->pED->tvtUser.orgPos.y != 0)
					PlayerAction::OnTeleportToLocation(pUser, pUser->pED->tvtUser.orgPos.x, pUser->pED->tvtUser.orgPos.y, pUser->pED->tvtUser.orgPos.z, false);
				else
					PlayerAction::OnTeleportToLocation(pUser, 82991, 149437, -3464, false);
  

				pUser->pED->tvtUser.Clear();
				pUser->pSD->teamType = 0;

				wcscpy(pUser->wTitle, pUser->pED->OriginalwTitle);
				pUser->SetUserInfoChanged();
				pUser->SetCharInfoChanged();

				pUser->pED->m_CtfUserFlag = 0;
				pUser->pED->m_CtfUserFlagWeapon = 0;
				if(m_lpEvent->m_state == TvT::StateFight)
				{
					if(m_lpEvent->m_lpInfo->type == TvT::TvTCaptureTheFlag2)
					{
						if(pUser->nDBID == m_lpEvent->m_CtfUserFlag_red)
						{
							m_lpEvent->m_CtfUserFlag_red = 0;
							m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", L"El equipo Rojo ha perdido la bandera.");
						}
						if(pUser->nDBID == m_lpEvent->m_CtfUserFlag_blue)
						{
							m_lpEvent->m_CtfUserFlag_blue = 0;
							m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", L"El equipo Azul ha perdido la bandera.");
						}
					}
				}
			}
		}
	}
}

void CTvT::OnNpcSpawn(CNPC *pNpc)
{
	if(m_enabled)
	{
		if(pNpc)
		{
			Lock();
			if(m_lpEvent)
			{
				if(m_lpEvent->m_lpInfo->registerNpcClassId)
				{
					if(pNpc->pSD->nNpcClassID == m_lpEvent->m_lpInfo->registerNpcClassId)
					{
						if(m_lpEvent->m_managerServerId == 0)
						{
							m_lpEvent->m_managerServerId = pNpc->nObjectID;
						}
						if(m_lpEvent->m_managerServerId2 == 0)
						{
							m_lpEvent->m_managerServerId2 = pNpc->nObjectID;
						}
						if(m_lpEvent->m_managerServerId3 == 0)
						{
							m_lpEvent->m_managerServerId3 = pNpc->nObjectID;
						}
					}
				}
			}
			Unlock();
		}
	}
}


void CTvT::TimerExpired(User *pUser)
{
	guard;

	//--------------METER PERSONAJE SI SE LE CERRO POR CRITICO
		if(m_lpEvent)
		{
			if(m_lpEvent->m_state == StateRegistration || m_lpEvent->m_state == StatePreparation || m_lpEvent->m_state == StateCountDown || m_lpEvent->m_state == StateFight)
			{
				if (pUser->pED->tvtUser.status == TvT::UserNone && !pUser->pED->nTestTvTUserSiFueCritico)
				{
					bool test = 0;
					pUser->pED->nTestTvTUserSiFueCritico = true;

					if (m_lpEvent->m_lpInfo->MeterAlEventoSiHayCritico)
					{
						Lock();
						map<UINT, User*>::iterator Iter2 = m_lpEvent->m_users.find(pUser->nDBID);
						if(Iter2!=m_lpEvent->m_users.end())
						{
							map<UINT, TvTUser>::iterator Iter = m_lpEvent->m_usersBackup.find(pUser->nDBID);
							if(Iter!=m_lpEvent->m_usersBackup.end())
							{
								pUser->pED->tvtUser = TvTUser(Iter->second);
								pUser->pED->m_CtfUserFlag = 0;
								pUser->pED->m_CtfUserFlagWeapon = 0;
								pUser->pSD->teamType = pUser->pED->tvtUser.team;
								Iter2->second = pUser;
								test = 1;


								if(m_lpEvent->m_lpInfo->type == TvT::TvTFortress)
									FortressApplySkill(pUser);
							}
						}
						Unlock();
					}

					if (test == 0 && pUser->pSD->nBuilder == 0)
					{
						pUser->pED->m_CtfUserFlag = 0;
						pUser->pED->m_CtfUserFlagWeapon = 0;

						if(m_lpEvent->m_lpInfo->kickOutPos.x != 0 || m_lpEvent->m_lpInfo->kickOutPos.y != 0)
							g_UserDB.KickOutFromRangeUser(pUser, m_lpEvent->m_lpInfo->kickOutPos, m_lpEvent->m_lpInfo->fightZoneX[0], m_lpEvent->m_lpInfo->fightZoneX[1], m_lpEvent->m_lpInfo->fightZoneY[0], m_lpEvent->m_lpInfo->fightZoneY[1] );

						OnExit(pUser);
						unguard;
						return;
					}
				}
			}
		}
	//--------------FIN METER PERSONAJE SI SE LE CERRO POR CRITICO

	if(m_enabled && pUser->pED->tvtUser.status != TvT::UserNone)
	{

		if((pUser->pED->tvtUser.status == TvT::UserPreparing || pUser->pED->tvtUser.status == TvT::UserFinishing) && pUser->pSD->nKarma == 0)
		{
			if(m_lpEvent->m_lpInfo->fightZoneX[0] <= (INT32)pUser->pSD->Pos.x && m_lpEvent->m_lpInfo->fightZoneX[1] >= (INT32)pUser->pSD->Pos.x
				&& m_lpEvent->m_lpInfo->fightZoneY[0] <= (INT32)pUser->pSD->Pos.y && m_lpEvent->m_lpInfo->fightZoneY[1] >= (INT32)pUser->pSD->Pos.y)
			{
				pUser->inPeaceZone = true;
			}
		}
		if(pUser->pED->tvtUser.status == TvT::UserFighting)
		{
				pUser->pSD->pExData->m_TimeTvTAfk++;
				//g_Log.Add(CLog::Blue, "pUser->pSD->pExData->m_TimeTvTAfk=[%d][%d]", pUser->pSD->pExData->m_TimeTvTAfk,m_lpEvent->m_lpInfo->TimeAfk);

				if (pUser->pSD->pExData->m_TimeTvTAfk > m_lpEvent->m_lpInfo->TimeAfk-10)
					pUser->pSocket->SendSystemMessage(L"Debes estar activo o seras expulsado del evento.");

				if(pUser->pSD->pExData->m_TimeTvTAfk > m_lpEvent->m_lpInfo->TimeAfk)
				{
					pUser->pSocket->SendSystemMessage(L"Fuiste descalificado del evento por inactividad.");
					//g_Log.Add(CLog::Blue, "Fuiste descalificado del evento por inactividad.[%d]", pUser->pSD->pExData->m_TimeTvTAfk);


					pUser->pED->m_CtfUserFlag = 0;
					pUser->pED->m_CtfUserFlagWeapon = 0;
					if(pUser->nDBID == m_lpEvent->m_CtfUserFlag_blue)
					{
						m_lpEvent->m_CtfUserFlag_blue = 0;
						m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", L"El equipo Azul ha perdido la bandera.");
					}
					if(pUser->nDBID == m_lpEvent->m_CtfUserFlag_red)
					{
						m_lpEvent->m_CtfUserFlag_red = 0;
						m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", L"El equipo Rojo ha perdido la bandera.");
					}

					Lock();
					if (m_lpEvent->m_lpInfo->MeterAlEventoSiHayCritico)
					{
						map<UINT, TvTUser>::iterator Iter2 = m_lpEvent->m_usersBackup.find(pUser->nDBID);
						if(Iter2!=m_lpEvent->m_usersBackup.end())
						{
							m_lpEvent->m_usersBackup.erase(Iter2);
						}
					}
					Unlock();

					OnExit(pUser);
					unguard;
					return;
				}


			//check loc
			if(m_lpEvent->m_lpInfo->fightZoneX[0] > (INT32)pUser->pSD->Pos.x || m_lpEvent->m_lpInfo->fightZoneX[1] < (INT32)pUser->pSD->Pos.x
				|| m_lpEvent->m_lpInfo->fightZoneY[0] > (INT32)pUser->pSD->Pos.y || m_lpEvent->m_lpInfo->fightZoneY[1] < (INT32)pUser->pSD->Pos.y)
			{
				if(pUser->pED->tvtUser.resetTimer == 0)
				{
					//2590	1	a,You're outside combat zone, you'll be expelled from TvT event in $s1 seconds.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
					CSystemMessage msg(2590);
					msg.AddNumber(15);
					pUser->SendSystemMessage(&msg);
					pUser->pED->tvtUser.resetTimer = 15;
				}

				pUser->pED->tvtUser.resetTimer--;
				if(pUser->pED->tvtUser.resetTimer == 0)
				{
					//2591	1	a,You're outside combat zone, you've been expelled from TvT event.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
					pUser->pSocket->SendSystemMessage(2591);
					
					pUser->pED->m_CtfUserFlag = 0;
					pUser->pED->m_CtfUserFlagWeapon = 0;
					if(pUser->nDBID == m_lpEvent->m_CtfUserFlag_blue)
					{
						m_lpEvent->m_CtfUserFlag_blue = 0;
						m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", L"El equipo Azul ha perdido la bandera.");
					}
					if(pUser->nDBID == m_lpEvent->m_CtfUserFlag_red)
					{
						m_lpEvent->m_CtfUserFlag_red = 0;
						m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", L"El equipo Rojo ha perdido la bandera.");
					}
					
					//OnExit(pUser);
					if(pUser->pED->tvtUser.respawnPos.x != 0 || pUser->pED->tvtUser.respawnPos.y != 0)
					{
						pUser->StopMove();
						PlayerAction::OnTeleportToLocation(pUser, pUser->pED->tvtUser.respawnPos.x, pUser->pED->tvtUser.respawnPos.y, pUser->pED->tvtUser.respawnPos.z, false);
						pUser->pSD->pExData->m_TimeTvTAfk=0;
					}

					unguard;
					return;
				}
			}else if(pUser->pED->tvtUser.resetTimer != 0)
			{
				pUser->pED->tvtUser.resetTimer = 0;
			}

			if(pUser->pED->tvtUser.respawnTick > 0)
			{
				if(!pUser->pSD->nAlive)
				{
					pUser->pED->tvtUser.respawnTick--;
					if(pUser->pED->tvtUser.respawnTick != 0)
					{
						CSystemMessage msg(2452);	//You'll be respawned in $s1 second(s)!
						msg.AddNumber(pUser->pED->tvtUser.respawnTick);
						pUser->pSocket->SendSystemMessage(&msg);
						pUser->pSD->pExData->m_TimeTvTAfk=0;
					}else
					{
						pUser->pSD->pExData->m_TimeTvTAfk=0;

						pUser->ResurrectedBy(pUser, 100);
						
						pUser->pSD->fHP = pUser->pSD->MaxHP;
						pUser->pSD->fCP = pUser->pSD->MaxCP;
						pUser->pSD->fMP = pUser->pSD->MaxMP;

						TvTInfo *pInfo = m_lpEvent->m_lpInfo;
						if(pInfo)
						{
							if(CCategoryDataDB::IsInCategory(pUser->pSD->nClass, CCategoryDataDB::MAGE_GROUP))
							{
								for(UINT n=0;n<pInfo->defaultMageBuffs.size();n++)
								{
									if(CSkillInfo *pSI = g_SkillDB.GetSkillInfo(pInfo->defaultMageBuffs[n].skillId, pInfo->defaultMageBuffs[n].level))
									{
										pSI->ActivateSkill(pUser, pUser);
									}
								}
							}else
							{
								for(UINT n=0;n<pInfo->defaultFighterBuffs.size();n++)
								{
									if(CSkillInfo *pSI = g_SkillDB.GetSkillInfo(pInfo->defaultFighterBuffs[n].skillId, pInfo->defaultFighterBuffs[n].level))
									{
										pSI->ActivateSkill(pUser, pUser);
									}
								}
							}
						}


						if(pUser->pED->tvtUser.respawnPos.x != 0 || pUser->pED->tvtUser.respawnPos.y != 0)
						{
							pUser->StopMove();
							PlayerAction::OnTeleportToLocation(pUser, pUser->pED->tvtUser.respawnPos.x, pUser->pED->tvtUser.respawnPos.y, pUser->pED->tvtUser.respawnPos.z, false);
							pUser->pSD->pExData->m_TimeTvTAfk=0;


							if(m_lpEvent->m_lpInfo->type == TvT::TvTCaptureTheFlag2 && m_lpEvent->m_state == TvT::StateFight)
							{
								if(pUser->nDBID == m_lpEvent->m_CtfUserFlag_red)
								{
									m_lpEvent->m_CtfUserFlag_red = 0;
									CItem *pWeapon = pUser->inventory.GetItemBySID(pUser->pED->m_CtfUserFlagWeapon);
									if(pWeapon->IsValidItem())
									{
										pUser->UseItem(pWeapon,true);
									}
									pUser->pED->m_CtfUserFlagWeapon = 0;
									pUser->pED->m_CtfUserFlag = 0;
								}else if(pUser->nDBID == m_lpEvent->m_CtfUserFlag_blue)
								{
									m_lpEvent->m_CtfUserFlag_blue = 0;
									CItem *pWeapon = pUser->inventory.GetItemBySID(pUser->pED->m_CtfUserFlagWeapon);
									if(pWeapon->IsValidItem())
									{
										pUser->UseItem(pWeapon,true);
									}
									pUser->pED->m_CtfUserFlagWeapon = 0;
									pUser->pED->m_CtfUserFlag = 0;
								}
							}
						}
					}

				}else if(!pUser->pSD->nAlive && pUser->pSD->pExData->m_TimeTvTAfk > 10 && pUser->pED->tvtUser.respawnTick == 0)
				{
					pUser->pSD->pExData->m_TimeTvTAfk=0;

					pUser->ResurrectedBy(pUser, 100);
						
					pUser->pSD->fHP = pUser->pSD->MaxHP;
					pUser->pSD->fCP = pUser->pSD->MaxCP;
					pUser->pSD->fMP = pUser->pSD->MaxMP;

					TvTInfo *pInfo = m_lpEvent->m_lpInfo;
					if(pInfo)
					{
						if(CCategoryDataDB::IsInCategory(pUser->pSD->nClass, CCategoryDataDB::MAGE_GROUP))
						{
							for(UINT n=0;n<pInfo->defaultMageBuffs.size();n++)
							{
								if(CSkillInfo *pSI = g_SkillDB.GetSkillInfo(pInfo->defaultMageBuffs[n].skillId, pInfo->defaultMageBuffs[n].level))
								{
									pSI->ActivateSkill(pUser, pUser);
								}
							}
						}else
						{
							for(UINT n=0;n<pInfo->defaultFighterBuffs.size();n++)
							{
								if(CSkillInfo *pSI = g_SkillDB.GetSkillInfo(pInfo->defaultFighterBuffs[n].skillId, pInfo->defaultFighterBuffs[n].level))
								{
									pSI->ActivateSkill(pUser, pUser);
								}
							}
						}
					}

					if(pUser->pED->tvtUser.respawnPos.x != 0 || pUser->pED->tvtUser.respawnPos.y != 0)
					{
						pUser->StopMove();
						PlayerAction::OnTeleportToLocation(pUser, pUser->pED->tvtUser.respawnPos.x, pUser->pED->tvtUser.respawnPos.y, pUser->pED->tvtUser.respawnPos.z, false);
						pUser->pSD->pExData->m_TimeTvTAfk=0;

						if(m_lpEvent->m_lpInfo->type == TvT::TvTCaptureTheFlag2 && m_lpEvent->m_state == TvT::StateFight)
						{
							if(pUser->nDBID == m_lpEvent->m_CtfUserFlag_red)
							{
								m_lpEvent->m_CtfUserFlag_red = 0;
								CItem *pWeapon = pUser->inventory.GetItemBySID(pUser->pED->m_CtfUserFlagWeapon);
								if(pWeapon->IsValidItem())
								{
									pUser->UseItem(pWeapon,true);
								}
								pUser->pED->m_CtfUserFlagWeapon = 0;
								pUser->pED->m_CtfUserFlag = 0;
							}else if(pUser->nDBID == m_lpEvent->m_CtfUserFlag_blue)
							{
								m_lpEvent->m_CtfUserFlag_blue = 0;
								CItem *pWeapon = pUser->inventory.GetItemBySID(pUser->pED->m_CtfUserFlagWeapon);
								if(pWeapon->IsValidItem())
								{
									pUser->UseItem(pWeapon,true);
								}
								pUser->pED->m_CtfUserFlagWeapon = 0;
								pUser->pED->m_CtfUserFlag = 0;
							}
						}

					}

				}else
				{
					pUser->pED->tvtUser.respawnTick = 0;
				}
			}
		}
	}
	unguard;
}

bool CTvT::CanUse(CItem *pItem)
{
	
	if(m_enabled && m_lpEvent)
	{
		if(m_lpEvent->m_state == TvT::StateCountDown || m_lpEvent->m_state == TvT::StateFight)
		{
			for(UINT n=0;n< m_lpEvent->m_lpInfo->blockedItem.size();n++)
			{
				if(m_lpEvent->m_lpInfo->blockedItem[n] == pItem->pSID->nItemID)
					return false;
			}

			if(pItem->pII->nCrystalType < 10)
			{
				if(m_lpEvent->m_lpInfo->blockedCrystalType[pItem->pII->nCrystalType])
					return false;
			}

			if(m_lpEvent->m_lpInfo->blockAugmentation && pItem->nAugmentationID)
				return false;

			if(pItem->pSID->nItemType == 0 && m_lpEvent->m_lpInfo->maxWeaponEnchant > 0)
			{
				if(pItem->pII->weaponType == WeaponDual)
				{
					if( pItem->pSID->nEnchantLevel > (m_lpEvent->m_lpInfo->maxWeaponEnchant + 1) )
					{
						return false;
					}
				}else
				{
					if(pItem->pSID->nEnchantLevel > m_lpEvent->m_lpInfo->maxWeaponEnchant)
					{
						return false;
					}
				}
			}else if(m_lpEvent->m_lpInfo->maxArmorEnchant > 0)
			{
				if(pItem->pSID->nSlotType == SlotOnePiece)
				{
					if( pItem->pSID->nEnchantLevel > (m_lpEvent->m_lpInfo->maxWeaponEnchant + 1) )
					{
						return false;
					}
				}else
				{
					if( pItem->pSID->nEnchantLevel > m_lpEvent->m_lpInfo->maxWeaponEnchant )
					{
						return false;
					}
				}
			}
		}
	}

	return true;
}

void CTvT::ValidateItems(User *pUser)
{
	
	if(pUser->ValidUser())
	{
		for(int n=0;n<18;n++)
		{
			INT32 index = pUser->pSD->nEquipment[n];
			if(index > 0)
			{
				CItem *pItem = pUser->inventory.GetItemByIndex(index);
				if(pItem)
				{
					if(!CanUse(pItem))
					{
						pUser->UnEquipItem(n);
						continue;
					}
				}
			}
		}
	}
}

bool CTvT::IsSkillBlocked(INT32 skillId)
{
	
	if(m_enabled && m_lpEvent)
	{
		if(m_lpEvent->m_state == TvT::StateCountDown || m_lpEvent->m_state == TvT::StateFight)
		{
			for(UINT n=0;n<m_lpEvent->m_lpInfo->blockedSkill.size();n++)
			{
				if(m_lpEvent->m_lpInfo->blockedSkill[n] == skillId)
					return true;
			}
		}
	}
	return false;
}

void CTvT::ApplyProtectionSkill(User *pUser)
{
	if(pUser->ValidUser())
	{
		pUser->AcquireSkill(g_TvT.GetSkillId(), 1);
		pUser->ValidateParameters();
	}
}

void CTvT::RemoveProtectionSkill(User *pUser)
{
	if(pUser->ValidUser())
	{
		pUser->DeleteSkill(g_TvT.GetSkillId());
		pUser->ValidateParameters();
	}
}

void CTvT::GiveBuffsToPlayer(User *pUser)
{
	guard;
	
	if(pUser->ValidUser() && pUser->pSD->nAlive)
	{
		if(CCategoryDataDB::IsInCategory(pUser->pSD->nClass, CCategoryDataDB::MAGE_GROUP))
		{
			for(UINT n=0;n<m_lpEvent->m_lpInfo->defaultMageBuffs.size();n++)
			{
				if(CSkillInfo *pSI = g_SkillDB.GetSkillInfo(m_lpEvent->m_lpInfo->defaultMageBuffs[n].skillId, m_lpEvent->m_lpInfo->defaultMageBuffs[n].level))
				{
					pSI->ActivateSkill(pUser, pUser);
				}
			}
		}else
		{
			for(UINT n=0;n<m_lpEvent->m_lpInfo->defaultFighterBuffs.size();n++)
			{
				if(CSkillInfo *pSI = g_SkillDB.GetSkillInfo(m_lpEvent->m_lpInfo->defaultFighterBuffs[n].skillId, m_lpEvent->m_lpInfo->defaultFighterBuffs[n].level))
				{
					pSI->ActivateSkill(pUser, pUser);
				}
			}
		}
	}

	unguard;
}

void CTvT::CheckPlayerLogin(User *pUser)
{
	guard;

	if(m_lpEvent)
	{
		double x1 = static_cast<double>(m_lpEvent->m_lpInfo->fightZoneX[0]);
		double x2 = static_cast<double>(m_lpEvent->m_lpInfo->fightZoneX[1]);
		double y1 = static_cast<double>(m_lpEvent->m_lpInfo->fightZoneY[0]);
		double y2 = static_cast<double>(m_lpEvent->m_lpInfo->fightZoneY[1]);

		if(pUser->pSD->Pos.x >= x1 && pUser->pSD->Pos.x <= x2)
		{
			if(pUser->pSD->Pos.y >= y1 && pUser->pSD->Pos.y <= y2)
			{
				pUser->SendSystemMessage(L"You have been expelled from here because a tvt event is live!");
				PlayerAction::OnTeleportToLocation(pUser, m_lpEvent->m_lpInfo->kickOutPos.x, m_lpEvent->m_lpInfo->kickOutPos.y, m_lpEvent->m_lpInfo->kickOutPos.z, false);
			}
		}
	}

	unguard;
}


bool CTvT::PickPlayersForMatchKorean()
{
	guard;

	Lock();
	if(m_lpEvent)
	{
		if (m_lpEvent->m_winnerTeam > 0 )
		{
			Unlock();
			return false;
		}

		//if it is full then do the check
		if(!m_lpEvent->m_Kusers.empty())
		{
			int nPlayer_per_team = m_lpEvent->m_lpInfo->participateplayers / 2;

			User *pBlueUser = 0;
			User *pRedUser = 0;
			for(map<UINT, User*>::iterator it = m_lpEvent->m_Kusers.begin();it!=m_lpEvent->m_Kusers.end();it++)
			{
				if(User *pUser = it->second->SafeCastUser())
				{
					if(pUser->ValidUser())
					{
						if(pUser->pED->tvtUser.team == TvT::TeamBlue)
							pBlueUser = pUser;
						else if(pUser->pED->tvtUser.team == TvT::TeamRed)
							pRedUser = pUser;
					}
				}
			}

			//Check For One Side
			if( pBlueUser->ValidUser() && pBlueUser->pSD->nAlive )
			{
				if(!pBlueUser->pED->tvtUser.korean_start)
				{
					pBlueUser->pED->tvtUser.korean_start = 1;
					g_TvT.RemoveProtectionSkill(pBlueUser);

					if(!pBlueUser->pED->tvtUser.korean_start_hp)
					{
						pBlueUser->pED->tvtUser.korean_start_hp = 1;

						//Dispel All Buffs
						pBlueUser->DispelAllByGM();

						//Give Buffs To Player
						g_TvT.GiveBuffsToPlayer(pBlueUser);

						//Heal up the user
						pBlueUser->pSD->fCP = pBlueUser->pSD->MaxCP;
						pBlueUser->pSD->fHP = pBlueUser->pSD->MaxHP;
						pBlueUser->pSD->fMP = pBlueUser->pSD->MaxMP;
						pBlueUser->SendHpInfo();
						pBlueUser->SendMpInfo();
					}

					//Change Target
					if(pRedUser->ValidUser())
					{
						pBlueUser->ChangeTarget(pRedUser, true);

						//Send a message the enemy
						//2655	1	You Fight with $s1!	4	79	9B	B0	FF			0	0	0	0	0		popup
						CSystemMessage msg(2655);
						msg.AddText(pRedUser->pSD->wszName);
						pBlueUser->SendSystemMessage(&msg);

						//Broadcast message who is fighting with who
						wstring announce = _T("Player [player1] fight with Player [player2]!");
						announce = Utils::ReplaceString(announce, _T("[player1]"), pBlueUser->pSD->wszName);
						announce = Utils::ReplaceString(announce, _T("[player2]"), pRedUser->pSD->wszName);
						m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", announce.c_str());
					}
					Unlock();
					return false;
				}
			}
			else
			{
				wstring announce = _T("Congrats! You won this round!");
				//m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", announce.c_str());
				pRedUser->pSocket->Send("cddSS", 0x4A, 0, 18, L"", announce.c_str());

				//Restore Korean Status
				pRedUser->pED->tvtUser.korean_start = 0;
				//Teleport Player back on respawn pos
				PlayerAction::OnTeleportToLocation(pRedUser, pRedUser->pED->tvtUser.respawnPos.x, pRedUser->pED->tvtUser.respawnPos.y, pRedUser->pED->tvtUser.respawnPos.z, false);
				//Reset Skill Reuse
				//pRedUser->ResetSkillReuse();

				m_lpEvent->m_KoreanBlue++;
				m_lpEvent->m_Kusers.clear();
				if( nPlayer_per_team < m_lpEvent->m_KoreanBlue )
				{
					m_lpEvent->m_winnerTeam = TvT::TeamRed;
					Unlock();
					return true;
				}
				Unlock();
				return false;
			}
			
			//Check For Other Side
			if( pRedUser->ValidUser() && pRedUser->pSD->nAlive )
			{
				if(!pRedUser->pED->tvtUser.korean_start)
				{
					pRedUser->pED->tvtUser.korean_start = 1;
					g_TvT.RemoveProtectionSkill(pRedUser);

					if(!pRedUser->pED->tvtUser.korean_start_hp)
					{
						pRedUser->pED->tvtUser.korean_start_hp = 1;

						//Dispel All Buffs
						pRedUser->DispelAllByGM();

						//Give Buffs To Player
						g_TvT.GiveBuffsToPlayer(pRedUser);

						//Heal up the user
						pRedUser->pSD->fCP = pRedUser->pSD->MaxCP;
						pRedUser->pSD->fHP = pRedUser->pSD->MaxHP;
						pRedUser->pSD->fMP = pRedUser->pSD->MaxMP;
						pRedUser->SendHpInfo();
						pRedUser->SendMpInfo();
					}

					if(pBlueUser->ValidUser())
					{
						//Change Target
						pRedUser->ChangeTarget(pBlueUser, true);

						//Send a message the enemy
						//2655	1	You Fight with $s1!	4	79	9B	B0	FF			0	0	0	0	0		popup
						CSystemMessage msg(2655);
						msg.AddText(pBlueUser->pSD->wszName);
						pRedUser->SendSystemMessage(&msg);

						//Broadcast message who is fighting with who
						wstring announce = _T("Player [player1] fight with Player [player2]!");
						announce = Utils::ReplaceString(announce, _T("[player1]"), pBlueUser->pSD->wszName);
						announce = Utils::ReplaceString(announce, _T("[player2]"), pRedUser->pSD->wszName);
						m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", announce.c_str());
					}
					Unlock();
					return false;
				}
			}
			else
			{
				wstring announce = _T("Congrats! You won this round!");
				//m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", announce.c_str());
				pBlueUser->pSocket->Send("cddSS", 0x4A, 0, 18, L"", announce.c_str());

				//Restore Korean Status
				pBlueUser->pED->tvtUser.korean_start = 0;
				//Teleport Player back on respawn pos
				PlayerAction::OnTeleportToLocation(pBlueUser, pBlueUser->pED->tvtUser.respawnPos.x, pBlueUser->pED->tvtUser.respawnPos.y, pBlueUser->pED->tvtUser.respawnPos.z, false);
				//Reset Skill Reuse
				//pBlueUser->ResetSkillReuse();

				m_lpEvent->m_KoreanRed++;
				m_lpEvent->m_Kusers.clear();
				if( nPlayer_per_team < m_lpEvent->m_KoreanRed )
				{
					m_lpEvent->m_winnerTeam = TvT::TeamBlue;
					Unlock();
					return true;
				}
				Unlock();
				return false;
			}
		}
		else //register new
		{
			for(map<UINT, User*>::iterator it = m_lpEvent->m_users.begin();it!=m_lpEvent->m_users.end();it++)
			{
				if(User *pUser = it->second->SafeCastUser())
				{
					if(pUser->ValidUser())
					{
						if( pUser->pED->tvtUser.team == TvT::TeamBlue && pUser->pED->tvtUser.korean_par == m_lpEvent->m_KoreanBlue )
						{
							//register on kusers
							m_lpEvent->m_Kusers.insert(pair<UINT, User*>(pUser->nDBID, pUser));
						}
						else if( pUser->pED->tvtUser.team == TvT::TeamRed && pUser->pED->tvtUser.korean_par == m_lpEvent->m_KoreanRed )
						{
							//register on kusers
							m_lpEvent->m_Kusers.insert(pair<UINT, User*>(pUser->nDBID, pUser));
						}
						else
						{
							//Nothing...
						}
					}
				}
			}
			Unlock();
			return false;
		}
	}
	Unlock();

	unguard;

	return false;
}

void CTvT::NPCAction(User *pUser)
{
	guard;

	unguard;
}

void CTvT::NPCActionBlueFlag(User *pUser)
{
	guard;
	if(pUser->ValidUser())
	{
		if(m_lpEvent)
		{
			if( m_lpEvent->m_state == TvT::StateFight && m_lpEvent->m_lpInfo->type == TvT::TvTCaptureTheFlag )
			{
				if(pUser->pED->tvtUser.status = TvT::UserFighting)
				{
					if(pUser->pED->tvtUser.team == TvT::TeamRed)
					{
						bool m_FlagTaken = false;
						for(map<UINT, User*>::iterator Iter = m_lpEvent->m_users.begin(); Iter!=m_lpEvent->m_users.end();Iter++)
						{
							User *pUserAsker = Iter->second;
							if(pUserAsker->ValidUser() && pUserAsker->pED->tvtUser.team == TvT::TeamRed)
							{
								if(pUserAsker->pED->tvtUser.flag)
									m_FlagTaken = true;
							}
						}

						if(!pUser->pED->tvtUser.flag && !m_FlagTaken)
						{
							pUser->pED->tvtUser.flag = true;
							pUser->SendSystemMessageGreen(L"You TOOK The Flag! Hurry, Go Back to Base!");
							ShowHtml(pUser,L"tvt_flag_on.htm");
							pUser->SetUserInfoChanged();
							pUser->SetCharInfoChanged();
							pUser->SocialAction(SocialActionHero);
						}
						else if(pUser->pED->tvtUser.flag)
							ShowHtml(pUser,L"tvt_flag_on.htm");
						else
							ShowHtml(pUser,L"tvt_flag_taken.htm");
					}
					if(pUser->pED->tvtUser.team == TvT::TeamBlue)
					{
						if(pUser->pED->tvtUser.flag)
						{
							pUser->pED->tvtUser.flag = false;
							ShowHtml(pUser,L"tvt_flag_off.htm");
							pUser->SetUserInfoChanged();
							pUser->SetCharInfoChanged();

							m_lpEvent->m_killCountBlue++;
							g_Achivments.SetUser_CaptureTheFlag(pUser);

							//BroadCast it
							wstring announce = L"Score: Blue Team: [scoreblue] / Red Team: [scorered]";
							announce = Utils::ReplaceString(announce, _T("[scoreblue]"), m_lpEvent->m_killCountBlue);
							announce = Utils::ReplaceString(announce, _T("[scorered]"), m_lpEvent->m_killCountRed);
							m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", announce.c_str());
						}
						else
							ShowHtml(pUser,L"tvt_flag_fetch.htm");
					}
				}
			}
		}
	}
	unguard;
}

void CTvT::NPCActionRedFlag(User *pUser)
{
	guard;
	if(pUser->ValidUser())
	{
		if(m_lpEvent)
		{
			if( m_lpEvent->m_state == TvT::StateFight && m_lpEvent->m_lpInfo->type == TvT::TvTCaptureTheFlag )
			{
				if(pUser->pED->tvtUser.status = TvT::UserFighting)
				{
					if(pUser->pED->tvtUser.team == TvT::TeamBlue)
					{
						bool m_FlagTaken = false;
						for(map<UINT, User*>::iterator Iter = m_lpEvent->m_users.begin(); Iter!=m_lpEvent->m_users.end();Iter++)
						{
							User *pUserAsker = Iter->second;
							if(pUserAsker->ValidUser() && pUserAsker->pED->tvtUser.team == TvT::TeamBlue)
							{
								if(pUserAsker->pED->tvtUser.flag)
									m_FlagTaken = true;
							}
						}

						if(!pUser->pED->tvtUser.flag && !m_FlagTaken)
						{
							pUser->pED->tvtUser.flag = true;
							pUser->SendSystemMessageGreen(L"You TOOK The Flag! Hurry, Go Back to Base!");
							ShowHtml(pUser,L"tvt_flag_on.htm");
							pUser->SetUserInfoChanged();
							pUser->SetCharInfoChanged();
							pUser->SocialAction(SocialActionHero);
						}
						else if(pUser->pED->tvtUser.flag)
							ShowHtml(pUser,L"tvt_flag_on.htm");
						else
							ShowHtml(pUser,L"tvt_flag_taken.htm");
					}
					if(pUser->pED->tvtUser.team == TvT::TeamRed)
					{
						if(pUser->pED->tvtUser.flag)
						{
							pUser->pED->tvtUser.flag = false;
							ShowHtml(pUser,L"tvt_flag_off.htm");
							pUser->SetUserInfoChanged();
							pUser->SetCharInfoChanged();

							m_lpEvent->m_killCountRed++;
							g_Achivments.SetUser_CaptureTheFlag(pUser);

							//BroadCast it
							wstring announce = L"Score: Blue Team: [scoreblue] / Red Team: [scorered]";
							announce = Utils::ReplaceString(announce, _T("[scoreblue]"), m_lpEvent->m_killCountBlue);
							announce = Utils::ReplaceString(announce, _T("[scorered]"), m_lpEvent->m_killCountRed);
							m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", announce.c_str());
						}
						else
							ShowHtml(pUser,L"tvt_flag_fetch.htm");
					}
					
				}
			}
		}
	}
	unguard;
}

void CTvT::ShowHtml(User *pUser, const WCHAR* filename)
{
	guard;
	if(pUser->ValidUser())
	{
		const WCHAR* wHTML = g_HtmlCache.Get(filename);
		if(wHTML)
		{
			pUser->ShowHTML(filename, wHTML, 0);
		}
	}
	unguard;
}




void CTvT::IniciarEventoManual(User* pUser, int Id)
{
	if(m_lpEvent)
	{
		pUser->SendSystemMessage(L"Ya hay otro evento en curso!");
	}
	else
	{
		int count = 0;
		for(list<TvT::TvTInfo*>::iterator Iter = m_tvtInfo.begin();Iter!=m_tvtInfo.end();Iter++)
		{
			TvT::TvTInfo *pInfo = (*Iter);
			if(pInfo)
			{
				if(pInfo->enabled && count == Id)
				{
					pUser->SendSystemMessage(L"Evento iniciado!");
					m_lpEvent = new CMatch(pInfo);
					break;
				}
			}
			count++;
		}
	}
}

void CTvT::FinalizarEventoManual(bool ValidateWinner)
{
	if(m_lpEvent)
	{

		m_lpEvent->ValidateWinner(ValidateWinner);
		m_lpEvent->OnFinish();
	}
}

//---------------------------


void CTvT::NpcDestroyTheBaseSetHP(CNPC* pNpc)
{
	if(m_enabled && m_lpEvent)
	{
		if(m_lpEvent->m_state != TvT::StateNone)
		{
			if(m_lpEvent->m_lpInfo->type == TvT::TvTDestroyTheBase)
			{
				if(pNpc->nObjectID == m_lpEvent->m_managerServerId14)
				{
					pNpc->pSD->MaxHP = static_cast<double>(m_lpEvent->m_lpInfo->DestroyBaseNpcHP);
					pNpc->pSD->fHP = static_cast<double>(m_lpEvent->m_lpInfo->DestroyBaseNpcHP);
				}
				else if(pNpc->nObjectID == m_lpEvent->m_managerServerId15)
				{
					pNpc->pSD->MaxHP = static_cast<double>(m_lpEvent->m_lpInfo->DestroyBaseNpcHP);
					pNpc->pSD->fHP = static_cast<double>(m_lpEvent->m_lpInfo->DestroyBaseNpcHP);
				}
			}
		}
	}
}

void CTvT::IsNpcDestroyTheBaseDIE(UINT nObjId)
{
	if(m_enabled && m_lpEvent)
	{
		if(m_lpEvent->m_state == TvT::StateFight)
		{
			if(m_lpEvent->m_lpInfo->type == TvT::TvTDestroyTheBase)
			{
//				g_Log.Add(CLog::Error, "m_managerServerId14=[%d] m_managerServerId15=[%d], nObjId=[%d]",m_lpEvent->m_managerServerId14, m_lpEvent->m_managerServerId15, nObjId);

				if (m_lpEvent->m_managerServerId14 == nObjId)	//red
				{
					m_lpEvent->m_BaseBlueDestroyed = 1;

					m_lpEvent->ValidateWinner(true);
					m_lpEvent->OnFinish();
				}
				else if (m_lpEvent->m_managerServerId15 == nObjId)	//blue
				{
					m_lpEvent->m_BaseRedDestroyed = 1;

					m_lpEvent->ValidateWinner(true);
					m_lpEvent->OnFinish();
				}
			}
		}
	}
}

bool CTvT::IsNpcDestroyTheBaseTeam(User* pUser, UINT nObjId)
{
	if(m_enabled && m_lpEvent)
	{
		if(m_lpEvent->m_state != TvT::StateNone)
		{
			if(m_lpEvent->m_lpInfo->type == TvT::TvTDestroyTheBase)
			{
				if (m_lpEvent->m_managerServerId14 == nObjId && pUser->pED->tvtUser.team == TvT::TeamRed)	//red
				{
					return true;
				}
				else if (m_lpEvent->m_managerServerId15 == nObjId && pUser->pED->tvtUser.team == TvT::TeamBlue)	//blue
				{
					return true;
				}
				else if((m_lpEvent->m_managerServerId15 == nObjId || m_lpEvent->m_managerServerId14 == nObjId) && m_lpEvent->m_state != TvT::StateFight)
				{
					return true;
				}
			}
		}
	}
	return false;
}


int CTvT::FortressGetSkill()
{
	if(m_enabled && m_lpEvent)
	{
		if(m_lpEvent->m_state != TvT::StateNone)
		{
			if(m_lpEvent->m_lpInfo->type == TvT::TvTFortress)
			{
				return m_lpEvent->m_lpInfo->FortressSkillId;
			}
		}
	}
	return 0;
}

int CTvT::FortressGetNpcObject()
{
	if(m_enabled && m_lpEvent)
	{
		if(m_lpEvent->m_state != TvT::StateNone)
		{
			if(m_lpEvent->m_lpInfo->type == TvT::TvTFortress)
			{
				return m_lpEvent->m_managerServerId16;
			}
		}
	}
	return 0;
}

void CTvT::FortressCastCrystal(User* pUser, UINT nTargetObjId, INT32 nSkillId)
{
	if(m_enabled && m_lpEvent)
	{
		if(m_lpEvent->m_state == TvT::StateFight)
		{
			if(m_lpEvent->m_lpInfo->type == TvT::TvTFortress )
			{
				if (m_lpEvent->m_managerServerId16 == nTargetObjId &&  m_lpEvent->m_lpInfo->FortressSkillId == nSkillId)
				{
					if(pUser->pED->tvtUser.team == TvT::TeamRed)
					{
						m_lpEvent->m_tomasCountRed++;
						wstringstream msg;
						msg << "Event Fortress: " << pUser->pSD->wszName << " del equipo Rojo ha casteado el Crystal.";
						m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", msg.str().c_str());

						if (m_lpEvent->m_lpInfo->CaptureFireworkId >0)
						{
							if(CSkillInfo *pSI = g_SkillDB.GetSkillInfo(m_lpEvent->m_lpInfo->CaptureFireworkId, 1))
							{
								pSI->ActivateSkill(pUser, pUser);
								CSkillFx::BroadcastAutoCastSkill(pUser->CastCreature()->nObjectID,pUser->CastCreature()->nObjectID, m_lpEvent->m_lpInfo->CaptureFireworkId, 1, &pUser->CastCreature()->pSD->Pos);
							}
						}

						FortressTeleports();
					}
					else if(pUser->pED->tvtUser.team == TvT::TeamBlue)
					{
						m_lpEvent->m_tomasCountBlue++;
						wstringstream msg;
						msg << "Event Fortress: " << pUser->pSD->wszName << " del equipo Azul ha casteado el Crystal.";
						m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", msg.str().c_str());

						if (m_lpEvent->m_lpInfo->CaptureFireworkId >0)
						{
							if(CSkillInfo *pSI = g_SkillDB.GetSkillInfo(m_lpEvent->m_lpInfo->CaptureFireworkId, 1))
							{
								pSI->ActivateSkill(pUser, pUser);
								CSkillFx::BroadcastAutoCastSkill(pUser->CastCreature()->nObjectID,pUser->CastCreature()->nObjectID, m_lpEvent->m_lpInfo->CaptureFireworkId, 1, &pUser->CastCreature()->pSD->Pos);
							}
						}

						FortressTeleports();
					}
				}
			}
		}
	}
}

void CTvT::FortressTeleports()
{
	if(m_lpEvent->m_lpInfo->bluePos[m_lpEvent->m_lpInfo->m_bluePosPosicion].x != 0 || m_lpEvent->m_lpInfo->bluePos[m_lpEvent->m_lpInfo->m_bluePosPosicion].y != 0)
	{
		for(map<UINT, User*>::iterator Iter = m_lpEvent->m_users.begin(); Iter!=m_lpEvent->m_users.end();Iter++)
		{
			User *pUser = Iter->second;
			if(pUser->ValidUser() && pUser->pED->tvtUser.team == TvT::TeamBlue)
			{
				PlayerAction::OnTeleportToLocation(pUser, m_lpEvent->m_lpInfo->bluePos[m_lpEvent->m_lpInfo->m_bluePosPosicion].x, m_lpEvent->m_lpInfo->bluePos[m_lpEvent->m_lpInfo->m_bluePosPosicion].y, m_lpEvent->m_lpInfo->bluePos[m_lpEvent->m_lpInfo->m_bluePosPosicion].z, false);
				if (m_lpEvent->m_lpInfo->m_bluePosPosicion+1 > m_lpEvent->m_lpInfo->m_bluePosCantidad)
					m_lpEvent->m_lpInfo->m_bluePosPosicion = 0;
				else
					m_lpEvent->m_lpInfo->m_bluePosPosicion++;

					Sleep(m_lpEvent->m_lpInfo->teleportDelay);
			}
			else if(pUser->ValidUser() && pUser->pED->tvtUser.team == TvT::TeamRed)
			{
				PlayerAction::OnTeleportToLocation(pUser, m_lpEvent->m_lpInfo->redPos[m_lpEvent->m_lpInfo->m_redPosPosicion].x, m_lpEvent->m_lpInfo->redPos[m_lpEvent->m_lpInfo->m_redPosPosicion].y, m_lpEvent->m_lpInfo->redPos[m_lpEvent->m_lpInfo->m_redPosPosicion].z, false);
				if (m_lpEvent->m_lpInfo->m_redPosPosicion+1 > m_lpEvent->m_lpInfo->m_redPosCantidad)
					m_lpEvent->m_lpInfo->m_redPosPosicion = 0;
				else
					m_lpEvent->m_lpInfo->m_redPosPosicion++;

				Sleep(m_lpEvent->m_lpInfo->teleportDelay);
			}
		}
	}
}

void CTvT::FortressApplySkill(User *pUser)
{
	
	if(pUser->ValidUser())
	{
		pUser->AcquireSkill(m_lpEvent->m_lpInfo->FortressSkillId, 1);
		pUser->ValidateParameters();
	}
}

void CTvT::FortressRemoveSkill(User *pUser)
{
	if(pUser->ValidUser())
	{
		pUser->DeleteSkill(m_lpEvent->m_lpInfo->FortressSkillId);
		pUser->ValidateParameters();
	}
}


bool CTvT::CtfUseWeapon(User*pUser, CItem* pItem)
{
	if(m_enabled && m_lpEvent)
	{
		if(m_lpEvent->m_state == TvT::StateFight)
		{
			if(m_lpEvent->m_lpInfo->type == TvT::TvTCaptureTheFlag2 && pUser->pED->m_CtfUserFlag>0)
			{
				if(pItem->pSID->nSlotType == SlotRightHand || pItem->pSID->nSlotType == SlotLeftHand || pItem->pSID->nSlotType == SlotRightLeftHand || pItem->pSID->nSlotType == SlotLeftRightHand)
				{
					return true;
				}
			}
		}
	}
	return false;
}

bool CTvT::IsCtfNpcFlag(User*pUser, UINT nTargetObjId)
{
	if(m_enabled && m_lpEvent)
	{
		if(m_lpEvent->m_state == TvT::StateFight)
		{
			if(m_lpEvent->m_lpInfo->type == TvT::TvTCaptureTheFlag2)
			{
				if (m_lpEvent->m_managerServerId12 == nTargetObjId)	//red
				{
					CCreature *pTarget = (CCreature*)L2Server::GetObjectByID(pUser->pSD->nTargetObjId);
					if(pUser->CheckDistance(pTarget, 105))
					{
						if(pUser->pED->tvtUser.team == TvT::TeamRed)
						{
							if(pUser->nDBID == m_lpEvent->m_CtfUserFlag_red)
							{
								m_lpEvent->m_ctfCaptureCountRed++;
								m_lpEvent->m_CtfUserFlag_red = 0;
								pUser->pED->m_CtfUserFlag = 0;

								CItem *pWeapon = pUser->inventory.GetItemBySID(pUser->pED->m_CtfUserFlagWeapon);
								if(pWeapon->IsValidItem())
								{
									pUser->UseItem(pWeapon,true);
								}
								pUser->pED->m_CtfUserFlagWeapon = 0;
								g_Achivments.SetUser_CaptureTheFlag(pUser);

								wstringstream msg;
								msg << pUser->pSD->wszName << " del equipo Rojo ha capturado la bandera.";
								m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", msg.str().c_str());

								if (m_lpEvent->m_lpInfo->CaptureFireworkId >0)
								{
									if(CSkillInfo *pSI = g_SkillDB.GetSkillInfo(m_lpEvent->m_lpInfo->CaptureFireworkId, 1))
									{
										pSI->ActivateSkill(pUser, pUser);
										CSkillFx::BroadcastAutoCastSkill(pUser->CastCreature()->nObjectID,pUser->CastCreature()->nObjectID, m_lpEvent->m_lpInfo->CaptureFireworkId, 1, &pUser->CastCreature()->pSD->Pos);
									}
								}
								//suma un puto y le quita la bandera
							}
						}
						else if(pUser->pED->tvtUser.team == TvT::TeamBlue)
						{
							if(m_lpEvent->m_CtfUserFlag_blue == 0)
							{
								//entrega la bandera 

								CSharedItemData *pData = pUser->GetEquipedWeapon();
								if(pData)
								{
									pUser->pED->m_CtfUserFlagWeapon = pData->nObjectID;
								}
								else
								{
									pUser->pED->m_CtfUserFlagWeapon = 0;
								}

								m_lpEvent->m_CtfUserFlag_blue = pUser->nDBID;
								pUser->pED->m_CtfUserFlag = m_lpEvent->m_lpInfo->BanderaRedItemId;
								pUser->UnEquipItem(CItem::LRHand);
								pUser->UnEquipItem(CItem::RHand);
								pUser->UnEquipItem(CItem::LHand);
								pUser->SetUserInfoChanged();
								pUser->SetCharInfoChanged();

								wstringstream msg;
								msg << pUser->pSD->wszName << " del equipo Azul tiene la bandera.";
								m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", msg.str().c_str());
							}
						}
						return true;
					}

				}
				else if(m_lpEvent->m_managerServerId13 == nTargetObjId)	//NPC blue
				{
					CCreature *pTarget = (CCreature*)L2Server::GetObjectByID(pUser->pSD->nTargetObjId);
					if(pUser->CheckDistance(pTarget, 105))
					{
						if(pUser->pED->tvtUser.team == TvT::TeamBlue)
						{
							if(pUser->nDBID == m_lpEvent->m_CtfUserFlag_blue)
							{
								m_lpEvent->m_ctfCaptureCountBlue++;
								m_lpEvent->m_CtfUserFlag_blue = 0;
								pUser->pED->m_CtfUserFlag = 0;

								CItem *pWeapon = pUser->inventory.GetItemBySID(pUser->pED->m_CtfUserFlagWeapon);
								if(pWeapon->IsValidItem())
								{
									pUser->UseItem(pWeapon,true);
								}
								pUser->pED->m_CtfUserFlagWeapon = 0;

								g_Achivments.SetUser_CaptureTheFlag(pUser);

								wstringstream msg;
								msg << pUser->pSD->wszName << " del equipo Azul ha capturado la bandera.";
								m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", msg.str().c_str());

								if (m_lpEvent->m_lpInfo->CaptureFireworkId >0)
								{
									if(CSkillInfo *pSI = g_SkillDB.GetSkillInfo(m_lpEvent->m_lpInfo->CaptureFireworkId, 1))
									{
										pSI->ActivateSkill(pUser, pUser);
										CSkillFx::BroadcastAutoCastSkill(pUser->CastCreature()->nObjectID,pUser->CastCreature()->nObjectID, m_lpEvent->m_lpInfo->CaptureFireworkId, 1, &pUser->CastCreature()->pSD->Pos);
									}
								}
								//suma un puto y le quita la bandera
							}
						}
						else if(pUser->pED->tvtUser.team == TvT::TeamRed)
						{
							if(m_lpEvent->m_CtfUserFlag_red == 0)
							{
								//entrega la bandera 

								CSharedItemData *pData = pUser->GetEquipedWeapon();
								if(pData)
								{
									pUser->pED->m_CtfUserFlagWeapon = pData->nObjectID;
								}
								else
								{
									pUser->pED->m_CtfUserFlagWeapon = 0;
								}

								m_lpEvent->m_CtfUserFlag_red = pUser->nDBID;
								pUser->pED->m_CtfUserFlag = m_lpEvent->m_lpInfo->BanderaBlueItemId;
								pUser->UnEquipItem(CItem::LRHand);
								pUser->UnEquipItem(CItem::RHand);
								pUser->UnEquipItem(CItem::LHand);
								pUser->SetUserInfoChanged();
								pUser->SetCharInfoChanged();

								wstringstream msg;
								msg << pUser->pSD->wszName << " del equipo Rojo tiene la bandera.";
								m_lpEvent->Broadcast("cddSS", 0x4A, 0, 18, L"", msg.str().c_str());
							}
						}
						return true;
					}
				}
			}
		}
	}
	return false;
}

void CTvT::IsCtfEventMoveBackGround(User* pUser, UINT nTargetObjId)
{
	if(m_enabled && m_lpEvent && nTargetObjId > 0)
	{
		if(m_lpEvent->m_state == TvT::StateFight)
		{
			if(m_lpEvent->m_lpInfo->type == TvT::TvTCaptureTheFlag2)
			{
				if (m_lpEvent->m_managerServerId12 == nTargetObjId || m_lpEvent->m_managerServerId13 == nTargetObjId)
				{
					if(pUser->CastCreature()->pCreatureController->_unkn24[349]	== 6)
						pUser->CastCreature()->pCreatureController->_unkn24[349]=0;
				}
			}
		}
	}
}