#include "StdAfx.h"
#include "HappyHours.h"

CHappyHours g_HappyHours;

HappyHoursPeriod g_HappyPeriod[7];

CHappyHours::CHappyHours()
{
}

CHappyHours::~CHappyHours()
{
}

/*
[HappyHours]
Enabled=1
;All The Bonuses are multiplier
BonusExp=1
BonusSP=1
BonusAdena=1
BonusDrop=1
BonusSpoil=1
;Announcement 1 hour before start
AnnounceBeforeStart=
;Announcement on Start
AnnounceOnStart=
;Announce End, [param] is for minutes
AnnounceEnd=
;Time For Happy Hours
SundayStart=01
SundayEnd=02
MondayStart=01
MondayEnd=02
TuesdayStart=01
TuesdayEnd=02
WednesdayStart=01
WednesdayEnd=02
ThursdayStart=01
ThursdayEnd=02
FridayStart=01
FridayEnd=02
SaturdayStart=01
SaturdayEnd=02
;Second Time Enable
EnableSecondTime=0
SundayStart2=03
SundayEnd2=04
MondayStart2=03
MondayEnd2=04
TuesdayStart2=03
TuesdayEnd2=04
WednesdayStart2=03
WednesdayEnd2=04
ThursdayStart2=03
ThursdayEnd2=04
FridayStart2=03
FridayEnd2=04
SaturdayStart2=03
SaturdayEnd2=04
*/

void CHappyHours::Initialize()
{
	const TCHAR* section = _T("HappyHours");
	m_Enabled = GetPrivateProfileInt(section, _T("Enabled"), FALSE, g_ConfigFile);
	g_HappyHourSecondTimeEnabled = GetPrivateProfileInt(section, _T("EnableSecondTime"), FALSE, g_ConfigFile);

	nExpRateBonus = GetPrivateProfileInt(section, _T("BonusExp"), FALSE, g_ConfigFile);
	nSPRateBonus = GetPrivateProfileInt(section, _T("BonusSP"), FALSE, g_ConfigFile);
	nAdenaRateBonus = GetPrivateProfileInt(section, _T("BonusAdena"), FALSE, g_ConfigFile);
	nDropRateBonus = GetPrivateProfileInt(section, _T("BonusDrop"), FALSE, g_ConfigFile);
	nSpoilRateBonus = GetPrivateProfileInt(section, _T("BonusSpoil"), FALSE, g_ConfigFile);

	UINT dayIndex = 0;
	g_HappyPeriod[dayIndex].startHour = GetPrivateProfileInt(section, _T("SundayStart"), 20, g_ConfigFile);
	g_HappyPeriod[dayIndex].endHour = GetPrivateProfileInt(section, _T("SundayEnd"), 0, g_ConfigFile);
	g_HappyPeriod[dayIndex].startHour2 = GetPrivateProfileInt(section, _T("SundayStart2"), 20, g_ConfigFile);
	g_HappyPeriod[dayIndex].endHour2 = GetPrivateProfileInt(section, _T("SundayEnd2"), 0, g_ConfigFile);
	dayIndex++;
	g_HappyPeriod[dayIndex].startHour = GetPrivateProfileInt(section, _T("MondayStart"), 20, g_ConfigFile);
	g_HappyPeriod[dayIndex].endHour = GetPrivateProfileInt(section, _T("MondayEnd"), 0, g_ConfigFile);
	g_HappyPeriod[dayIndex].startHour2 = GetPrivateProfileInt(section, _T("MondayStart2"), 20, g_ConfigFile);
	g_HappyPeriod[dayIndex].endHour2 = GetPrivateProfileInt(section, _T("MondayEnd2"), 0, g_ConfigFile);
	dayIndex++;
	g_HappyPeriod[dayIndex].startHour = GetPrivateProfileInt(section, _T("TuesdayStart"), 20, g_ConfigFile);
	g_HappyPeriod[dayIndex].endHour = GetPrivateProfileInt(section, _T("TuesdayEnd"), 0, g_ConfigFile);
	g_HappyPeriod[dayIndex].startHour2 = GetPrivateProfileInt(section, _T("TuesdayStart2"), 20, g_ConfigFile);
	g_HappyPeriod[dayIndex].endHour2 = GetPrivateProfileInt(section, _T("TuesdayEnd2"), 0, g_ConfigFile);
	dayIndex++;
	g_HappyPeriod[dayIndex].startHour = GetPrivateProfileInt(section, _T("WednesdayStart"), 20, g_ConfigFile);
	g_HappyPeriod[dayIndex].endHour = GetPrivateProfileInt(section, _T("WednesdayEnd"), 0, g_ConfigFile);
	g_HappyPeriod[dayIndex].startHour2 = GetPrivateProfileInt(section, _T("WednesdayStart2"), 20, g_ConfigFile);
	g_HappyPeriod[dayIndex].endHour2 = GetPrivateProfileInt(section, _T("WednesdayEnd2"), 0, g_ConfigFile);
	dayIndex++;
	g_HappyPeriod[dayIndex].startHour = GetPrivateProfileInt(section, _T("ThursdayStart"), 20, g_ConfigFile);
	g_HappyPeriod[dayIndex].endHour = GetPrivateProfileInt(section, _T("ThursdayEnd"), 0, g_ConfigFile);
	g_HappyPeriod[dayIndex].startHour2 = GetPrivateProfileInt(section, _T("ThursdayStart2"), 20, g_ConfigFile);
	g_HappyPeriod[dayIndex].endHour2 = GetPrivateProfileInt(section, _T("ThursdayEnd2"), 0, g_ConfigFile);
	dayIndex++;
	g_HappyPeriod[dayIndex].startHour = GetPrivateProfileInt(section, _T("FridayStart"), 20, g_ConfigFile);
	g_HappyPeriod[dayIndex].endHour = GetPrivateProfileInt(section, _T("FridayEnd"), 0, g_ConfigFile);
	g_HappyPeriod[dayIndex].startHour2 = GetPrivateProfileInt(section, _T("FridayStart2"), 20, g_ConfigFile);
	g_HappyPeriod[dayIndex].endHour2 = GetPrivateProfileInt(section, _T("FridayEnd2"), 0, g_ConfigFile);
	dayIndex++;
	g_HappyPeriod[dayIndex].startHour = GetPrivateProfileInt(section, _T("SaturdayStart"), 20, g_ConfigFile);
	g_HappyPeriod[dayIndex].endHour = GetPrivateProfileInt(section, _T("SaturdayEnd"), 0, g_ConfigFile);
	g_HappyPeriod[dayIndex].startHour2 = GetPrivateProfileInt(section, _T("SaturdayStart2"), 20, g_ConfigFile);
	g_HappyPeriod[dayIndex].endHour2 = GetPrivateProfileInt(section, _T("SaturdayEnd2"), 0, g_ConfigFile);
	dayIndex++;

	TCHAR sTemp[0x8000];
	memset(sTemp, 0, sizeof(sTemp));
	if(GetPrivateProfileString(section, _T("AnnounceBeforeStart"), 0, sTemp, 8192, g_ConfigFile))
	{
		registrationBeforeStart = sTemp;
	}
	if(GetPrivateProfileString(section, _T("AnnounceOnStart"), 0, sTemp, 8192, g_ConfigFile))
	{
		registrationOnStart = sTemp;
	}
	if(GetPrivateProfileString(section, _T("AnnounceEnd"), 0, sTemp, 8192, g_ConfigFile))
	{
		registrationEnd = sTemp;
	}

	if(m_Enabled)
	{
		g_Log.Add(CLog::Blue, "[%s] Happy Hours Event Enabled.", __FUNCTION__);
	}
}

bool CHappyHours::GetStatus()
{
	tm ti;
	GetTimeInfo(ti);

	int StartHour = 20;
	int EndHour = 0;
	int StartHour2 = 20;
	int EndHour2 = 0;

	StartHour = g_HappyPeriod[ti.tm_wday].startHour;
	EndHour = g_HappyPeriod[ti.tm_wday].endHour;
	StartHour2 = g_HappyPeriod[ti.tm_wday].startHour2;
	EndHour2 = g_HappyPeriod[ti.tm_wday].endHour2;

	if(m_Enabled)
	{
		if( g_HappyHourSecondTimeEnabled == FALSE )
		{
			if(EndHour < StartHour)
			{
				if(ti.tm_hour >= StartHour)
				{
					return true;
				}
				if(ti.tm_hour >= EndHour)
				{
					return false;
				}
			}

			if(ti.tm_hour < StartHour)
			{
				return false;
			}

			if(ti.tm_hour >= EndHour)
			{
				return false;
			}
		}
		else
		{
			if( (ti.tm_hour > EndHour) && (EndHour > StartHour) )
			{
				if(EndHour2 < StartHour2)
				{
					if(ti.tm_hour >= StartHour2)
					{
						return true;
					}
					if(ti.tm_hour >= EndHour2)
					{
						return false;
					}
				}

				if(ti.tm_hour < StartHour2)
				{
					return false;
				}

				if(ti.tm_hour >= EndHour2)
				{
					return false;
				}
			}
			else
			{
				if(EndHour < StartHour)
				{
					if(ti.tm_hour >= StartHour)
					{
						return true;
					}
					if(ti.tm_hour >= EndHour)
					{
						return false;
					}
				}

				if(ti.tm_hour < StartHour)
				{
					return false;
				}

				if(ti.tm_hour >= EndHour)
				{
					return false;
				}
			}
		}
	}

	return false;
}

int CHappyHours::GetSP(int baseSP)
{
	if(GetStatus())
	{
		if(nSPRateBonus > 1)
		{
			double bonus = (double)(nSPRateBonus + 100);
			bonus /= 100;

			double sp = (double)baseSP;
			sp *= bonus;

	//		g_Log.Add(CLog::Blue, "[%s] IncSP[%d] bonus[%f] OutExp[%d]", __FUNCTION__, baseSP, bonus, (int)sp);

			return (int)sp;
		}
	}

	return baseSP;
}

int CHappyHours::GetExp(int baseExp)
{
	if(GetStatus())
	{
		if(nExpRateBonus > 1)
		{
			double bonus = (double)(nExpRateBonus + 100);
			bonus /= 100;

			double exp = (double)baseExp;
			exp *= bonus;

	//		g_Log.Add(CLog::Blue, "[%s] IncExp[%d] bonus[%f] OutExp[%d]", __FUNCTION__, baseExp, bonus, (int)exp);

			return (int)exp;
		}
	}

	return baseExp;
}

double CHappyHours::GetSpoilRate(CCreature *pCreature)
{
	double spoilRate = 1.0;

	if(GetStatus())
	{
		if(pCreature->ValidUser())
		{
			if(nSpoilRateBonus > 1)
			{
				double bonus = (double)(nSpoilRateBonus + 100);
				bonus /= 100;
				spoilRate *= bonus;

				//g_Log.Add(CLog::Blue, "[%s] spoilRate[%f]", __FUNCTION__, spoilRate);
			}
		}
	}

	return spoilRate;
}

double CHappyHours::GetAdenaRate(CCreature *pCreature)
{
	double dropRate = 1.0;

	if(GetStatus())
	{
		if(pCreature->ValidCreature())
		{
			if(pCreature->ValidUser())
			{
				if(nAdenaRateBonus > 1)
				{
					double bonus = (double)(nAdenaRateBonus + 100);
					bonus /= 100;
					dropRate *= bonus;
					//		g_Log.Add(CLog::Blue, "[%s] bonus[%f] DropRate[%f]", __FUNCTION__, bonus, dropRate);
				}
			}else if (pCreature->IsSummon())
			{
				CSummon *pSummon = (CSummon*)pCreature;
				if(User *pUser = pSummon->GetMaster())
				{
					if(nAdenaRateBonus > 1)
					{
						double bonus = (double)(nAdenaRateBonus + 100);
						bonus /= 100;
						dropRate *= bonus;
					}
				}
			}
		}
	}

	return dropRate;
}

double CHappyHours::GetDropRate(CCreature *pCreature)
{
	double dropRate = 1;

	if(GetStatus())
	{
		if(pCreature->ValidCreature())
		{
			if(pCreature->ValidUser())
			{
				if(nDropRateBonus > 1)
				{
					double bonus = (double)(nDropRateBonus + 100);
					bonus /= 100;
					dropRate *= bonus;
					//g_Log.Add(CLog::Blue, "[%s] bonus[%f] DropRate[%f]", __FUNCTION__, bonus, dropRate);
				}
			}else if (pCreature->IsSummon())
			{
				CSummon *pSummon = (CSummon*)pCreature;
				if(User *pUser = pSummon->GetMaster())
				{
					if(nDropRateBonus > 1)
					{
						double bonus = (double)(nDropRateBonus + 100);
						bonus /= 100;
						dropRate *= bonus;
					}
				}
			}
		}
	}

	return dropRate;
}
