#include "stdafx.h"
#include "RatesDinamicos.h"
#include "DropList.h"

RatesDinamicos g_RatesDinamicos;

void RatesDinamicos::Init()
{
	g_Log.Add(CLog::Blue, "[Load Rates Dinamicos]");
	Lock();

		m_eventInfo.clear();

		m_lpEvent = new Evento();
		m_lpEvent->enabled = FALSE;
		m_lpEvent->estado = StateDetenido;

		m_enabled = FALSE;
		LoadINI();
		if(m_enabled)
		{
			g_Log.Add(CLog::Blue, "[%S] Feature is enabled, loaded [%d] events", L"TvT", m_eventInfo.size());
		}
		else
		{
			g_Log.Add(CLog::Blue, "[%S] Feature is Disabled");
		}
	Unlock();
}

void RatesDinamicos::LoadINI()
{
	TCHAR g_DinamicRatesFile[260];
	GetCurrentDirectory(MAX_PATH,g_DinamicRatesFile);

	lstrcat(g_DinamicRatesFile, m_ConfigsIlExt);

	lstrcat(g_DinamicRatesFile, TEXT("\\DinamicRates.ini"));
	const TCHAR* section = _T("DinamicRates");
	m_enabled = GetPrivateProfileInt(section, _T("Enabled"), FALSE, g_DinamicRatesFile);
	INT32 count = GetPrivateProfileInt(section, _T("DinamicRatesCount"), 0, g_DinamicRatesFile);
	if(count > 0)
	{
		for(int n=1;n<=count;n++)
		{
			tstringstream sectionEx;
			sectionEx << "Dinamic_" << n ;

			Evento* pInfo = new Evento();
			pInfo->enabled = GetPrivateProfileInt(sectionEx.str().c_str(), _T("Enabled"), FALSE, g_DinamicRatesFile);

			UINT dayFlag = GetPrivateProfileInt(sectionEx.str().c_str(), _T("DayFlag"), 0, g_DinamicRatesFile);
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
			pInfo->startHour = GetPrivateProfileInt(sectionEx.str().c_str(), _T("StartHour"), 14, g_DinamicRatesFile);
			pInfo->startMinute = GetPrivateProfileInt(sectionEx.str().c_str(), _T("StartMinute"), 30, g_DinamicRatesFile);

			pInfo->endHour = GetPrivateProfileInt(sectionEx.str().c_str(), _T("EndHour"), 14, g_DinamicRatesFile);
			pInfo->endMinute = GetPrivateProfileInt(sectionEx.str().c_str(), _T("EndMinute"), 30, g_DinamicRatesFile);

			pInfo->nExpRate = GetPrivateProfileDouble(sectionEx.str().c_str(), _T("nExpRate"), 1.0, g_DinamicRatesFile);
			pInfo->nAdenaRate = GetPrivateProfileDouble(sectionEx.str().c_str(), _T("nAdenaRate"), 1.0, g_DinamicRatesFile);
			pInfo->nAncientAdenaRate = GetPrivateProfileDouble(sectionEx.str().c_str(), _T("nAncientAdenaRate"), 1.0, g_DinamicRatesFile);
			pInfo->nSpoilRate = GetPrivateProfileDouble(sectionEx.str().c_str(), _T("nSpoilRate"), 1.0, g_DinamicRatesFile);
			pInfo->nSpoilCount = GetPrivateProfileDouble(sectionEx.str().c_str(), _T("nSpoilCount"), 1.0, g_DinamicRatesFile);
			pInfo->nRaidBossItemChance = GetPrivateProfileDouble(sectionEx.str().c_str(), _T("nRaidBossItemChance"), 1.0, g_DinamicRatesFile);
			pInfo->nItemCountsChance = GetPrivateProfileDouble(sectionEx.str().c_str(), _T("nItemCountsChance"), 1.0, g_DinamicRatesFile);


			pInfo->m_AnnounceInitMsgId = GetPrivateProfileInt(sectionEx.str().c_str(), _T("AnnounceInitMsgId"), 2901, g_DinamicRatesFile);
			pInfo->m_AnnounceEndMsgId = GetPrivateProfileInt(sectionEx.str().c_str(), _T("AnnounceEndMsgId"), 2901, g_DinamicRatesFile);

			TCHAR temp[16384] = { 0 };
			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("AnnounceInitMsg"), 0, temp, 16384, g_DinamicRatesFile))
			{
				pInfo->m_AnnounceInitMsg = temp;
			}

			if(GetPrivateProfileString(sectionEx.str().c_str(), _T("AnnounceEndMsg"), 0, temp, 16384, g_DinamicRatesFile))
			{
				pInfo->m_AnnounceEndMsg = temp;
			}

			m_eventInfo.push_back(pInfo);
		}
	}
}

double RatesDinamicos::GetExpRate()
{
	double ret = 1.0;
	if(m_lpEvent->enabled == TRUE && m_lpEvent->estado == StateIniciado)
	{
		ret = m_lpEvent->nExpRate;
	}
	return ret;
}

double RatesDinamicos::GetAdenaRate()
{
	double ret = 1.0;
	if(m_lpEvent->enabled == TRUE && m_lpEvent->estado == StateIniciado)
	{
		ret = m_lpEvent->nAdenaRate;
	}
	return ret;
}

double RatesDinamicos::GetAncientAdenaRate()
{
	double ret = 1.0;
	if(m_lpEvent->enabled == TRUE && m_lpEvent->estado == StateIniciado)
	{
		ret = m_lpEvent->nAncientAdenaRate;
	}
	return ret;
}

double RatesDinamicos::GetSpoilRate()
{
	double ret = 1.0;
	if(m_lpEvent->enabled == TRUE && m_lpEvent->estado == StateIniciado)
	{
		ret = m_lpEvent->nSpoilRate;
	}
	return ret;
}

double RatesDinamicos::GetSpoilCount()
{
	double ret = 1.0;
	if(m_lpEvent->enabled == TRUE && m_lpEvent->estado == StateIniciado)
	{
		ret = m_lpEvent->nSpoilCount;
	}
	return ret;
}

double RatesDinamicos::GetRaidBossItemChance()
{
	double ret = 1.0;
	if(m_lpEvent->enabled == TRUE && m_lpEvent->estado == StateIniciado)
	{
		ret = m_lpEvent->nRaidBossItemChance;
	}
	return ret;
}

double RatesDinamicos::GetItemCountsChance()
{
	double ret = 1.0;
	if(m_lpEvent->enabled == TRUE && m_lpEvent->estado == StateIniciado)
	{
		ret = m_lpEvent->nItemCountsChance;
	}
	return ret;
}


void RatesDinamicos::EnterWorld(User* pUser)
{
	if(pUser->ValidUser())
	{
		if(m_lpEvent->enabled == TRUE && m_lpEvent->estado == StateIniciado)
		{
			CSystemMessage msg1(m_lpEvent->m_AnnounceInitMsgId);
			msg1.AddText(m_lpEvent->m_AnnounceInitMsg.c_str());
			pUser->pSocket->SendSystemMessage(&msg1);
		}
	}
}



void RatesDinamicos::TimerExpired()
{
	guard;
	if(m_enabled)
	{
		Lock();
		if(m_lpEvent->estado == StateMensajeInit)
		{
			CSystemMessage msg(m_lpEvent->m_AnnounceInitMsgId);
			msg.AddText(m_lpEvent->m_AnnounceInitMsg.c_str());
			L2Server::BroadcastToAllUser(msg.GetSize(), msg.GetBuff());
			m_lpEvent->estado = StateIniciado;
			
			g_DropList.Init();

		}else if(m_lpEvent->estado == StateIniciado)
		{
			tm ti; time_t rawtime;
			time ( &rawtime );
			localtime_s(&ti, &rawtime );
			if(m_lpEvent->endHour == ti.tm_hour && m_lpEvent->endMinute == ti.tm_min)
			{
				m_lpEvent->estado = StateMensajeFin;
			}
		}else if(m_lpEvent->estado == StateMensajeFin)
		{
			CSystemMessage msg(m_lpEvent->m_AnnounceEndMsgId);
			msg.AddText(m_lpEvent->m_AnnounceEndMsg.c_str());
			L2Server::BroadcastToAllUser(msg.GetSize(), msg.GetBuff());

			m_lpEvent->estado = StateDetenido;

			m_lpEvent = new Evento();
			g_DropList.Init();
		}else
		{
			tm ti; time_t rawtime;
			time ( &rawtime );
			localtime_s(&ti, &rawtime );



			for(list<Evento*>::iterator Iter = m_eventInfo.begin();Iter!=m_eventInfo.end();Iter++)
			{
				Evento* pInfo = (*Iter);
				if(pInfo)
				{
					if(pInfo->enabled)
					{
						if(pInfo->dayFlag[ti.tm_wday])
						{

							bool activarEnvento = false;

							time_t hora_local = time(0);
							tm* fecha_hora = localtime(&hora_local);
							INT32 dia = fecha_hora->tm_mday;
							INT32 mes = fecha_hora->tm_mon;  // Sumar 1 porque los meses comienzan en 0
							INT32 anio = fecha_hora->tm_year;  // Sumar 1900 porque los años comienzan en 1900

							//struct tm time_in = {0, 0, 0, dia, mes, anio}; // 00:00:00 del 25 de mayo de 2023
							//time_t time_unix = mktime(&time_in);

							struct tm time_in2 = {0, pInfo->startMinute, pInfo->startHour, dia, mes, anio}; // 00:00:00 del 25 de mayo de 2023
							time_t tiempo_start = mktime(&time_in2);
	
							struct tm time_in3 = {0, pInfo->endMinute, pInfo->endHour, dia, mes, anio}; // 00:00:00 del 25 de mayo de 2023
							time_t tiempo_end = mktime(&time_in3);
						

							if(hora_local > tiempo_start && hora_local < tiempo_end)
							{
								activarEnvento = true;
							}

							if(activarEnvento)
							{
								m_lpEvent = pInfo;
								m_lpEvent->estado = StateMensajeInit;

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