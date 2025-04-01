#include "StdAfx.h"
#include "FactionCounter.h"

CFactionCounter g_FactionCounter;

void CFactionCounter::Init()
{
	guard;
	m_RedTeamCount = 0;
	m_GreenTeamCount = 0;
	unguard;
}

void CFactionCounter::IncreaseRedTeam() 
{
	m_InsLock.Enter();
	m_RedTeamCount = m_RedTeamCount + 1;
	m_InsLock.Leave();
}

void CFactionCounter::IncreaseGreenTeam()
{
	m_InsLock.Enter();
	m_GreenTeamCount = m_GreenTeamCount + 1;
	m_InsLock.Leave();
}

void CFactionCounter::DecreaseRedTeam()
{
	m_InsLock.Enter();
	if(GetRedTeamCount() < 1)
	{
		m_RedTeamCount = 0;
	}
	else
	{
		m_RedTeamCount = m_RedTeamCount - 1;
	}
	m_InsLock.Leave();
}

void CFactionCounter::DecreaseGreenTeam()
{
	m_InsLock.Enter();
	if(GetGreenTeamCount() < 1)
	{
		m_GreenTeamCount = 0;
	}
	else
	{
		m_GreenTeamCount = m_GreenTeamCount - 1;
	}
	m_InsLock.Leave();
}
