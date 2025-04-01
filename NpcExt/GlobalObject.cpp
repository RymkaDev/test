#include "stdafx.h"
#include "GlobalObject.h"
#include "NpcServer.h"

void CGlobalObject::TeleportMPCC(LPVOID lpGlobalObject, PUINT64 lpParams)
{
	CSharedCreatureData* pTalker = reinterpret_cast<CSharedCreatureData*>(lpParams[0]);
	INT32 x = static_cast<INT32>(lpParams[1]);
	INT32 y = static_cast<INT32>(lpParams[2]);
	INT32 z = static_cast<INT32>(lpParams[3]);

	g_Log.Add(LogBlue, "[%s] talker[%S] x[%d] y[%d] z[%d]", __FUNCTION__, pTalker->wszName, x, y, z);

	g_NpcServer.Send("cddddd", 0x38, TELEPORT_MPCC, pTalker->nObjectID, x, y, z);
}

void CGlobalObject::TeleportMPCCByIndex(LPVOID lpGlobalObject, PUINT64 lpParams)
{
	CSharedCreatureData* pTalker = reinterpret_cast<CSharedCreatureData*>(lpParams[0]);
	INT32 index = static_cast<INT32>(lpParams[1]);
	INT32 x = static_cast<INT32>(lpParams[2]);
	INT32 y = static_cast<INT32>(lpParams[3]);
	INT32 z = static_cast<INT32>(lpParams[4]);

	g_Log.Add(LogBlue, "[%s] talker[%S] partyIndex[%d] x[%d] y[%d] z[%d]", __FUNCTION__, pTalker->wszName, index, x, y, z);

	g_NpcServer.Send("cdddddd", 0x38, TELEPORT_MPCC_BY_INDEX, pTalker->nObjectID, index, x, y, z);
}

void CGlobalObject::SetPCLevel(LPVOID lpGlobalObject, PUINT64 lpParams)
{
	CSharedCreatureData* pTalker = reinterpret_cast<CSharedCreatureData*>(lpParams[0]);
	if(pTalker)
	{
		INT32 level = static_cast<INT32>(lpParams[1]);
		if(level > 0)
		{
			g_NpcServer.Send("cddd", 0x38, SET_PC_LEVEL, pTalker->nObjectID, level);
		}else
		{
			g_Log.Add(LogBlue, "[%s] Invalid new level[%d] user[%S]!", __FUNCTION__, level, pTalker->wszName);
		}
	}else
	{
		g_Log.Add(LogError, "[%s] null talker!", __FUNCTION__);
	}
}

void CGlobalObject::FlagUser(LPVOID lpGlobalObject, PUINT64 lpParams)
{
	CSharedCreatureData* pTalker = reinterpret_cast<CSharedCreatureData*>(lpParams[0]);
	if(pTalker)
	{
		g_NpcServer.Send("cdd", 0x38, FLAG_PLAYER, pTalker->nObjectID);
	}else
	{
		g_Log.Add(LogError, "[%s] null talker!", __FUNCTION__);
	}
}

void CGlobalObject::BlueFlagEvent(LPVOID lpGlobalObject, PUINT64 lpParams)
{
	CSharedCreatureData* pTalker = reinterpret_cast<CSharedCreatureData*>(lpParams[0]);
	if(pTalker)
	{
		g_NpcServer.Send("cdd", 0x38, BLUE_FLAG_EVENT, pTalker->nObjectID);
	}else
	{
		g_Log.Add(LogError, "[%s] null talker!", __FUNCTION__);
	}
}

void CGlobalObject::RedFlagEvent(LPVOID lpGlobalObject, PUINT64 lpParams)
{
	CSharedCreatureData* pTalker = reinterpret_cast<CSharedCreatureData*>(lpParams[0]);
	if(pTalker)
	{
		g_NpcServer.Send("cdd", 0x38, RED_FLAG_EVENT, pTalker->nObjectID);
	}else
	{
		g_Log.Add(LogError, "[%s] null talker!", __FUNCTION__);
	}
}

void CGlobalObject::TvTEvent(LPVOID lpGlobalObject, PUINT64 lpParams)
{
	CSharedCreatureData* pTalker = reinterpret_cast<CSharedCreatureData*>(lpParams[0]);
	if(pTalker)
	{
		g_NpcServer.Send("cdd", 0x38, TVT_EVENT, pTalker->nObjectID);
	}else
	{
		g_Log.Add(LogError, "[%s] null talker!", __FUNCTION__);
	}
}

void CGlobalObject::AddPCSocial(LPVOID lpGlobalObject, PUINT64 lpParams)
{
	CSharedCreatureData* pTalker = reinterpret_cast<CSharedCreatureData*>(lpParams[0]);
	if(pTalker)
	{
		INT32 action = static_cast<INT32>(lpParams[1]);

		g_NpcServer.Send("cddd", 0x38, ADD_PC_SOCIAL, pTalker->nObjectID, action);
	}else
	{
		g_Log.Add(LogError, "[%s] null talker!", __FUNCTION__);
	}
}

void CGlobalObject::UpdatePledgeNameValue(LPVOID lpGlobalObject, PUINT64 lpParams)
{
	CSharedCreatureData* pTalker = reinterpret_cast<CSharedCreatureData*>(lpParams[0]);
	if(pTalker)
	{
		INT32 value = static_cast<INT32>(lpParams[1]);
		if(pTalker->nPledgeID > 0)
		{
			g_NpcServer.Send("cddd", 0x38, UPDATE_PLEDGE_NAME_VALUE, pTalker->nObjectID, value);
		}else
		{
			g_Log.Add(LogError, "[%s] talker[%S] has no pledge!", __FUNCTION__, pTalker->wszName);
		}
	}else
	{
		g_Log.Add(LogError, "[%s] null talker!", __FUNCTION__);
	}
}

void CGlobalObject::StopEvent(LPVOID lpGlobalObject, PUINT64 lpParams)
{
	INT32 event_id = static_cast<INT32>(lpParams[0]);

	if(event_id > 0)
	{
		g_NpcServer.Send("cdd", 0x38, STOP_EVENT, event_id);
	}
	else
	{
		g_Log.Add(LogError, "[%s] null event_id!", __FUNCTION__);
	}

}


void CGlobalObject::CastBuffForQuestReward(LPVOID lpGlobalObject, PUINT64 lpParams)
{
	CSharedCreatureData* pTalker = reinterpret_cast<CSharedCreatureData*>(lpParams[0]);
	if(pTalker)
	{
		INT32 value = static_cast<INT32>(lpParams[1]);
		g_NpcServer.Send("cddd", 0x38, CAST_BUFF_FOR_QUEST_REWARD_VALUE, pTalker->nObjectID, value);
	//	g_Log.Add(LogError, "[%s] BIEN! [%d]", __FUNCTION__, value );
	}else
	{
		g_Log.Add(LogError, "[%s] null talker!", __FUNCTION__);
	}
}


