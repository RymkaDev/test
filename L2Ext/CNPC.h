#pragma once
#include "CCreature.h"

struct NpcDataInfo
{
  int walk_speed;
  int swim_walk_speed;
  int fly_walk_speed2;
  int fly_walk_speed;
  int run_speed;
  int swim_run_speed;
  int fly_run_speed2;
  int fly_run_speed;
  PVOID _unkn[28];
//	PVOID _unkn[32];
	map<const wstring, const wstring> aiParams;
};

class CNPC: public CCreature
{
public:
	/* 1500 */ LPVOID _unkn1500[32];
	/* 1600 */ LPVOID _unkn1600[32];	
	/* 1700 */ LPVOID _unkn1700[32];
	/* 1800 */ LPVOID _unkn1800[32];
	/* 1900 */ LPVOID _unkn1900[26];
	/* 19D0 */ NpcDataInfo* pND;

	void TimerExpired(int id);
	void KillNPC();
	void TeleportToLocation(int x, int y, int z, int param0);
	void ValidateOrgHPMP();
	static CNPC* GetNPCByServerId(LPUINT pSID);
};
