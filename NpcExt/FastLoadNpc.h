#pragma once

class CFastLoadNPC
{
public:
	static void Init();
	static void TimerExpired(UINT64 pNpcMakerDB, int nTimerId);
};