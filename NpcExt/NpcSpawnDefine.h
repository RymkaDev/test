#pragma once


class CNpcSpawnDefine {
public:
	static void Init();
	static int CNpcSpawnDefine::GetRespawnTime(__int64*);

	/* 0x0000 */ unsigned char padding0x0000[0x0058 - 0x0000];
	/* 0x0058 */ WCHAR name[25];
	/* 0x0080 */ //unsigned char padding0x0080[0x0084 - 0x0080];
	/* 0x0084 */ UINT32 respawnTime;
	/* 0x0088 */ UINT32 respawnTimeRandom;
};

