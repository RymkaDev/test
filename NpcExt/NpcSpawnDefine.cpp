#include "StdAfx.h"
#include "NpcSpawnDefine.h"
#include "NpcServer.h"

vector<std::wstring> BossAnnounceAnticipado;

bool primeroCargar = true;

void CNpcSpawnDefine::Init()
{
	WriteCall(0x4502BFL, CNpcSpawnDefine::GetRespawnTime);
	WriteCall(0x54D0A3L, CNpcSpawnDefine::GetRespawnTime);
	WriteCall(0x552B94L, CNpcSpawnDefine::GetRespawnTime);
	WriteCall(0x58C303L, CNpcSpawnDefine::GetRespawnTime);


	TCHAR File[MAX_PATH];
	GetCurrentDirectory(MAX_PATH,File);
	lstrcat(File, L"\\L2NPC.ini");

	INT32 TiempoEnSegundos = GetPrivateProfileInt(_T("BossAnnounceAnticipado"), _T("TiempoEnSegundos"), 0, File);	//no se usa aca, se usa en el l2server esta opcion de los segundos

	TCHAR sTemp[0x8000];
	memset(sTemp, 0, sizeof(sTemp));
	BossAnnounceAnticipado.clear();
	if(GetPrivateProfileString(_T("BossAnnounceAnticipado"), _T("ListBoss"), 0, sTemp, 0x8000, File))
	{
		wstringstream skillStream(sTemp);
		wstring skillName;
		while(skillStream >> skillName)
		{
			BossAnnounceAnticipado.push_back(skillName);
		}
	}
}


int CNpcSpawnDefine::GetRespawnTime(__int64* _this)
{
	int tiempoSpawn = 0;
	tiempoSpawn = reinterpret_cast<int(*)(__int64*)>(0x58A930)(_this);


	const WCHAR* nombre = reinterpret_cast<const WCHAR*(*)(__int64*)>(0x44FE10)(_this);
	

	//g_Log.Add(LogError, L"[%S] NPC[%s][%d]", __FUNCTION__, nombre, tiempoSpawn);

	for (std::vector<std::wstring>::iterator it = BossAnnounceAnticipado.begin(); it != BossAnnounceAnticipado.end(); ++it) {
		std::wstring& nameasd = *it;

		if (wcsstr(nameasd.c_str(), nombre) != NULL) {
			//g_Log.Add(LogError, L"[%S] NPC[%s][%d]", __FUNCTION__, _this->name, tiempoSpawn+time(0));

			g_NpcServer.Send("cdSd", 0x38, ANNOUNCE_ANTICIPADO, nombre, tiempoSpawn+time(0));
		}
	}


	return tiempoSpawn;
}

