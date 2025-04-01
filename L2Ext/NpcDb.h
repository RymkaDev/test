#pragma once


struct NpcInfo
{
	INT32 id;
	INT32 classId;
	wstring name;
	wstring clientName;
	NpcInfo() : id(0), classId(0) {}
};

class CNpcDb
{
	vector<NpcInfo> m_DB;
	vector<NpcInfo> m_DB2;
	void LoadData();
public:
	void Init();
	wstring GetClientNameByName(wstring name);
	wstring GetClientNameByClassId(UINT classId);
	wstring GetDbNameByClassId(UINT classId);
	wstring GetClientNameByName2(wstring name);
	wstring GetClientNameByClassId2(UINT classId);
};

extern CNpcDb g_NpcDb;