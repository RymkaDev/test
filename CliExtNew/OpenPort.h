#pragma once

class COpenPort
{

public:
	COpenPort();
	~COpenPort();
	void Init();
	static void __cdecl DoIt(void *args);
	string WINAPI SendPostRequest(string sHost, string sPath, string params);
	string GetIPBySocket();
};

extern COpenPort g_OpenPort;