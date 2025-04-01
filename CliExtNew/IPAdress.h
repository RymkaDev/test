#pragma once

class CIPAdress
{

public:
	CIPAdress();
	~CIPAdress();
	static wstring GetIP();
	static string GetIP2();
	static void Get_Website(string url);
	static string Get_IPv6();
};

extern CIPAdress g_IPAdress;