#pragma once

class CUrlFunc
{

public:
	CUrlFunc();
	~CUrlFunc();

	string SendPostRequest(string sHost, string params);
	string SendGetRequest(string sHost);
	string TrimData(string todo);

	//size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp);

};

size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp);

extern CUrlFunc g_CUrl;