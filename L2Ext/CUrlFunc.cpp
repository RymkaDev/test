#include "stdafx.h"
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <iostream>
#include <vector>
#include <locale>
#include <sstream>
#include <cctype>
#include <iomanip>


#include "CUrlFunc.h"

using namespace std;

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"libcrypto64MT.lib")
#pragma comment(lib,"libssl64MT.lib")
#pragma comment(lib,"wldap32.lib")
#pragma comment(lib,"winmm.lib")
#pragma comment(lib,"libcurl.lib")
#define CURL_STATICLIB

#include "curl/curl.h"

CUrlFunc g_CUrl;

CUrlFunc::CUrlFunc()
{
}

CUrlFunc::~CUrlFunc()
{
}

string CUrlFunc::TrimData(string todo)
{
	while(todo.find ("\n") != string::npos)
    {
        todo.erase ( todo.find ("\n"), 1 );
    }

	return todo;
}

string CUrlFunc::SendPostRequest(string sHost, string params)
{
	string readBuffer;
	CURL *curl;
	CURLcode res;
	
	curl_global_init(CURL_GLOBAL_DEFAULT);

	curl = curl_easy_init();
	if(curl) 
	{
		curl_easy_setopt(curl, CURLOPT_URL, sHost.c_str());
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 7L);
		//curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.0.7) Gecko/20061022 Iceweasel/1.5.0.7-g2"); 

		if(params.size() > 0)
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, params.c_str());

		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		
		res = curl_easy_perform(curl);

		curl_easy_cleanup(curl);
	}
 
	curl_global_cleanup();

	return readBuffer;
}

string CUrlFunc::SendGetRequest(string sHost)
{
	string readBuffer;
	CURL *curl;
	CURLcode res;
	
	curl_global_init(CURL_GLOBAL_DEFAULT);

	curl = curl_easy_init();
	if(curl) 
	{
		curl_easy_setopt(curl, CURLOPT_URL, sHost.c_str());
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 7L);
		//curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.0.7) Gecko/20061022 Iceweasel/1.5.0.7-g2"); 

		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		
		res = curl_easy_perform(curl);

		curl_easy_cleanup(curl);
	}
 
	curl_global_cleanup();

	return readBuffer;
}

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

