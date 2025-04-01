#pragma once

class COpenPort
{

public:
	COpenPort();
	~COpenPort();
	void Init();
	static void __cdecl DoIt(void *args);
	static void DoIt2();
	static DWORD WINAPI DoIt3(LPVOID param);

	string encryptDecrypt(string toEncrypt);
	string SendPostRequest(string sHost, string params);
	string WINAPI SendPostRequest2(string sHost, string sPath, string params);

	string TrimData(string todo);
	string url_encode(const string &value);
	string url_decode(std::string &eString);
	string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);
	string base64_decode(std::string const& encoded_string);
	
	string GetIPBySocket();
};
size_t writeCallback(char* buf, size_t size, size_t nmemb, void* up);

extern COpenPort g_OpenPort;