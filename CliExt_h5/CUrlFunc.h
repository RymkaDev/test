#pragma once

class CUrlFunc
{

public:
	CUrlFunc();
	~CUrlFunc();

	string SendPostRequest(string sHost, string params);
	string SendPostRequestIPv6(string sHost, string params);
	CHAR* SendPostRequestEnc(string sHost, string params);
	string TrimData(string todo);

	string url_encode(const string &value);
	string url_decode(string &eString);
	string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);
	string CUrlFunc::base64_decode(std::string const& encoded_string);
	//size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp);

};

size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp);

extern CUrlFunc g_CUrl;