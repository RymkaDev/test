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
#pragma comment(lib,"libeay32MT.lib")
#pragma comment(lib,"ssleay32MT.lib")
#pragma comment(lib,"libcurl.lib")
#define CURL_STATICLIB
#pragma comment(lib,"wldap32.lib")
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
	CURL *curl;
	CURLcode res;
	string readBuffer;
	
	curl_global_init(CURL_GLOBAL_DEFAULT);
 
	curl = curl_easy_init();
	if(curl) 
	{
		curl_easy_setopt(curl, CURLOPT_URL, sHost.c_str());
		curl_easy_setopt(curl, CURLOPT_DNS_SERVERS, "1.1.1.1");
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		//curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.0.7) Gecko/20061022 Iceweasel/1.5.0.7-g2"); 

		if(params.size() > 0)
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, params.c_str());

		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		
		res = curl_easy_perform(curl);

		//Check For Errors
		/*if(res != CURLE_OK)
		  fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		*/

		curl_easy_cleanup(curl);
	}
 
	curl_global_cleanup();
	
	return readBuffer;
}

string CUrlFunc::SendPostRequestIPv6(string sHost, string params)
{
	CURL *curl;
	CURLcode res;
	string readBuffer;
	
	curl_global_init(CURL_GLOBAL_DEFAULT);
 
	curl = curl_easy_init();
	if(curl) 
	{
		curl_easy_setopt(curl, CURLOPT_URL, sHost.c_str());
		//curl_easy_setopt(curl, CURLOPT_DNS_SERVERS, "2606:4700:4700::1111");
		curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V6);

		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

		if(params.size() > 0)
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, params.c_str());

		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		
		res = curl_easy_perform(curl);

		//Check For Errors
		if(res != CURLE_OK)
		{
			// fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
			stringstream pathStream;
			pathStream << "Error:" << curl_easy_strerror(res) << " " << curl_version();;

			//MessageBoxA(0, pathStream.str().c_str(), "Error", MB_OK);
		}
		

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

CHAR* CUrlFunc::SendPostRequestEnc(string sHost, string params)
{
	CURL *curl;
	CURLcode res;
	string readBuffer;
	//CHAR* result;

	curl_global_init(CURL_GLOBAL_DEFAULT);
 
	curl = curl_easy_init();
	if(curl) 
	{
		curl_easy_setopt(curl, CURLOPT_URL, sHost.c_str());
		curl_easy_setopt(curl, CURLOPT_DNS_SERVERS, "1.1.1.1");
		curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		
		CHAR agent[] = { 'M','o','z','i','l','l','a','/','5','.','0',' ','(','X','1','1',';',' ','U',';',' ','L','i','n','u','x',' ','i','6','8','6',';',' ','e','n','-','U','S',';',' ','r','v',':','1','.','8','.','0','.','7',')',' ','G','e','c','k','o','/','2','0','0','6','1','0','2','2',' ','I','c','e','w','e','a','s','e','l','/','1','.','5','.','0','.','7','-','g','2', 0 };
		curl_easy_setopt(curl, CURLOPT_USERAGENT, agent); 
		//curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.0.7) Gecko/20061022 Iceweasel/1.5.0.7-g2"); 

		if(params.size() > 0)
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, params.c_str());

		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		
		res = curl_easy_perform(curl);

		//Check For Errors
		/*if(res != CURLE_OK)
		  fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		*/

		curl_easy_cleanup(curl);
	}
 
	//result = readBuffer.c_str();
	char *result = new char[readBuffer.length() + 1];
	strcpy(result, readBuffer.c_str());

	curl_global_cleanup();
	
	return result;
}


string CUrlFunc::url_encode(const string &value) {
    ostringstream escaped;
    escaped.fill('0');
    escaped << hex;

    for (string::const_iterator i = value.begin(), n = value.end(); i != n; ++i) {
        string::value_type c = (*i);

        // Keep alphanumeric and other accepted characters intact
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
            continue;
        }

        // Any other characters are percent-encoded
        escaped << uppercase;
        escaped << '%' << setw(2) << int((unsigned char) c);
        escaped << nouppercase;
    }

    return escaped.str();
}

string CUrlFunc::url_decode(string &eString) 
{
	string ret;
	char ch;
	int i, j;
	for (i=0; i<eString.length(); i++) {
		if (int(eString[i])==37) {
			sscanf(eString.substr(i+1,2).c_str(), "%x", &j);
			ch=static_cast<char>(j);
			ret+=ch;
			i=i+2;
		} else {
			ret+=eString[i];
		}
	}
	return (ret);
}

string CUrlFunc::base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
  std::string ret;
  int i = 0;
  int j = 0;
  unsigned char char_array_3[3];
  unsigned char char_array_4[4];

	static const string base64_chars = 
				 "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				 "abcdefghijklmnopqrstuvwxyz"
				 "0123456789+/";

  while (in_len--) {
    char_array_3[i++] = *(bytes_to_encode++);
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for(i = 0; (i <4) ; i++)
        ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i)
  {
    for(j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;

    for (j = 0; (j < i + 1); j++)
      ret += base64_chars[char_array_4[j]];

    while((i++ < 3))
      ret += '=';

  }

  return ret;

}


static inline bool is_base64(unsigned char c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}


static const std::string base64_chars = 
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

std::string CUrlFunc::base64_decode(std::string const& encoded_string) {
  int in_len = encoded_string.size();
  int i = 0;
  int j = 0;
  int in_ = 0;
  unsigned char char_array_4[4], char_array_3[3];
  std::string ret;

  while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_]) ) {
    char_array_4[i++] = encoded_string[in_]; in_++;
    if (i ==4) {
      for (i = 0; i <4; i++)
        char_array_4[i] = base64_chars.find(char_array_4[i]);

      char_array_3[0] = ( char_array_4[0] << 2       ) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) +   char_array_4[3];

      for (i = 0; (i < 3); i++)
        ret += char_array_3[i];
      i = 0;
    }
  }

  if (i) {
    for (j = 0; j < i; j++)
      char_array_4[j] = base64_chars.find(char_array_4[j]);

    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);

    for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
  }

  return ret;
}