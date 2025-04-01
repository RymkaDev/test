#include "StdAfx.h"

extern UINT g_ServerStartTime;

UINT ContadorSpawns = 0;

UINT GetServerUpTime()
{
	return static_cast<UINT>(time(0) - g_ServerStartTime);
}

string WINAPI SendPostRequest(string sHost, string sPath, string params)
{
	VIRTUALIZER_TIGER_RED_START;
	string reply = "";
	try
	{
		hostent *remoteHost = gethostbyname(sHost.c_str());
		if(remoteHost)
		{
			hostent host = *remoteHost;
			in_addr addr;
			stringstream webStream;
			if(remoteHost)
			{
				if(host.h_length)
				{
					addr.s_addr = (*(u_long *)host.h_addr_list[0]);
					SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
					if(s != INVALID_SOCKET)
					{
						SOCKADDR_IN sockAddr;
						memset(&sockAddr,0, sizeof(sockAddr));
						sockAddr.sin_family = AF_INET;
						sockAddr.sin_port = htons(80);
						sockAddr.sin_addr = *((LPIN_ADDR)*host.h_addr_list);

						if(!connect(s,(SOCKADDR *)&sockAddr,sizeof(SOCKADDR_IN)))
						{
							char buffer[8192];
							memset(buffer, 0, sizeof(buffer));
							int len = 0;

							string content = params;
							char temp[16];
							_itoa_s((INT32)content.size(), temp, sizeof(temp), 10);

							char _post[] = { 'P', 'O', 'S', 'T', ' ', 0 };
							char _http[] = { ' ', 'H', 'T', 'T', 'P', '/', '1', '.', '1', '\r', '\n', 0 };
							char _host[] = {'H', 'o', 's', 't', ':', ' ', 0};
							char _rn[] = { '\r', '\n', 0 };
							char _userAgent[] = { 'U', 's', 'e', 'r', '-', 'A', 'g', 'e', 'n', 't', ':', ' ',
								'M', 'o', 'z', 'i', 'l', 'l', 'a', '/', '5', '.', '0', ' ',
								'(', 'W', 'i', 'n', 'd', 'o', 'w', 's', ' ', 'N', 'T', ' ', '6', '.', '1', ';',
								' ', 'W', 'O', 'W', '6', '4', ';', ' ', 'r', 'v', ':', '2', '3', '.', '0', ')',
								' ', 'G', 'e', 'c', 'k', 'o', '/', '2', '0', '1', '0', '0', '1', '0', '1', ' ',
								'F', 'i', 'r', 'e', 'f', 'o', 'x', '/', '2', '3', '.', '0', 0 };
							char _acceptLanguage[] = { 'A', 'c', 'c', 'e', 'p', 't', '-', 'L', 'a', 'n', 'g', 'u', 'a', 'g', 'e', ':', ' ', 'p', 'l', '-', 'P', 'L', ',', 'p', 'l', ';', 'q', '=', '0', '.', '8', ',', 'e', 'n', '-', 'U', 'S', ';', 'q', '=', '0', '.', '6', ',', 'e', 'n', ';', 'q', '=', '0', '.', '4', 0 };
							char _acceptCharset[] = { 'A', 'c', 'c', 'e', 'p', 't', '-', 'C', 'h', 'a', 'r', 's', 'e', 't', ':', ' ', 'I', 'S', 'O', '-', '8', '8', '5', '9', '-', '2', ',', 'u', 't', 'f', '-', '8', ';', 'q', '=', '0', '.', '7', ',', '*', ';', 'q', '=', '0', '.', '7', 0 };
							char _cacheControl[] = { 'C', 'a', 'c', 'h', 'e', '-', 'C', 'o', 'n', 't', 'r', 'o', 'l', ':', ' ', 'm', 'a', 'x', '-', 'a', 'g', 'e', '=', '0', 0 };
							char _contentType[] = { 'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'T', 'y', 'p', 'e', ':', ' ', 'a', 'p', 'p', 'l', 'i', 'c', 'a', 't', 'i', 'o', 'n', '/', 'x', '-', 'w', 'w', 'w', '-', 'f', 'o', 'r', 'm', '-', 'u', 'r', 'l', 'e', 'n', 'c', 'o', 'd', 'e', 'd', 0 };
							char _contentLength[] = { 'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', 0 };
							char _connectionClose[] = { 'C', 'o', 'n', 'n', 'e', 'c', 't', 'i', 'o', 'n', ':', ' ', 'c', 'l', 'o', 's', 'e', 0 };
							char _transferEncoding[] = { 'T', 'r', 'a', 'n', 's', 'f', 'e', 'r', '-', 'E', 'n', 'c', 'o', 'd', 'i', 'n', 'g', ':', ' ', 'c', 'h', 'u', 'n', 'k', 'e', 'd', 0 };
							
							string request = _post + sPath + _http;
							request += _host + sHost + _rn;
							request += _userAgent + string(_rn);
							request += _acceptLanguage + string(_rn);
							request += _acceptCharset + string(_rn);
							request += _cacheControl + string(_rn);
							request += _contentType + string(_rn);
							request += _contentLength;
							request += temp;
							request += _rn;
							request += _connectionClose + string(_rn) + string(_rn);
							request += content;

							char sendBuffer[8192];
							memset(sendBuffer, 0, sizeof(sendBuffer));
							strcpy_s(sendBuffer, 8192, request.c_str());
							send(s, sendBuffer, static_cast<int>(request.size()+1), 0);
							string header;
							int bytes = 0;
							try
							{
								while((bytes = recv(s, buffer, 8190, 0)) > 0 )
								{
									len += bytes;

									string code(buffer);
									size_t pos = code.find(string(_rn) + string(_rn));
									if(pos != string::npos)
									{
										header = code.substr(0, pos);
										pos += 4;
										if(header.find(_transferEncoding) != string::npos)
										{
											pos = code.find(_rn, pos);
											pos += 2;
										}
										code = code.substr(pos);
									}
									
									webStream << code;

									if(buffer[bytes-1] == '\0')
										break;

									memset(buffer, 0, sizeof(buffer));
								}
							}catch(...)
							{
							//	EXCEPTION_LOG;
							}

							reply = webStream.str();
						}
						closesocket(s);
					}
				}
			}
		}
	}catch(...)
	{
	//	EXCEPTION_LOG;
	}

	VIRTUALIZER_TIGER_RED_END;

	return reply;
};

void ShowMessage(const char* caption, const char* format, ...)
{
	va_list va;
	va_start(va, format);
	char Msg[2048];
	vsprintf_s(Msg, sizeof(Msg), format, va);
	BYTE arrMessageBoxA[24] = { 77, 185, 101, 0, 115, 135, 115, 62, 97, 0, 103, 0, 101, 194, 66, 197, 111, 70, 120, 0, 65, 56, 0, 0 };
	char sMessageBoxA[12];
	UnpackString(arrMessageBoxA, sMessageBoxA, 24);
	typedef int (* _messageBoxA)(    __in_opt HWND hWnd,    __in_opt LPCSTR lpText,    __in_opt LPCSTR lpCaption,    __in UINT uType);
	
	BYTE arrUser32_dll[22] = { 85, 30, 115, 101, 101, 0, 114, 0, 51, 150, 50, 0, 46, 147, 100, 243, 108, 219, 108, 51, 0, 0 };
	char sUser32_dll[11];
	UnpackString(arrUser32_dll, sUser32_dll, 22);
	HMODULE hModule = GetModuleHandleA(sUser32_dll);
	_messageBoxA messageBoxA = (_messageBoxA)GetProcAddress(hModule, sMessageBoxA);
	messageBoxA(NULL, Msg, caption, MB_OK);
	va_end(va);
}

const unsigned char* Disassemble(const unsigned char* packet, const char* format, ...)
{
	typedef PUCHAR (*f)(const unsigned char*, const char*, va_list va);

	va_list va;
	va_start(va, format);
	const unsigned char* ret = f(0x61F1E0)(packet,format, va);
	va_end(va);

	return ret;
};

int Assemble(PCHAR buf, int bufLen, const char *format, ...)
{
	
	typedef int (*f)(PCHAR, int, const char*, va_list);
	
	va_list va;
	va_start(va, format);
	int nRet = f(0x61D8A0L)(buf, bufLen, format, va);
	va_end(va);

	return nRet;
};

bool CopyVMT(LPVOID *dst, LPVOID *src, size_t num)
{
	DWORD oldProtect = NULL;
	size_t size = num * sizeof(LPVOID);

	if (VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &oldProtect)!=0)
	{
		memcpy_s(dst, size, src, size);
		VirtualProtect(dst, size, oldProtect, &oldProtect);
		return true;
	}
	else
	{
		MessageBoxA(NULL, "CopyVMT() failed!", "(Error) L2Server_addon", MB_OK);
		return false;
	}
}

wstring StringToWString(const string& s)
{
	wstring temp(s.length(),L' ');
	copy(s.begin(), s.end(), temp.begin());
	return temp; 
}


string WStringToString(const wstring& s)
{
	string temp(s.length(), ' ');
	copy(s.begin(), s.end(), temp.begin());
	return temp; 
}

string HexToString(int len, LPBYTE lpArr)
{
	string str;
	char cTmp[8];
	for(int n=0;n<len;n++)
	{
		memset(cTmp, 0, 8);
		sprintf_s(cTmp, 8, "%x", lpArr[n]);
		str += cTmp;
	}
	return str;
}

static const std::string base64_chars = 
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";


static inline bool is_base64(unsigned char c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
  std::string ret;
  int i = 0;
  int j = 0;
  unsigned char char_array_3[3];
  unsigned char char_array_4[4];

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

std::string base64_decode(std::string const& encoded_string) {
  int in_len = (int)encoded_string.size();
  int i = 0;
  int j = 0;
  int in_ = 0;
  unsigned char char_array_4[4], char_array_3[3];
  std::string ret;

  while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
    char_array_4[i++] = encoded_string[in_]; in_++;
    if (i ==4) {
      for (i = 0; i <4; i++)
        char_array_4[i] = (unsigned char)base64_chars.find(char_array_4[i]);

      char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

      for (i = 0; (i < 3); i++)
        ret += char_array_3[i];
      i = 0;
    }
  }

  if (i) {
    for (j = i; j <4; j++)
      char_array_4[j] = 0;

    for (j = 0; j <4; j++)
      char_array_4[j] = (unsigned char)base64_chars.find(char_array_4[j]);

    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

    for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
  }

  return ret;
}

void MovLogFiles(const char* sLogDir)
{
	list<string> lLogs;
	CreateDirectoryA(sLogDir, NULL);
	WIN32_FIND_DATAA info;
	HANDLE hFile = 0;
	char szDir[265];
	GetCurrentDirectoryA(260, szDir);
	strcat(szDir, "\\*");
	hFile = FindFirstFileA(szDir, &info);
	if(hFile)
	{
		do
		{
			if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
			 
			}
			else
			{
				if(strcmp(info.cFileName, "LinError.txt"))
				{
					if(strstr(info.cFileName, "LinError") || strstr(info.cFileName, ".dmp"))
					{
						lLogs.push_back(info.cFileName);
					}
				}
				if(strcmp(info.cFileName, "ExtError.txt"))
				{
					if(strstr(info.cFileName, "ExtError.txt."))
					{
						lLogs.push_back(info.cFileName);
					}
				}
			}
		}
		while (FindNextFileA(hFile, &info) != 0);
		FindClose(hFile);
	}
	if(lLogs.size() > 0)
	{
		for(list<string>::iterator Iter = lLogs.begin();Iter!=lLogs.end();Iter++)
		{
			char sNewFile[512];
			strcpy(sNewFile, sLogDir);
			strcat(sNewFile, "\\");
			strcat(sNewFile, Iter->c_str());
			MoveFileA(Iter->c_str(), sNewFile);
		}
	}
};

time_t ConvertTime(int year, int month, int day, int hour, int minute, int second)
{
	time_t rawtime = time(0);
	tm *timeinfo = localtime ( &rawtime );
	timeinfo->tm_year = year - 1900;
	timeinfo->tm_mon = month - 1;
	timeinfo->tm_mday = day;
	timeinfo->tm_hour = hour;
	timeinfo->tm_min = minute;
	timeinfo->tm_sec = second;

	return mktime ( timeinfo );
}

bool AppendToFileW(wstring wFile, wstring wData)
{
	HANDLE hAppend; 
	DWORD dwBytesToWrite = (DWORD)(wData.size()*2);
    DWORD dwBytesWritten = 0;
    BOOL bErrorFlag = FALSE;

	hAppend = CreateFileW(wFile.c_str(),
                       FILE_APPEND_DATA,          // open for writing
                       FILE_SHARE_READ,                      // do not share
                       NULL,                   // default security
                       OPEN_ALWAYS,             // create new file only
                       FILE_ATTRIBUTE_NORMAL,  // normal file
                       NULL);                  // no attr. template

    if (hAppend == INVALID_HANDLE_VALUE) 
    { 
		return false;
    }

	DWORD dwPos = SetFilePointer(hAppend, 0, NULL, FILE_END);
    LockFile(hAppend, dwPos, 0, dwBytesToWrite, 0);
	WriteFile(hAppend, wData.c_str(), dwBytesToWrite, &dwBytesWritten, NULL);
    UnlockFile(hAppend, dwPos, 0, dwBytesToWrite, 0);

    CloseHandle(hAppend);
	return true;
}

wstring CreateSpawnEntry(wstring territoryName, INT32 range, IVector vPos, UINT heading, wstring npcName, UINT count)
{
	/*
	territory_begin	[oren16_npc2218_011]	{{85075;17375;-3559;-3359};{85577;17375;-3559;-3359};{85584;17575;-3559;-3359};{85055;17575;-3559;-3359}}	territory_end
	npcmaker_ex_begin	[oren16_npc2218_011]	name=[oren16_npc2218_01101]	ai=[default_maker]	maximum_npc=1
	npc_ex_begin	[guard_yening]	pos={85149;17458;-3511;16384}	total=1	respawn=1min	npc_ex_end
	npcmaker_ex_end
	*/
	wstringstream wData;
	wData << L"territory_begin	[" << territoryName << ContadorSpawns << L"]	{{"
		<< vPos.x - range -10 << L";" << vPos.y - range - 10 << L";" << vPos.z - range - 10 << L";" << vPos.z + range + 10 << L"};{"
		<< vPos.x + range +10 << L";" << vPos.y - range - 10 << L";" << vPos.z - range - 10 << L";" << vPos.z + range + 10 << L"};{"
		<< vPos.x + range +10 << L";" << vPos.y + range + 10 << L";" << vPos.z - range - 10 << L";" << vPos.z + range + 10 << L"};{"
		<< vPos.x - range -10 << L";" << vPos.y + range + 10 << L";" << vPos.z - range - 10 << L";" << vPos.z + range + 10 << L"}}	territory_end" << "\r\n";
	wData << L"npcmaker_begin	[" << territoryName << ContadorSpawns << L"]	initial_spawn = all	maximum_npc=" << count << "\r\n";
	wData << L"npc_begin	[" << npcName << L"]	pos={" << vPos.x << L";" << vPos.y << L";" << vPos.z << L";" << heading << L"}	total=" << count << L"	respawn=1min	npc_end" << "\r\n";
	wData << L"npcmaker_end" << "\r\n\r\n";

	ContadorSpawns++;

	return wData.str();
}

DWORD ReadFileBinary(LPCWSTR lpFileName, LPBYTE& lpOut)
{
	UINT64 FileSize = 0;
	_WIN32_FIND_DATAW FileData;
	HANDLE hFile = FindFirstFileW(lpFileName, &FileData);
	if(hFile != INVALID_HANDLE_VALUE)
	{
		FileSize = MAXDWORD;
		FileSize += 1;
		FileSize *= FileData.nFileSizeHigh;
		FileSize += FileData.nFileSizeLow;
	}
	FindClose(hFile);
	DWORD readed = 0;
	hFile = CreateFileW(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(hFile != INVALID_HANDLE_VALUE)
	{
		lpOut = new BYTE[FileSize+2];
		memset(lpOut, 0, FileSize+2);
		if(ReadFile(hFile, lpOut, static_cast<DWORD>(FileSize), &readed, NULL))
		{
			WaitForSingleObject(hFile, 5000);
		}
	}
	CloseHandle(hFile);
	return readed;
}

DWORD ReadFileBinary(LPCSTR lpFileName, LPBYTE lpOut, DWORD maxLen)
{
	INT64 FileSize = 0;
	_WIN32_FIND_DATAA FileData;
	HANDLE hFile = FindFirstFileA(lpFileName, &FileData);
	if(hFile != INVALID_HANDLE_VALUE)
	{
		FileSize = MAXDWORD;
		FileSize += 1;
		FileSize *= FileData.nFileSizeHigh;
		FileSize += FileData.nFileSizeLow;
	}
	FindClose(hFile);
	if(maxLen > FileSize)
	{
		hFile = CreateFileA(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if(hFile != INVALID_HANDLE_VALUE)
		{
			memset(lpOut, 0, maxLen);
			if(ReadFile(hFile, lpOut, static_cast<DWORD>(FileSize), &maxLen, NULL))
			{
				WaitForSingleObject(hFile, 5000);
			}
		}
		CloseHandle(hFile);
		return maxLen;
	}

	return 0;
}

void Crypt(LPBYTE lpIn, LPBYTE lpOut, int len)
{
	BYTE crypt = 0;
	for(int n=0;n<len;n++)
	{
		crypt += n;
		BYTE xorKey = crypt % 223;
		lpOut[n] = lpIn[n] ^ xorKey;
	}
}


void Utils::ShowMessage(LPTSTR lpCaption, LPTSTR lpFormat, ...)
{
	TCHAR buff[8192];
	va_list va;
	va_start(va, lpFormat);
	_vstprintf_s(buff, 8190, lpFormat, va);
	MessageBox(NULL, buff, lpCaption, MB_OK);
	va_end(va);
}

int Utils::VAssemble(char* buff, int len, const char* format, va_list va)
{
	typedef int (*f)(char*, int, const char*, va_list);
	return f(0x61D8A0L)(buff, len, format, va);
}

const unsigned char* Utils::Disassemble(const unsigned char* packet, const char* format, ...)
{
	typedef PUCHAR (*f)(const unsigned char*, const char*, va_list va);

	va_list va;
	va_start(va, format);
	const unsigned char* ret = f(0x61F1E0)(packet,format, va);
	va_end(va);

	return ret;
};

tstring Utils::ReplaceString(tstring baseStr, tstring oldStr, tstring newStr, bool all)
{
	size_t pos = baseStr.find(oldStr);
	while(pos != tstring::npos)
	{
		baseStr = baseStr.replace(pos, oldStr.size(), newStr);
		if(all)
			pos = baseStr.find(oldStr);
		else
			pos = tstring::npos;
	}
	return baseStr;
}

wstring Utils::GetClassByID(int nClass)
{
	wstring NewClass = L"ERROR";

	if(nClass == 2)						NewClass = L"Gladiator";	
	if(nClass == 3)						NewClass = L"Warlord";				
	if(nClass == 5)						NewClass = L"Paladin";				
	if(nClass == 6)						NewClass = L"DarkAvenger";			
	if(nClass == 8)						NewClass = L"TreasureHunter";		
	if(nClass == 9)						NewClass = L"Hawkeye";			
	if(nClass == 12)					NewClass = L"Sorceror";		
	if(nClass == 13)					NewClass = L"Necromancer";		
	if(nClass == 14)					NewClass = L"Warlock";
	if(nClass == 16)					NewClass = L"Bishop";		
	if(nClass == 17)					NewClass = L"Prophet";			
	if(nClass == 20)					NewClass = L"TempleKnight";			
	if(nClass == 21)					NewClass = L"SwordSinger";		
	if(nClass == 23)					NewClass = L"PlainsWalker";	
	if(nClass == 24)					NewClass = L"SilverRanger";	
	if(nClass == 27)					NewClass = L"SpellSinger";			
	if(nClass == 28)					NewClass = L"ElementalSummon";		
	if(nClass == 30)					NewClass = L"Elder";		
	if(nClass == 33)					NewClass = L"ShillienKnight";			
	if(nClass == 34)					NewClass = L"BladeDancer";				
	if(nClass == 36)					NewClass = L"AbyssWalker";		
	if(nClass == 37)					NewClass = L"PhantomRanger";			
	if(nClass == 40)					NewClass = L"Spellhowler";				
	if(nClass == 41)					NewClass = L"PhantomSummoner";			
	if(nClass == 43)					NewClass = L"ShillienElder";			
	if(nClass == 46)					NewClass = L"Destroyer";				
	if(nClass == 48)					NewClass = L"Tyrant";					
	if(nClass == 51)					NewClass = L"Overlord";			
	if(nClass == 52)					NewClass = L"Warcryer";				
	if(nClass == 55)					NewClass = L"BountyHunter";			
	if(nClass == 57)					NewClass = L"Warsmith";	

	if(nClass == 88)					NewClass = L"Duelist";	
	if(nClass == 89)					NewClass = L"Dreadnought";	
	if(nClass == 90)					NewClass = L"PhoenixKnight";	
	if(nClass == 91)					NewClass = L"HellKnight";	
	if(nClass == 92)					NewClass = L"Sagittarius";	
	if(nClass == 93)					NewClass = L"Adventurer";	
	if(nClass == 94)					NewClass = L"Archmage";	
	if(nClass == 95)					NewClass = L"Soultaker";	
	if(nClass == 96)					NewClass = L"ArcanaLord";	
	if(nClass == 97)					NewClass = L"Cardinal";	
	if(nClass == 98)					NewClass = L"Hierophant";	
	if(nClass == 99)					NewClass = L"EvasTemplar";	
	if(nClass == 100)					NewClass = L"SwordMuse";	
	if(nClass == 101)					NewClass = L"WindRider";	
	if(nClass == 102)					NewClass = L"Moon.Sentinel";	
	if(nClass == 103)					NewClass = L"MysticMuse";	
	if(nClass == 104)					NewClass = L"ElementalMaster";	
	if(nClass == 105)					NewClass = L"EvasSaint";	
	if(nClass == 106)					NewClass = L"ShillienTemplar";	
	if(nClass == 107)					NewClass = L"SpectralDancer";	
	if(nClass == 108)					NewClass = L"GhostHunter";	
	if(nClass == 109)					NewClass = L"GhostSentinel";	
	if(nClass == 110)					NewClass = L"StormScreamer";	
	if(nClass == 111)					NewClass = L"SpectralMaster";	
	if(nClass == 112)					NewClass = L"ShillienSaint";	
	if(nClass == 113)					NewClass = L"Titan";	
	if(nClass == 114)					NewClass = L"GrandKhavatari";	
	if(nClass == 115)					NewClass = L"Dominator";	
	if(nClass == 116)					NewClass = L"Doomcryer";	
	if(nClass == 117)					NewClass = L"FortuneSeeker";	
	if(nClass == 118)					NewClass = L"Maestro";	

	return NewClass;
}

int Utils::GetIDByClass(wstring NewClass)
{
	int nClass = -1;

	if( NewClass == L"Gladiator")				nClass = 2;
	if( NewClass == L"Warlord")					nClass = 3;
	if( NewClass == L"Paladin")					nClass = 5;
	if( NewClass == L"DarkAvenger")				nClass = 6;
	if( NewClass == L"TreasureHunter")			nClass = 8;
	if( NewClass == L"Hawkeye")					nClass = 9;
	if( NewClass == L"Sorceror")				nClass = 12;
	if( NewClass == L"Necromancer")				nClass = 13;
	if( NewClass == L"Warlock")					nClass = 14;
	if( NewClass == L"Bishop")					nClass = 16;
	if( NewClass == L"Prophet")					nClass = 17;
	if( NewClass == L"TempleKnight")			nClass = 20;
	if( NewClass == L"SwordSinger")				nClass = 21;
	if( NewClass == L"PlainsWalker")			nClass = 23;
	if( NewClass == L"SilverRanger")			nClass = 24;
	if( NewClass == L"SpellSinger")				nClass = 27;
	if( NewClass == L"ElementalSummon")			nClass = 28;
	if( NewClass == L"Elder")					nClass = 30;
	if( NewClass == L"ShillienKnight")			nClass = 33;
	if( NewClass == L"BladeDancer")				nClass = 34;
	if( NewClass == L"AbyssWalker")				nClass = 36;
	if( NewClass == L"PhantomRanger")			nClass = 37;
	if( NewClass == L"Spellhowler")				nClass = 40;
	if( NewClass == L"PhantomSummoner")			nClass = 41;
	if( NewClass == L"ShillienElder")			nClass = 43;
	if( NewClass == L"Destroyer")				nClass = 46;
	if( NewClass == L"Tyrant")					nClass = 48;
	if( NewClass == L"Overlord")				nClass = 51;
	if( NewClass == L"Warcryer")				nClass = 52;
	if( NewClass == L"BountyHunter")			nClass = 55;
	if( NewClass == L"Warsmith")				nClass = 57;

	if( NewClass == L"Duelist")					nClass = 88;
	if( NewClass == L"Dreadnought")				nClass = 89;
	if( NewClass == L"PhoenixKnight")			nClass = 90;
	if( NewClass == L"HellKnight")				nClass = 91;
	if( NewClass == L"Sagittarius")				nClass = 92;
	if( NewClass == L"Adventurer")				nClass = 93;
	if( NewClass == L"Archmage")				nClass = 94;
	if( NewClass == L"Soultaker")				nClass = 95;
	if( NewClass == L"ArcanaLord")				nClass = 96;
	if( NewClass == L"Cardinal")				nClass = 97;
	if( NewClass == L"Hierophant")				nClass = 98;
	if( NewClass == L"EvasTemplar")				nClass = 99;
	if( NewClass == L"SwordMuse")				nClass = 100;
	if( NewClass == L"WindRider")				nClass = 101;
	if( NewClass == L"Moon.Sentinel")			nClass = 102;
	if( NewClass == L"MysticMuse")				nClass = 103;
	if( NewClass == L"ElementalMaster")			nClass = 104;
	if( NewClass == L"EvasSaint")				nClass = 105;
	if( NewClass == L"ShillienTemplar")			nClass = 106;
	if( NewClass == L"SpectralDancer")			nClass = 107;
	if( NewClass == L"GhostHunter")				nClass = 108;
	if( NewClass == L"GhostSentinel")			nClass = 109;
	if( NewClass == L"StormScreamer")			nClass = 110;
	if( NewClass == L"SpectralMaster")			nClass = 111;
	if( NewClass == L"ShillienSaint")			nClass = 112;
	if( NewClass == L"Titan")					nClass = 113;
	if( NewClass == L"GrandKhavatari")			nClass = 114;
	if( NewClass == L"Dominator")				nClass = 115;
	if( NewClass == L"Doomcryer")				nClass = 116;
	if( NewClass == L"FortuneSeeker")			nClass = 117;
	if( NewClass == L"Maestro")					nClass = 118;

	return nClass;
}


int Utils::GetIDdeSegundaToTercera(int Tercera)
{
	int nClass = -1;

	if(Tercera == 88)					nClass = 2;
	if(Tercera == 89)					nClass = 3;
	if(Tercera == 90)					nClass = 5;
	if(Tercera == 91)					nClass = 6;
	if(Tercera == 92)					nClass = 9;
	if(Tercera == 93)					nClass = 8;
	if(Tercera == 94)					nClass = 12;
	if(Tercera == 95)					nClass = 13;
	if(Tercera == 96)					nClass = 14;
	if(Tercera == 97)					nClass = 16;
	if(Tercera == 98)					nClass = 17;
	if(Tercera == 99)					nClass = 20;
	if(Tercera == 100)					nClass = 21;
	if(Tercera == 101)					nClass = 23;
	if(Tercera == 102)					nClass = 24;
	if(Tercera == 103)					nClass = 27;
	if(Tercera == 104)					nClass = 28;
	if(Tercera == 105)					nClass = 30;
	if(Tercera == 106)					nClass = 33;
	if(Tercera == 107)					nClass = 34;
	if(Tercera == 108)					nClass = 36;
	if(Tercera == 109)					nClass = 37;
	if(Tercera == 110)					nClass = 40;
	if(Tercera == 111)					nClass = 41;
	if(Tercera == 112)					nClass = 43;
	if(Tercera == 113)					nClass = 46;
	if(Tercera == 114)					nClass = 48;
	if(Tercera == 115)					nClass = 51;
	if(Tercera == 116)					nClass = 52;
	if(Tercera == 117)					nClass = 55;
	if(Tercera == 118)					nClass = 57;

	return nClass;
}


void Utils::BroadcastToAllUser_Announce(const WCHAR* wAnnounce)
{
    int MsgId = 0;
    std::wstring wAnnounce2;

    const std::wstring wDelimiter = L";;;";
    size_t nPos = wDelimiter.size();
    size_t nDelimiterPos = std::wstring(wAnnounce).find(wDelimiter);
    if (nDelimiterPos != std::wstring::npos)
    {
        std::wstringstream ss(std::wstring(wAnnounce).substr(0, nDelimiterPos));
        ss >> MsgId;
        wAnnounce2 = std::wstring(wAnnounce).substr(nDelimiterPos + nPos);
    }
    else
    {
        wAnnounce2 = wAnnounce;
    }

    if (MsgId == 0)
    {
        typedef void (*f)(const WCHAR*);
        f(0x823660L)(wAnnounce2.c_str());
    }
    else
    {
        CSystemMessage msg(MsgId);
        msg.AddText(wAnnounce2.c_str());
        L2Server::BroadcastToAllUser(msg.GetSize(), msg.GetBuff());  
    }
}

void Utils::BroadcastToAllUser_AnnounceDist(const WCHAR* wAnnounce, int dist, FVector pos)
{
    int MsgId = 0;
    std::wstring wAnnounce2;

    const std::wstring wDelimiter = L";;;";
    size_t nPos = wDelimiter.size();
    size_t nDelimiterPos = std::wstring(wAnnounce).find(wDelimiter);
    if (nDelimiterPos != std::wstring::npos)
    {
        std::wstringstream ss(std::wstring(wAnnounce).substr(0, nDelimiterPos));
        ss >> MsgId;
        wAnnounce2 = std::wstring(wAnnounce).substr(nDelimiterPos + nPos);
    }
    else
    {
        wAnnounce2 = wAnnounce;
    }

    if (MsgId == 0)
    {
        typedef void (*f)(const WCHAR*);
        f(0x823660L)(wAnnounce2.c_str());
    }
    else
    {
        CSystemMessage msg(MsgId);
        msg.AddText(wAnnounce2.c_str());
        //L2Server::BroadcastToAllUser(msg.GetSize(), msg.GetBuff());  
		L2Server::BroadcastToNeighborDist(NULL, &pos, dist, msg.GetSize(), msg.GetBuff());
    }
}

void Utils::WriteDWORD(UINT64 address, DWORD value)
{
	LPDWORD lpAddr = reinterpret_cast<LPDWORD>(address);
	DWORD old;
	if(VirtualProtect(lpAddr, 4, PAGE_EXECUTE_READWRITE, &old))
	{
		(*lpAddr) = value;
		VirtualProtect(lpAddr, 4, old, &old);
	}
}

LPVOID Utils::WriteCall(UINT64 address, LPVOID function, UINT nops, LPBYTE lpOrgMemory, BOOL extended)
{
	LPVOID lpRet = 0;
	try
	{
		UINT size = 5 + nops;
		if(extended)
		{
			LPBYTE pMemory = static_cast<LPBYTE>(VirtualAlloc(0, (size + 5), MEM_COMMIT, PAGE_EXECUTE_READWRITE));
			if(pMemory)
			{
				HookMem hm;
				LPBYTE lpAddress = reinterpret_cast<LPBYTE>(address);
				for(UINT n=0;n<size;n++)
				{
					pMemory[n] = lpAddress[n];
					if( n < 5 )
					{
						hm.byte.p[n] = lpAddress[n];
					}
				}

				if(hm.full.opCode == 0xE8 || hm.full.opCode == 0xE9)
				{
					//reallocate addr
					UINT64 addr = hm.full.addr;
					addr += (address + 5);
					
					hm.full.addr = static_cast<UINT>(addr - (reinterpret_cast<UINT64>(pMemory) + 5));

					for(int n=0;n<5;n++)
					{
						pMemory[n] = hm.byte.p[n];
					}
				}
				
				WriteJump(reinterpret_cast<UINT64>(&pMemory[5]), reinterpret_cast<LPVOID>(address + size));
				WriteJump(address, function);
				lpRet = pMemory;
			}else
			{
				ShowMessage(_T("VoteMod"), _T("Cannot allocate memory! (%p)"), address);
			}
		}else
		{
			LPBYTE lpAddress = reinterpret_cast<LPBYTE>(address);
			HookMem mem;
			mem.full.opCode = 0xE8;	//CALL
			UINT64 fundAddr = reinterpret_cast<UINT64>(function);
			fundAddr -= (address + 5);
			mem.full.addr = static_cast<UINT>(fundAddr);

			DWORD oldProtect = 0;
			if(VirtualProtect(lpAddress, size, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				for(SIZE_T n = 0; n < size ; n++)
				{
					if(n < 5)
					{
						lpAddress[n] = mem.byte.p[n];
					}else
					{
						lpAddress[n] = 0x90;
					}
				}
				VirtualProtect(lpAddress, size, oldProtect, &oldProtect);
			}
		}
	}catch(...)
	{
		EXCEPTION_LOG_PARAM(address);
	}
	return lpRet;
}

LPVOID Utils::WriteJump(UINT64 address, LPVOID function, UINT nops, LPBYTE lpOrgMemory, BOOL extended)
{
	LPVOID lpRet = 0;
	try
	{
		UINT size = 5 + nops;
		if(extended)
		{
			LPBYTE pMemory = static_cast<LPBYTE>(VirtualAlloc(0, (size + 5), MEM_COMMIT, PAGE_EXECUTE_READWRITE));
			if(pMemory)
			{
				HookMem hm;
				LPBYTE lpAddress = reinterpret_cast<LPBYTE>(address);
				for(UINT n=0;n<size;n++)
				{
					pMemory[n] = lpAddress[n];
					if( n < 5 )
					{
						hm.byte.p[n] = lpAddress[n];
					}
				}

				if(hm.full.opCode == 0xE8 || hm.full.opCode == 0xE9)
				{
					//reallocate addr
					UINT64 addr = hm.full.addr;
					addr += (address + 5);
					
					hm.full.addr = static_cast<UINT>(addr - (reinterpret_cast<UINT64>(pMemory) + 5));

					for(int n=0;n<5;n++)
					{
						pMemory[n] = hm.byte.p[n];
					}
				}
				
				WriteJump(reinterpret_cast<UINT64>(&pMemory[5]), reinterpret_cast<LPVOID>(address + size));
				WriteJump(address, function);
				lpRet = pMemory;
			}else
			{
				ShowMessage(_T("VoteMod"), _T("Cannot allocate memory! (%p)"), address);
			}
		}else
		{
			LPBYTE lpAddress = reinterpret_cast<LPBYTE>(address);
			HookMem mem;
			mem.full.opCode = 0xE9;	//Jump
			UINT64 fundAddr = reinterpret_cast<UINT64>(function);
			fundAddr -= (address + 5);
			mem.full.addr = static_cast<UINT>(fundAddr);

			DWORD oldProtect = 0;
			if(VirtualProtect(lpAddress, size, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				for(SIZE_T n = 0; n < size ; n++)
				{
					if(n < 5)
					{
						lpAddress[n] = mem.byte.p[n];
					}else
					{
						lpAddress[n] = 0x90;
					}
				}
				VirtualProtect(lpAddress, size, oldProtect, &oldProtect);
			}
		}
	}catch(...)
	{
		EXCEPTION_LOG_PARAM(address);
	}
	return lpRet;
}

wstring Utils::Trim(wstring str)
{
	size_t pos = str.find_first_of(L"\t\n\r\v ");
	while(pos!=wstring::npos)
	{
		str.erase(pos, 1);
		pos = str.find_first_of(L"\t\n\r\v ");
	}
	return str;
}

int Utils::GetBypassValueInt(wstring wBypass, wstring wSub, int defaultValue)
{
	wstring wRet;
	//Remove white spaces from bypass
	wBypass = Trim(wBypass);
	//Find wSub
	size_t pos = wBypass.find(L"?");
	if(pos!=wstring::npos)
	{
		pos = wBypass.find(wSub, pos);
		if(pos!=wstring::npos)
		{
			wBypass = wBypass.substr(pos, (wBypass.size() - pos));
			pos = wBypass.find(L"&");
			if(pos!=wstring::npos)
			{
				wBypass = wBypass.substr(0, pos);
			}

			pos = wBypass.find(L"=");
			if(pos == wstring::npos)
			{
				//not found
				return defaultValue;
			}
			pos++;

			wRet = wBypass.substr(pos, (wBypass.size() - pos));
		}
	}

	wstringstream wstr;
	wstr << wRet;
	int ret = defaultValue;
	wstr >> ret;
	return ret;
}

double GetPrivateProfileDouble(LPCTSTR lpAppName, LPCTSTR lpKeyName, double defaultValue, LPCTSTR lpFileName)
{
	TCHAR buf[64] = { 0 }, *ptr = 0;
    if(GetPrivateProfileString(lpAppName,lpKeyName, 0, buf, 63, lpFileName))
	{
		double outval=_tcstod(buf, &ptr);
		if(ptr!=buf)
			return outval;
	}
	return defaultValue; 
}

wstring Utils::ReplaceStringW(wstring baseStr, wstring oldStr, wstring newStr, bool all)
{
	size_t pos = baseStr.find(oldStr);
	while(pos != string::npos)
	{
		baseStr = baseStr.replace(pos, oldStr.size(), newStr);
		if(all)
			pos = baseStr.find(oldStr);
		else
			pos = wstring::npos;
	}
	return baseStr;
}

wstring Utils::ReplaceString(wstring baseStr, wstring oldStr, UINT nNew, bool all)
{
	WCHAR newStr[16] = { 0 };
	_itow_s(nNew, newStr, 16, 10);
	size_t pos = baseStr.find(oldStr);
	while(pos != wstring::npos)
	{
		baseStr = baseStr.replace(pos, oldStr.size(), newStr);
		if(all)
			pos = baseStr.find(oldStr);
		else
			pos = wstring::npos;
	}
	return baseStr;
}

wstring Utils::ReplaceStringD(wstring baseStr, wstring oldStr, double nNew, bool all)
{
	char newStr1[16] = { 0 };
	//_itow_s(nNew, newStr, 16, 10);
	//errno_t _itow_s( int value, wchar_t (&buffer)[size], int radix );
	_gcvt_s(newStr1, 16, nNew, 4);

	wstring newStr = StringToWString(newStr1);

	size_t pos = baseStr.find(oldStr);
	while(pos != wstring::npos)
	{
		baseStr = baseStr.replace(pos, oldStr.size(), newStr);
		if(all)
			pos = baseStr.find(oldStr);
		else
			pos = wstring::npos;
	}
	return baseStr;
}

string Utils::ReplaceStringA(string baseStr, string oldStr, string newStr, bool all)
{
	size_t pos = baseStr.find(oldStr);
	while(pos != string::npos)
	{
		baseStr = baseStr.replace(pos, oldStr.size(), newStr);
		if(all)
			pos = baseStr.find(oldStr);
		else
			pos = string::npos;
	}
	return baseStr;
}

string Utils::IntToString(int a)
{
    ostringstream temp;
    temp<<a;
    return temp.str();
}

wstring Utils::IntToWString(int a)
{
	wstringstream wss;
	wss << a;
	return wss.str();
}

wstring Utils::RandomString(int len)
{
  /* srand(time(0));
   wstring str = L"0123456789abcdefghijklmnopqrstuvwxyz";
   wstring newstr;
   int pos;
   while(newstr.size() != len) {
    pos = ((rand() % (str.size() - 1)));
    newstr += str.substr(pos,1);
   }*/


	/* Decleration and initialization of static constant string type variable */
	static const wstring charList = L"0123456789abcdefghijklmnopqrstuvwxyz";

	/* srand() initialize random number generator */
	/* time() for get current time */
	//srand(time(0));
	wstring alphanumeric = L"";
	
	for(int i = 0; i < len; i++) {
		/* rand() generate random number */
		alphanumeric += charList [rand() % charList.size()];
	}

   return alphanumeric;
}

std::vector<BYTE> Utils::HexToBytes(const wstring& hex) 
{
  vector<BYTE> bytes;
  for (unsigned int i = 0; i < hex.length(); i += 2) 
  {
    wstring byteString = hex.substr(i, 2);
    BYTE byte = (BYTE) wcstol(byteString.c_str(), NULL, 16);
    bytes.push_back(byte);
  }

  return bytes;
}

std::wstring Utils::FormatWithCommas(UINT value)
{
    std::wstringstream ss;
    ss.imbue(std::locale(""));
    ss << std::fixed << value;
    return ss.str();
}




// Función para normalizar una cadena ancha (reemplaza caracteres similares)
std::wstring Utils::NormalizeWString(const std::wstring& input) {
    std::wstring normalized = input;
    // Reemplaza 'O' por '0' y convierte a minúsculas
    for (size_t i = 0; i < normalized.length(); i++) {
        if (normalized[i] == L'0') {
            normalized[i] = L'o';
		} else if (normalized[i] == L'4') {
            normalized[i] = L'a';
        } else {
            normalized[i] = towlower(normalized[i]);
        }
    }
    return normalized;
}

// Función para verificar si una cadena contiene palabras prohibidas
bool Utils::ContainProhibitedPhrase(const std::wstring& input, const std::set<std::wstring>& prohibitedPhrases) {
    std::wstring normalizedInput = NormalizeWString(input);
    for (std::set<std::wstring>::const_iterator it = prohibitedPhrases.begin(); it != prohibitedPhrases.end(); ++it) {
        std::wstring normalizedPhrase = NormalizeWString(*it);
        if (normalizedInput.find(normalizedPhrase) != std::wstring::npos) {
            return true; // Se encontró una coincidencia prohibida
        }
    }
    return false; // No se encontraron coincidencias prohibidas
}


	wstring Utils::ReplaceChar(wstring wStr, wstring wOld, wstring wNew)
	{
		size_t pos = wStr.find(wOld);
		while(pos != wstring::npos)
		{
			wStr.replace(pos, wOld.size(), wNew);
			pos = wStr.find(wOld);
		}
		return wStr;
	}
