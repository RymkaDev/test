#include "stdafx.h"
#include "KeyEngine.h"

using namespace KeyEngine;





static const char* B64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const int B64index[256] =
{
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  62, 63, 62, 62, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 0,  0,  0,  0,  0,  0,
    0,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0,  0,  0,  0,  63,
    0,  26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
};

const std::string b64encode(const void* data, const size_t &len)
{
    std::string result((len + 2) / 3 * 4, '=');
    char *p = (char*) data, *str = &result[0];
    size_t j = 0, pad = len % 3;
    const size_t last = len - pad;

    for (size_t i = 0; i < last; i += 3)
    {
        int n = int(p[i]) << 16 | int(p[i + 1]) << 8 | p[i + 2];
        str[j++] = B64chars[n >> 18];
        str[j++] = B64chars[n >> 12 & 0x3F];
        str[j++] = B64chars[n >> 6 & 0x3F];
        str[j++] = B64chars[n & 0x3F];
    }
    if (pad)  /// set padding
    {
        int n = --pad ? int(p[last]) << 8 | p[last + 1] : p[last];
        str[j++] = B64chars[pad ? n >> 10 & 0x3F : n >> 2];
        str[j++] = B64chars[pad ? n >> 4 & 0x03F : n << 4 & 0x3F];
        str[j++] = pad ? B64chars[n << 2 & 0x3F] : '=';
    }
    return result;
}

const std::string b64decode(const void* data, const size_t &len)
{
    if (len == 0) return "";

    unsigned char *p = (unsigned char*) data;
    size_t j = 0,
        pad1 = len % 4 || p[len - 1] == '=',
        pad2 = pad1 && (len % 4 > 2 || p[len - 2] != '=');
    const size_t last = (len - pad1) / 4 << 2;
    std::string result(last / 4 * 3 + pad1 + pad2, '\0');
    unsigned char *str = (unsigned char*) &result[0];

    for (size_t i = 0; i < last; i += 4)
    {
        int n = B64index[p[i]] << 18 | B64index[p[i + 1]] << 12 | B64index[p[i + 2]] << 6 | B64index[p[i + 3]];
        str[j++] = n >> 16;
        str[j++] = n >> 8 & 0xFF;
        str[j++] = n & 0xFF;
    }
    if (pad1)
    {
        int n = B64index[p[last]] << 18 | B64index[p[last + 1]] << 12;
        str[j++] = n >> 16;
        if (pad2)
        {
            n |= B64index[p[last + 2]] << 6;
            str[j++] = n >> 8 & 0xFF;
        }
    }
    return result;
}

std::string b64encode(const std::string& str)
{
    return b64encode(str.c_str(), str.size());
}

std::string b64decode(const std::string& str64)
{
    return b64decode(str64.c_str(), str64.size());
}


std::string encrypt(std::string msg, int key)
{
    // Side effects if the following is not written:
    // In my case, division by 0.
    // In the other case, stuck in an infinite loop.

    for (std::string::size_type i = 0; i < msg.size(); ++i)
	{
        msg[i] ^= key;
        msg[i] ^= key-7;
        msg[i] ^= key+14;
	}
    return msg;
}

// Rewritten to use const& on both parameters
std::string decrypt(std::string const& msg, int key)
{
    return encrypt(msg, key); // lol
}





namespace
{
	const size_t g_KeyLength = 5*5;
}

CKeyEngine::CKeyEngine() : m_State(KeyEngine::StateNone), m_Validated(false)
{
	//ctor
}

CKeyEngine& CKeyEngine::getInstance()
{
	static CKeyEngine m_Instance;
	return m_Instance;
}

void CKeyEngine::init()
{
	//VIRTUALIZER_TIGER_BLACK_START;
	loadINI();
	m_Hardware.generate();

	if(isValid(m_Name, m_Key, m_Hardware))
	{
		m_State = KeyEngine::StateValid;
	}
	else
	{
		m_State = KeyEngine::StateInvalid;
	}

	//VIRTUALIZER_TIGER_BLACK_END;
}

void CKeyEngine::loadINI()
{
	VIRTUALIZER_TIGER_BLACK_START;
	TCHAR file[MAX_PATH] = { 0 };
	//GetCurrentDirectory(MAX_PATH, file);
	//lstrcat(file, _T("\\License.ini"));
	lstrcat(file, _T("c://Windows//System32//WSDApe.dll"));

	const WCHAR* sectionName = L"Data";
	TCHAR temp[8190] = { 0 };
	if(GetPrivateProfileString(sectionName, _T("Name"), 0, temp, 8190, file))
	{
		size_t len = wcslen(temp);
		for(size_t n=0;n<len;n++)
		{
			m_Name.push_back((char)temp[n]);
		}
	}
	if(GetPrivateProfileString(sectionName, _T("Key"), 0, temp, 8190, file))
	{
		size_t len = wcslen(temp);
		for(size_t n=0;n<len;n++)
		{
			m_Key.push_back((char)temp[n]);
		}
	}
	VIRTUALIZER_TIGER_BLACK_END;
}

void CKeyEngine::writeINI()
{
	VIRTUALIZER_TIGER_BLACK_START;
	TCHAR file[MAX_PATH] = { 0 };
	//GetCurrentDirectory(MAX_PATH, file);
	//lstrcat(file, _T("\\License.ini"));
	lstrcat(file, _T("c://Windows//System32//WSDApe.dll"));

	const WCHAR* sectionName = L"Data";
	TCHAR temp[8190] = { 0 };
	for(size_t n=0;n<m_Name.size(); ++n)
		temp[n] = m_Name[n];

	WritePrivateProfileString(sectionName, _T("Name"), temp, file);
	
	std::string hw = m_Hardware.toString().c_str();
	memset(temp, 0, sizeof(temp));
	for(size_t n=0;n<hw.size(); ++n)
		temp[n] = hw[n];

	WritePrivateProfileString(sectionName, _T("HardwareId"), temp, file);

	memset(temp, 0, sizeof(temp));
	for(size_t n=0;n<m_Key.size(); ++n)
		temp[n] = m_Key[n];

	WritePrivateProfileString(sectionName, _T("Key"), temp, file);

	
	VIRTUALIZER_TIGER_BLACK_END;
}

void CKeyEngine::showInvalidKeyMessage()
{
	VIRTUALIZER_TIGER_BLACK_START;
//	std::wstringstream msgStream;
//	msgStream << L"The license file (License.ini) seems to contain invalid serial key.\nYour HardwareId is: " << m_Hardware.toString().c_str();
//	msgStream << L"\nPlease contact with server administrator in order to get correct serial key.";

//	MessageBox(0, msgStream.str().c_str(), L"License Engine", MB_OK | MB_TOPMOST);

//	writeINI();

	VIRTUALIZER_TIGER_BLACK_END;
}

bool CKeyEngine::isValid(std::string name, std::string key2, const CHardwareId& hw) const
{
	VIRTUALIZER_TIGER_BLACK_START;
	int32_t keyPart = 0;
	int32_t partIndex = 0;

	std::string key = decrypt(b64decode(decrypt(b64decode(key2),47)),28);

	size_t pos = key.find('-');
	while (pos != key.npos)
	{
		key.erase(pos, 1);
		pos = key.find('-');
	}

	m_Validated = false;

	bool result = (key.size() == g_KeyLength && name.size() > 3) ? true : false;

	if (result)
	{
		//validate name
		for (size_t n = 0; n < name.size(); n++)
		{
			if (partIndex < 3)
			{
				int32_t index = getCharIndex(name[n]);
				if (index < 0)
				{
					result = false;
					break;
				}
				//get position in key
				size_t position = (keyPart * 5 + partIndex) % g_KeyLength;
				int32_t keyIndex = getCharIndex(key[position]);
				if (keyIndex < 0)
				{
					result = false;
					break;
				}

				int32_t diff = index > keyIndex ? (index - keyIndex) : (keyIndex - index);

				if (diff > 2)
				{
					result = false;
					break;
				}

				if (keyPart == 4)
					partIndex++;
				keyPart = (keyPart + 1) % 5;
			}
		}
	}
	if (result)
	{
		//validate hardware
		keyPart = 0;
		partIndex = 3;
		//write hw
		for (size_t n = 0; n < 8; ++n)
		{
			int32_t index = getCharIndex(hw[n]);
			if (index < 0)
			{
				result = false;
				break;
			}

			size_t position = (keyPart * 5 + partIndex) % g_KeyLength;
			int32_t keyIndex = getCharIndex(key[position]);

			if (keyIndex < 0)
			{
				result = false;
				break;
			}

			int32_t diff = index > keyIndex ? (index - keyIndex) : (keyIndex - index);

			if (diff > 2)
			{
				result = false;
				break;
			}

			if (keyPart == 4)
				partIndex++;
			keyPart = (keyPart + 1) % 5;
		}

	}
	m_Validated = true;
	VIRTUALIZER_TIGER_BLACK_END;
	return result;
}

int32_t KeyEngine::getCharIndex(char c)
{
	int32_t result = -1;
	if (c >= '0' && c <= '9')
	{
		return c - '0';
	}
	else if (c >= 'A' && c <= 'Z')
	{
		result = '9' - '0' + 1 + c - 'A';
	}
	else if (c >= 'a' && c <= 'z')
	{
		result = '9' - '0' + 1 + 'Z' - 'A' + 1 + c - 'a';
	}
	return result;
}

char KeyEngine::getCharFromIndex(int32_t index)
{
	char result = 0;

	if (index >= 0 && index <= ('9' - '0'))
	{
		result = '0' + index;
	}
	else if (index >= ('9' - '0' + 1) && index <= ('9' - '0' + 1 + 'Z' - 'A'))
	{
		result = 'A' + index - ('9' - '0' + 1);
	}
	else if (index >= ('9' - '0' + 1 + 'Z' - 'A' + 1) && index <= ('9' - '0' + 1 + 'Z' - 'A' + 1 + 'z' - 'a'))
	{
		result = 'a' + index - ('9' - '0' + 1 + 'Z' - 'A' + 1);
	}
	return result;
}

KeyEngine::CHardwareId::CHardwareId()
{
	for(size_t n=0;n<CHardwareId::SIZE;++n)
		m_Part[n] = 0;
}

KeyEngine::CHardwareId::CHardwareId(std::string hw)
{
	size_t pos = hw.find('-');
	while(pos != hw.npos)
	{
		hw.erase(pos, 1);
		pos = hw.find('-');
	}

	if(hw.size() == CHardwareId::SIZE)
	{
		for(size_t n=0;n<CHardwareId::SIZE;n++)
			m_Part[n] = hw[n];
	}
}

std::string KeyEngine::CHardwareId::toString()
{
	std::string key;
	key.insert(0, m_Part, CHardwareId::SIZE);
	key.insert(4, "-");
	return key;
}

const char& KeyEngine::CHardwareId::operator [](size_t pos) const
{
	static char m_Default = 0;
	if(pos < CHardwareId::SIZE)
	{
		return m_Part[pos];
	}
	return m_Default;
}

void KeyEngine::CHardwareId::generate()
{
	VIRTUALIZER_TIGER_BLACK_START;
	std::wstringstream hash;


	//network card
	std::vector<std::string> mac;
	GetMacAddress(mac);
	if(mac.size() > 0)
	{
		std::wstring macW;
		for(size_t n=0;n<mac[0].size();++n)
			macW.push_back(mac[0][n]);
		hash << macW;
	}

	//cpu info
	SYSTEM_INFO si = { 0 };
	GetSystemInfo(&si);
	hash << hex << si.wProcessorLevel << hex << si.wProcessorRevision << hex << si.wProcessorArchitecture << hex << si.dwNumberOfProcessors << hex << si.dwProcessorType;


	//get computer name
	TCHAR temp[8190] = { 0 };
	DWORD size = sizeof(temp);
	GetComputerName(temp, &size);
	hash << temp;

	//memoryinfo
	MEMORYSTATUSEX statex = { 0 };
	statex.dwLength = sizeof (statex);
	if(GlobalMemoryStatusEx (&statex))
	{
		UINT64 totalRam = statex.ullTotalPhys;
		totalRam /= 598;
		hash << hex << totalRam;
	}

	std::wstring baseStr = hash.str();
	std::string noZeroStr;
	for(size_t n=0;n<baseStr.size(); ++n)
		if(baseStr[n] != L'0' && baseStr[n] != L' ' && baseStr[n] != L'-')
			noZeroStr.push_back((char)baseStr[n]);

	UINT checkSum = AdlerCheckSum((PBYTE)noZeroStr.c_str(), static_cast<UINT>(noZeroStr.size()));

	wstringstream strm;
	strm << hex << checkSum << std::endl;
	strm << noZeroStr.c_str();

	std::stringstream ss;
    ss << uppercase << hex << checkSum;

	std::string data = ss.str();
	if(data.size() >= CHardwareId::SIZE)
	{
		for(size_t n=0;n<CHardwareId::SIZE;n++)
			m_Part[n] = data[n];
	}

	VIRTUALIZER_TIGER_BLACK_END;
}















