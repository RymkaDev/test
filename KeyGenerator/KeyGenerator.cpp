// KeyGenerator.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <iostream>
#include <sstream>
#include <vector>

using namespace std;

const size_t g_KeyLength = 25;


int32_t getCharIndex(char c)
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

char getCharFromIndex(int32_t index)
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

struct HardwareId
{
	char part[8];
	HardwareId(std::string hw)
	{
		size_t pos = hw.find('-');
		while (pos != hw.npos)
		{
			hw.erase(pos, 1);
			pos = hw.find('-');
		}
		if (hw.size() == 8)
		{
			for (size_t n = 0; n < 8; n++)
				part[n] = hw[n];
		}
	}
};

std::string generateKey(std::string name, const HardwareId& hw)
{
	std::string key(g_KeyLength, '*');
	int32_t keyPart = 0;
	int32_t partIndex = 0;
	//write name
	for (size_t n = 0; n < name.size(); n++)
	{
		if (partIndex < 3)
		{
			int32_t index = getCharIndex(name[n]);
			if (index < 0)
			{
				break;
			}
			//get position in key
			size_t position = (keyPart * 5 + partIndex) % g_KeyLength;
			if (keyPart == 4)
				partIndex++;

			keyPart = (keyPart + 1) % 5;

			int32_t keyIndex = index + ((rand() % 5) - 2);
			if (keyIndex > getCharIndex('z'))
				keyIndex = getCharIndex('z');
			if (keyIndex < 0)
				keyIndex = 0;

			key[position] = getCharFromIndex(keyIndex);
		}
	}
	keyPart = 0;
	partIndex = 3;
	//write hw
	for (size_t n = 0; n < 8; ++n)
	{
		int32_t index = getCharIndex(hw.part[n]);
		if (index >= 0)
		{
			int32_t keyIndex = index + ((rand() % 5) - 2);
			if (keyIndex > getCharIndex('z'))
				keyIndex = getCharIndex('z');
			if (keyIndex < 0)
				keyIndex = 0;

			size_t position = (keyPart * 5 + partIndex) % g_KeyLength;
			key[position] = getCharFromIndex(keyIndex);
		}
		if (keyPart == 4)
			partIndex++;
		keyPart = (keyPart + 1) % 5;
	}

	for (size_t n = 0; n < key.size(); n++)
	{
		if (key[n] == '*')
		{
			key[n] = getCharFromIndex(rand() % (getCharIndex('z') + 1));
		}
	}

	for (size_t n = 0; n < 4; n++)
	{
		key.insert((n * 5 + 5 + n), "-");
	}

	return key;
}











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

int _tmain(int argc, _TCHAR* argv[])
{
	cout << "Welcome to key generator." << std::endl;
	cout << "License name: ";
	std::string name;
	cin >> name;
	cout << "HardwareId: ";
	std::string hardware;
	cin >> hardware;

	cout << "Generating a key ..." << endl;

	std::string key = generateKey(name, HardwareId(hardware));


	//cout << "Generated key: " << key << endl;

	cout << "Generated key: " << b64encode(encrypt(b64encode(encrypt(key,28)),47)) << endl;

	system("pause");

	return 0;
}

