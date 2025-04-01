// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#ifndef _L2WINDOWNICKNAME_H
#define _L2WINDOWNICKNAME_H

//#include <SDKDDKVer.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

void toLowerCase(char* str) {
	for(size_t i = 0; i < strlen(str); i++) {
		if(isupper(str[i])) {
			str[i] = tolower(str[i]);
		}
	}
}

bool GetCfgBool(const char* section, const char* param, bool defaultValue) {
	char strValue[255];
	GetPrivateProfileStringA(section, param, defaultValue ? "true" : "false", strValue, 255, "./option.ini");
	toLowerCase(strValue);

	return strcmp("true", strValue) == 0;
}


#define NAMEPOSTFIX L" - L2Tekila.com.ar"

#endif