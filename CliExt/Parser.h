#pragma once

class CParser
{
public:
	static wstring Replace(wstring str, wchar_t sign, wchar_t new_sign);
	static string Replace(string str, char sign, char new_sign);
	static wstring GetValueString(wstring sSub, wstring sName);
	static string GetValueString(string sSub, string sName);
	
	/*static wstring Trim(wstring str);
	static string Trim(string str);
	static wstring GetBypassValue(wstring wBypass, wstring wSub);
	static int GetBypassValueInt(wstring wBypass, wstring wSub, int defaultValue = -1);
	static string GetColumn(string sSub, int nIndex);
	static string GetValueString(string sSub, string sName);
	static wstring GetName(wstring wStr);
	static wstring GetValueString(wstring sSub, wstring sName);
	static int GetValueInt(string sSub, string sName, int defaultValue = 0);
	static int GetValueInt(wstring wSub, wstring wName);
	static double GetValueDouble(string sSub, string sName);
	static void ConvToLower(PWCHAR wsTxt, int nMaxSize);*/
};

namespace Parser
{
	wstring Replace(wstring str, wchar_t sign, wchar_t new_sign);
	string Replace(string str, char sign, char new_sign);
	wstring Trim(wstring str);
	string Trim(string str);
	vector<wstring> Split(wstring line, wstring separators);
	vector<string> Split(string line, string separators);
	void SplitEx(wstring line, wstring separators, vector<wstring>& words, wstring magicChar, bool toLower);
	wstring Trim(wstring str);
	string Trim(string str);
};