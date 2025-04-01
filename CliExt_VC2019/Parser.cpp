#include "stdafx.h"
#include "Parser.h"

wstring Parser::Replace(wstring str, wchar_t sign, wchar_t new_sign)
{
	size_t pos = str.find(sign);
	while(pos!=wstring::npos)
	{
		str[pos] = new_sign;
		pos = str.find(sign);
	}
	return str;
}

string Parser::Replace(string str, char sign, char new_sign)
{
	size_t pos = str.find(sign);
	while(pos!=string::npos)
	{
		str[pos] = new_sign;
		pos = str.find(sign);
	}
	return str;
}

vector<string> Parser::Split(string line, string separator)
{
	vector<string> data;
	string ex = "";
	for(UINT n=0;n<line.size();n++)
	{
		bool newL = false;
		for(UINT m = 0; m < separator.size(); m++)
		{
			if(line[n] == separator[m])
			{
				newL = true;
				break;
			}
		}
		if(newL)
		{
			data.push_back(ex);
			ex = "";
			continue;
		}
		ex += line[n];
	}
	
	if(ex.size() > 0)
	{
		data.push_back(ex);
	}
	return data;
}

vector<wstring> Parser::Split(wstring line, wstring separator)
{
	vector<wstring> data;
	wstring ex = L"";
	for(UINT n=0;n<line.size();n++)
	{
		bool newL = false;
		for(UINT m = 0; m < separator.size(); m++)
		{
			if(line[n] == separator[m])
			{
				newL = true;
				break;
			}
		}
		if(newL)
		{
			data.push_back(ex);
			ex = L"";
			continue;
		}
		ex += line[n];
	}
	if(ex.size() > 0)
	{
		data.push_back(ex);
	}
	return data;
}

void Parser::SplitEx(wstring line, wstring separators, vector<wstring>& words, wstring magicChars, bool toLower)
{
	wstring word = L"";
	wstring magicWord = L"";
	for(UINT n=0;n<line.size();n++)
	{
		bool newWord = false;
		bool newMagicWord = false;
		for(UINT m=0;m<separators.size();m++)
		{
			if(line[n] == separators[m])
			{
				newWord = true;
				break;
			}
		}
		for(UINT m=0;m<magicChars.size();m++)
		{
			if(line[n] == magicChars[m])
			{
				newWord = true;
				newMagicWord = true;
				magicWord = line[n];
				break;
			}
		}
		if(newWord)
		{
			if(word.size() > 0)
			{
				words.push_back(word);
				word = L"";
			}
			if(newMagicWord)
			{
				words.push_back(magicWord);
				magicWord = L"";
			}
		}else
		{
			if(toLower)
			{
				word += towlower(line[n]);
			}else
			{
				word += line[n];
			}
		}
	}
	if(word.size() > 0)
	{
		words.push_back(word);
	}
}

wstring CParser::GetValueString(wstring sSub, wstring sName)
{
	wstring sValue;
	size_t pos = sSub.find(sName);
	if(pos != wstring::npos)
	{
		wstring sTmp = sSub.substr(pos+sName.size(), sSub.size());
		pos = sTmp.find('=');
		if(pos!= wstring::npos)
			sValue = sTmp.substr(pos+1, sSub.size());
	}
	
	wstringstream sstr;
	sstr << sValue;
	sstr >> sValue;
	return sValue;
}

string CParser::GetValueString(string sSub, string sName)
{
	string sValue;
	size_t pos = sSub.find(sName);
	if(pos != string::npos)
	{
		string sTmp = sSub.substr(pos+sName.size(), sSub.size());
		pos = sTmp.find('=');
		if(pos!= string::npos)
			sValue = sTmp.substr(pos+1, sSub.size());
	}
	
	stringstream sstr;
	sstr << sValue;
	sstr >> sValue;
	return sValue;
}

wstring Parser::Trim(wstring str)
{
	size_t pos = str.find_first_of(L"\t\n\r\v ");
	while(pos!=wstring::npos)
	{
		str.erase(pos, 1);
		pos = str.find_first_of(L"\t\n\r\v ");
	}
	return str;
}
string Parser::Trim(string str)
{
	size_t pos = str.find_first_of("\t\n\r\v ");
	while(pos!=string::npos)
	{
		str.erase(pos, 1);
		pos = str.find_first_of("\t\n\r\v ");
	}
	return str;
}

