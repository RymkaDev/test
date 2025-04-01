#include "StdAfx.h"

wstring StringToWString(const string& s)
{
	wstring temp(s.length(),L' ');
	copy(s.begin(), s.end(), temp.begin());
	return temp; 
}

wstring getFileName(const wstring& s) 
{

   char sep = '/';

#ifdef _WIN32
   sep = '\\';
#endif

   size_t i = s.rfind(sep, s.length());
   if (i != wstring::npos) {
      return(s.substr(i+1, s.length() - i));
   }

   return(L"");
}