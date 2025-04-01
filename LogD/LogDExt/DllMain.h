#pragma once

#include <cmath>
#include <cstdarg>
#include <ctime>
#include <map>
#include <list>
#include <string>
#include <vector>
#include <windows.h>
#include <tchar.h>
#include "Utils.h"

// Namespaces
using namespace std;




__declspec(dllexport) BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved );
void Initialize();
