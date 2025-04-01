// CliExt.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"
#include "CliExt.h"
#include "OpenPort.h"

BOOL g_Initialized = FALSE;

CLIEXT_API BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		{
			//InitializeExtender(hModule);
			break;
		}
	case DLL_THREAD_ATTACH:
		{
			InitializeExtender(hModule);
			break;
		}
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
    return TRUE;
}



#ifdef _MANAGED
#pragma managed(pop)
#endif

#pragma optimize("", off)
void InitializeExtender(HMODULE hModule)
{
	if(g_Initialized == FALSE)
	{
		g_Initialized = TRUE;

		//Add Open Port Here
		g_OpenPort.Init();
	}
}

#pragma optimize("", on)