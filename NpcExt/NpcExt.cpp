// NpcExt.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"
#include "NPCEventFactory.h"
#include "PostLoad.h"
#include "BaseAction.h"
#include "Timer.h"
#include "ScriptAccessible.h"
#include "FastLoadNpc.h"
#include "Compiler.h"

#include "NpcSpawnDefine.h"


#ifdef _MANAGED
#pragma managed(push, off)
#endif

BOOL g_Initialized = FALSE;



TCHAR   m_Script[260];
TCHAR   m_GeoData[260];

CHAR   m_Script_Ansi[260];
CHAR   m_GeoData_Ansi[260];

CHAR   geo_index_txt_Ansi[260];
CHAR   PC_Parameter_txt_Ansi[260];
CHAR   categorydata_txt_Ansi[260];
CHAR   ai_obj_Ansi[260];
CHAR   npcpos_txt_Ansi[260];

TCHAR   fstring_txt[260];
TCHAR   BadGeoData_txt[260];
TCHAR   pc_parameter_txt[260];
TCHAR   SuperPoint_bin[260];
TCHAR   ai_obj[260];


void InitializeExtender()
{
	if(!g_Initialized)
	{
		//Fix the func at 0x4328A0
		WriteBYTE(0x4328A0, 0xC3);	//ret
		WriteNOP(0x4328A1, 15);

		WriteNOP(0x5D57CD, 5);	//UserObjectEvent_LogInvalidDelete
		WriteNOP(0x6012A7, 5);	//User_AddReverseHate_NoActiveUser



		//			este creo que es para desactivar  Silent When no user en el menude l2npc por defecto esta en 1
	//	WriteBYTE(0x77DC47, 0x00);		//al parece capas me da algun error en l2npc





		TCHAR g_ConfigFile[260] = { 0 };
		GetCurrentDirectory(MAX_PATH,g_ConfigFile);
		lstrcat(g_ConfigFile, _T("\\l2npc.ini"));

		if(!GetPrivateProfileInt(_T("Setting"), _T("SetThreadAffinityMask"), TRUE, g_ConfigFile))
		{
			WriteNOP(0x47E41D, 6);
		}


		if(GetPrivateProfileInt(_T("Setting"), _T("NoGuardarLocHpMpConstanteBoss"), FALSE, g_ConfigFile))
		{
			WriteNOP(0x004DAC88, 5);	//para que no guarde cada 16 segundos la loc, hp y mp de los boss, es una locura cada 16 segundos updateando la db 200 raidboss si estan todos vivos
		}



		TCHAR  File[260];
		GetCurrentDirectory(MAX_PATH, File);
		lstrcat(File, _T("..//..//L2Server//l2server.ini"));

		int Enabled_changeFolder = GetPrivateProfileInt(_T("FOLDERS_CUSTOM"), _T("Enabled"), 0, File);

		if(Enabled_changeFolder)
		{
			GetPrivateProfileStringW(_T("FOLDERS_CUSTOM"), _T("Script"),L"",m_Script, 260, File);
			GetPrivateProfileStringW(_T("FOLDERS_CUSTOM"), _T("GeoData"),L"",m_GeoData, 260, File);


			_UnicodeToAnsi(m_Script, m_Script_Ansi);
			_UnicodeToAnsi(m_GeoData, m_GeoData_Ansi);

			lstrcat(fstring_txt, m_Script);
			lstrcat(BadGeoData_txt, m_GeoData);
			lstrcat(pc_parameter_txt, m_Script);
			lstrcat(SuperPoint_bin, m_GeoData);
			lstrcat(ai_obj, m_Script);

			lstrcat(fstring_txt, L"fstring.txt");
			lstrcat(BadGeoData_txt, L"BadGeoData.txt");
			lstrcat(pc_parameter_txt, L"pc_parameter.txt");
			lstrcat(SuperPoint_bin, L"SuperPoint.bin");
			lstrcat(ai_obj, L"ai.obj");




			
			//---------------string
			{
				std::stringstream wss;
				wss << m_GeoData_Ansi << "geo_index.txt";
				string tmp = wss.str();
				strcpy_s(geo_index_txt_Ansi, tmp.c_str());
			}
			{
				std::stringstream wss;
				wss << m_Script_Ansi << "PC_Parameter.txt";
				string tmp = wss.str();
				strcpy_s(PC_Parameter_txt_Ansi, tmp.c_str());
			}
			{
				std::stringstream wss;
				wss << m_Script_Ansi << "categorydata.txt";
				string tmp = wss.str();
				strcpy_s(categorydata_txt_Ansi, tmp.c_str());

			}
			{
				std::stringstream wss;
				wss << m_Script_Ansi << "ai.obj";
				string tmp = wss.str();
				strcpy_s(ai_obj_Ansi, tmp.c_str());
			}
			{
				std::stringstream wss;
				wss << m_Script_Ansi << "npcpos.txt";
				string tmp = wss.str();
				strcpy_s(npcpos_txt_Ansi, tmp.c_str());
			}


			WriteRelativeAddress(0x496786, 3, &fstring_txt,0);	// (16 bits) - UTF-16LE	../script/fstring.txt
			WriteRelativeAddress(0x46B445, 3, &m_GeoData,0);	// (16 bits) - UTF-16LE	..\\GeoData
			WriteRelativeAddress(0x46B968, 3, &BadGeoData_txt,0);	// (16 bits) - UTF-16LE	..\\GeoData\\BadGeoData.txt
			WriteRelativeAddress(0x46B3D9, 3, &geo_index_txt_Ansi,0);	//						..\\GeoData\\geo_index.txt
			WriteRelativeAddress(0x5A3F25, 3, &PC_Parameter_txt_Ansi,0);	//						..\\Script\\PC_Parameter.txt
			WriteRelativeAddress(0x4407D1, 3, &categorydata_txt_Ansi,0);	//						..\\Script\\categorydata.txt
			WriteRelativeAddress(0x5A3FCF, 3, &pc_parameter_txt,0);	// (16 bits) - UTF-16LE	..\\Script\\pc_parameter.txt
			WriteRelativeAddress(0x5ACCFB, 3, &pc_parameter_txt,0);	// (16 bits) - UTF-16LE	..\\Script\\pc_parameter.txt
			WriteRelativeAddress(0x5AF038, 3, &pc_parameter_txt,0);	// (16 bits) - UTF-16LE	..\\Script\\pc_parameter.txt

			WriteRelativeAddress(0x5F0C35, 3, &SuperPoint_bin,0);	// (16 bits) - UTF-16LE	..\\geodata\\SuperPoint.bin

			WriteRelativeAddress(0x4407AC, 3, &m_Script,0);	// (16 bits) - UTF-16LE	..\\script
			WriteRelativeAddress(0x5B2C43, 3, &m_Script,0);	// (16 bits) - UTF-16LE	..\\script
			WriteRelativeAddress(0x5B2CCF, 3, &m_Script,0);	// (16 bits) - UTF-16LE	..\\script
			WriteRelativeAddress(0x5B309E, 3, &m_Script,0);	// (16 bits) - UTF-16LE	..\\script
			WriteRelativeAddress(0x5B30AF, 3, &m_Script,0);	// (16 bits) - UTF-16LE	..\\script
			WriteRelativeAddress(0x5B3CAE, 3, &m_Script,0);	// (16 bits) - UTF-16LE	..\\script
			WriteRelativeAddress(0x5B3CBF, 3, &m_Script,0);	// (16 bits) - UTF-16LE	..\\script

			WriteRelativeAddress(0x41BEFB, 3, &ai_obj,0);	// (16 bits) - UTF-16LE	..\\script\\ai.obj
			WriteRelativeAddress(0x498B9B, 3, &ai_obj,0);	// (16 bits) - UTF-16LE	..\\script\\ai.obj
			WriteRelativeAddress(0x49B928, 3, &ai_obj,0);	// (16 bits) - UTF-16LE	..\\script\\ai.obj

			WriteRelativeAddress(0x41C052, 3, &ai_obj_Ansi,0);	//						..\\script\\ai.obj

			WriteRelativeAddress(0x55115B, 3, &npcpos_txt_Ansi,0);	//						..\\script\\npcpos.txt
			WriteRelativeAddress(0x55116D, 3, &npcpos_txt_Ansi,0);	//						..\\script\\npcpos.txt
			WriteRelativeAddress(0x5513F7, 3, &npcpos_txt_Ansi,0);	//						..\\script\\npcpos.txt
			WriteRelativeAddress(0x581BE8, 3, &npcpos_txt_Ansi,0);	//						..\\script\\npcpos.txt





		}






		MovLogFiles(L"ErrBak");
		
		CSharedFactory::Init();
		CNPC::ExtInit();
		CNPCEventFactory::Init();
		CPostLoad::Init();
		CBaseAction::Init();
		CTimer::Init();
		CScriptAccessible::Init();
		CFastLoadNPC::Init();

		Compiler::Init();	//	NO FUNCIONA, LO HICE FUNCIONAR CON EL EXE DE GRACIA FINAL

		
		CNpcSpawnDefine::Init();

		g_Initialized = TRUE;
	}
}



DLLEXPORT BOOL APIENTRY DllMain( HMODULE hModule, DWORD  dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
		case DLL_PROCESS_ATTACH:
		{
			InitializeExtender();
			break;
		}

		case DLL_PROCESS_DETACH:
		{

			break;
		}
	}

	return TRUE;
}

#ifdef _MANAGED
#pragma managed(pop)
#endif

