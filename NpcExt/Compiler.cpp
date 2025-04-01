
#include "stdafx.h"
#include "Compiler.h"
#include "Utils.h"
#include "Log.h"
#include <vector>
#include <fstream>

#include <Shellapi.h>

std::wstring Compiler::exeFilename;
std::string Compiler::filename;
bool Compiler::close = false;
bool Compiler::closeOnError = false;

void Compiler::Init()
{
	int argc;
	wchar_t **argv;
	argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	if (!argv) {
		MessageBox(0, L"Couldn't parse command line arguments (CommandLineToArgvW failed)", L"Error", 0);
		exit(0);
	}
	std::vector<std::wstring> args;
	for (size_t i = 0; i < argc; ++i) {
		args.push_back(std::wstring(argv[i]));
	}
	LocalFree(argv);

	exeFilename = args[0];
	if (args.size() > 1) {
		for (size_t i = 1; i < args.size(); ++i) {
			if (args[i] == L"-c" || args[i] == L"--close") {
				close = true;
			} else if (args[i] == L"-e" || args[i] == L"--close-on-error") {
				closeOnError = true;
			} else if (filename.empty()) {
				filename = Narrow(args[i]);
			} else {
				wchar_t buffer[4096];
				if (args[0].size() < 2048) {
					wsprintf(buffer, L"Usage:\r\n%s [-c|--close] [-e|--close-on-error] [FILENAME]", exeFilename.c_str());
				} else {
					wsprintf(buffer, L"Usage:\r\n%s... [-c|--close] [-e|--close-on-error] [FILENAME]", exeFilename.substr(0, 2048).c_str());
				}
				MessageBox(0, buffer, L"Invalid arguments", 0);
				exit(0);
			}
		}
	}
	if (filename.empty()) {
		return;
	}

	WriteInstructionCall(0x4013C0 + 0x29A, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4013C0 + 0x347, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4013C0 + 0x56D, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x22A, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x350, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0xB31, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x1518, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x15C6, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x1677, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x17CF, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x19F6, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x1BB9, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x1D4A, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x1F90, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x2161, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x21D3, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x2521, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x2564, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x2636, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x2733, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x28AA, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x2A63, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x2BA8, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x2DFE, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x3152, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x3421, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x35E1, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x37A1, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x3B7C, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x3E32, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x428F, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x4471, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x4533, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x48A6, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x48F2, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x49C8, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x4B4C, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x4FDE, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x5091, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x5123, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x55D9, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x5649, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x57F5, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x585D, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x5A2A, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x5AD3, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x5B71, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x5CD9, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x5F1E, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x5F86, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x4067F0 + 0x61CB, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x40D570 + 0x1C, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x6001F0 + 0x89, reinterpret_cast<UINT32>(LogErrora));
	WriteInstructionCall(0x6001F0 + 0xC2, reinterpret_cast<UINT32>(LogErrora));

	WriteInstructionCall(0x40D58C, reinterpret_cast<UINT32>(LogErrora));




	WriteInstructionCall(0x581BDE, reinterpret_cast<UINT32>(Compile));			//54817C
	WriteInstructionJmp(0x613A30, reinterpret_cast<UINT32>(exit));				//42B140
	WriteInstructionJmp(0x4965C3, 0x4965E3);		//475826    475846
	WriteAddress(0x40D434 + 3, 0x68BE08);		//5BE2EC   665030
	WriteMemoryBYTES(0x46ACD0, "\x48\x31\xC0\xC3", 4);	//448108
	WriteMemoryBYTES(0x46AFD0, "\x48\x31\xC0\xC3", 4);	//44838C
	WriteMemoryBYTES(0x4B9E20, "\x48\x31\xC0\xC3", 4);	//482A60    NO ESTOY SEGURO
	WriteMemoryBYTES(0x525E40, "\x48\x31\xC0\xC3", 4);	//55C82C	NO ESTOY SEGURO
	WriteMemoryBYTES(0x5245C0, "\x48\x31\xC0\xC3", 4);	//596998	NO ESTOY SEGURO
	WriteMemoryBYTES(0x524810, "\x48\x31\xC0\xC3", 4);	//596A28
	WriteMemoryBYTES(0x524A60, "\x48\x31\xC0\xC3", 4);	//596AB8
	WriteNOP(0x40D43B, 5);		//5BE2F3
	WriteNOP(0x60C9D3, 5);		//5B9EF7
	WriteNOP(0x60CA0F, 5);		//5B9F39
	WriteNOP(0x496B04, 5);		//474D73
	WriteNOP(0x448923, 5);		//41C7AA
	WriteInstructionCall(0x4059EF, 0x618180);	//5E9210
	WriteNOP(0x581BA1, 30);	//PARA PODER USARLO SIN LEVANTAR CACHED

	//WriteMemoryBYTES(0x6793A0, "00\x00\x02\x00\x06\x00\x00\x00\x03\x00\x03\x00\x0B\x00\x04\x00\x03\x00\x05\x00\x05\x00\x03\x00\x05\x00\x06\x00\x07\x00\x02\x00\x07\x00\x07\x00\x00\x00\x08\x00\x08\x00\x03\x00\x09\x00\x08\x00\x03\x00\x0A\x00\x08\x00\x01\x00\x0B\x00\x08\x00\x00\x00\x0C\x00\x0A\x00\x00\x00\x0D\x00\x09\x00\x03\x00\x0E\x00\x09\x00\x00\x00\xFF\xFF\x0B\x00\x02\x00\xFF\xFF\x0B\x00\x00\x00\xFF\xFF\x0C\x00\x05\x00\x0F\x00\x0C\x00\x05\x00\x10\x00\x0C\x00\x05\x00\x11\x00\x0C\x00\x05\x00\x12\x00\x0C\x00\x03\x00\x13\x00\x0C\x00\x03\x00\x14\x00\x0E\x00\x00\x00\x15\x00\x0D\x00\x03\x00\x16\x00\x0D\x00\x00\x00\xFF\xFF\x0F\x00\x02\x00\xFF\xFF\x0F\x00\x00\x00\xFF\xFF\x10\x00\x05\x00\x17\x00\x10\x00\x05\x00\x18\x00\x10\x00\x05\x00\x19\x00\x10\x00\x05\x00\x1A\x00\x11\x00\x00\x00\x1B\x00\x10\x00\x08\x00\x1C\x00\x12\x00\x00\x00\x1D\x00\x10\x00\x08\x00\x1E\x00\x13\x00\x03\x00\xFF\xFF\x13\x00\x01\x00\xFF\xFF\x14\x00\x0D\x00\x1F\x00\x14\x00\x0D\x00\x20\x00\x14\x00\x0B\x00\x21\x00\x14\x00\x0B\x00\x22\x00\x14\x00\x0F\x00\x23\x00\x14\x00\x0F\x00\x24\x00\x15\x00\x03\x00\x25\x00\x15\x00\x01\x00\x26\x00\x16\x00\x03\x00\xFF\xFF\x16\x00\x03\x00\xFF\xFF\x16\x00\x01\x00\xFF\xFF\x16\x00\x01\x00\xFF\xFF\x16\x00\x00\x00\xFF\xFF\x17\x00\x05\x00\x27\x00\x17\x00\x09\x00\x28\x00\x18\x00\x01\x00\x29\x00\x19\x00\x02\x00\xFF\xFF\x19\x00\x00\x00\xFF\xFF\x1A\x00\x02\x00\x2A\x00\x1A\x00\x00\x00\xFF\xFF\x1C\x00\x00\x00\x2B\x00\x1D\x00\x00\x00\x2C\x00\x1B\x00\x08\x00\x2D\x00\x1E\x00\x00\x00\x2E\x00\x1B\x00\x04\x00\xFF\xFF\x1F\x00\x03\x00\x2F\x00\x20\x00\x02\x00\x30\x00\x20\x00\x00\x00\x31\x00\x21\x00\x02\x00\x32\x00\x22\x00\x00\x00\x33\x00\x21\x00\x02\x00\x34\x00\x21\x00\x02\x00\x35\x00\x21\x00\x02\x00\x36\x00\x21\x00\x01\x00\x37\x00\x21\x00\x06\x00\x38\x00\x23\x00\x00\x00\x39\x00\x21\x00\x09\x00\x3A\x00\x24\x00\x00\x00\x3B\x00\x25\x00\x00\x00\x3C\x00\x21\x00\x07\x00\x3D\x00\x26\x00\x00\x00\x3E\x00\x21\x00\x08\x00\x3F\x00\x27\x00\x00\x00\x40\x00\x28\x00\x00\x00\x41\x00\x29\x00\x00\x00\x42\x00\x21\x00\x0C\x00\x43\x00\x21\x00\x02\x00\x44\x00\x21\x00\x02\x00\x45\x00\x2A\x00\x00\x00\x46\x00\x2B\x00\x02\x00\xFF\xFF\x2B\x00\x00\x00\xFF\xFF\x2D\x00\x00\x00\x47\x00\x2C\x00\x05\x00\x48\x00\x2C\x00\x04\x00\x49\x00\x2C\x00\x04\x00\x4A\x00\x2E\x00\x01\x00\x4B\x00\x2E\x00\x00\x00\x4C\x00\x30\x00\x00\x00\x4D\x00\x2F\x00\x04\x00\x4E\x00\x2F\x00\x01\x00\x4F\x00\x31\x00\x01\x00\x50\x00\x33\x00\x00\x00\x51\x00\x32\x00\x04\x00\x52\x00\x32\x00\x01\x00\x53\x00\x34\x00\x01\x00\x54\x00\x36\x00\x00\x00\x55\x00\x35\x00\x04\x00\x56\x00\x35\x00\x01\x00\x57\x00\x38\x00\x00\x00\x58\x00\x37\x00\x04\x00\x59\x00\x39\x00\x00\x00\x5A\x00\x37\x00\x04\x00\x5B\x00\x3A\x00\x00\x00\x5C\x00\x37\x00\x04\x00\x5D\x00\x3B\x00\x00\x00\x5E\x00\x37\x00\x04\x00\x5F\x00\x3C\x00\x00\x00\x60\x00\x37\x00\x04\x00\x61\x00\x3D\x00\x00\x00\x62\x00\x37\x00\x04\x00\x63\x00\x3E\x00\x00\x00\x64\x00\x37\x00\x04\x00\x65\x00\x3F\x00\x00\x00\x66\x00\x37\x00\x04\x00\x67\x00\x40\x00\x00\x00\x68\x00\x37\x00\x04\x00\x69\x00\x41\x00\x00\x00\x6A\x00\x37\x00\x04\x00\x6B\x00\x37\x00\x01\x00\x6C\x00\x42\x00\x03\x00\x6D\x00\x42\x00\x01\x00\x6E\x00\x42\x00\x01\x00\x6F\x00\x42\x00\x01\x00\x70\x00\x42\x00\x02\x00\x71\x00\x42\x00\x02\x00\x72\x00\x42\x00\x01\x00\x73\x00\x42\x00\x03\x00\x74\x00\x43\x00\x00\x00\x75\x00\x42\x00\x05\x00\x76\x00\x42\x00\x03\x00\x77\x00\x42\x00\x05\x00\x78\x00\x44\x00\x00\x00\x79\x00\x42\x00\x07\x00\x7A\x00\x42\x00\x02\x00\x7B\x00\x42\x00\x02\x00\x7C\x00\x45\x00\x01\x00\x7D\x00\x45\x00\x03\x00\x7E\x00\x46\x00", 864);	//596AB8

}

int Compiler::LogErrora(void*, const wchar_t* format, ...)
{
	va_list va;
    va_start(va, format);
	g_Log.AddV(LogError, format, va);
	vwprintf(format, va);
    va_end(va);
	return 1;
}


void Compiler::Compile()
{
	std::string outputFilename = filename + ".obj";

	size_t pos = filename.rfind(".");
	if (pos != std::string::npos) {
		outputFilename = filename.substr(0, pos) + ".obj";
	}

	std::wstring wfilename = Widen(filename);
	std::wstring woutputFilename = Widen(outputFilename);

	g_Log.Add(LogError, L" ");
	g_Log.Add(LogError, L"Going to compile %s to %s", wfilename.c_str(), woutputFilename.c_str());
	g_Log.Add(LogError, L" ");

	if (!std::wifstream(filename.c_str())) {
		g_Log.Add(LogError, L"Can't open input file %s", wfilename.c_str());
		Done(false);
	}

	*reinterpret_cast<int*>(0x2EBD7E8) = 1; // enable logging		37886B8

	Parser parser;
	reinterpret_cast<void*(*)(void*)>(0x405CD0)(&parser); // construct parser	5C9980		

	reinterpret_cast<void(*)(UINT64, UINT64, FILE*)>(0x5B2AC0)(0x9BFC2A0, 0x4407AC, 0); // load pch db	55A890   36E58D0   649CA8

	// this is how we can add @variables
	// reinterpret_cast<void(*)(UINT64, const wchar_t*, int)>(0x55B18C)(0x36E58D0, L"variable", 123);

	InputFile inputFile;
	reinterpret_cast<void(*)(InputFile*, const char*, int, int)>(0x41CA90)(&inputFile, filename.c_str(), 1, 1); // open input file  4086F8

	if (inputFile.something2[inputFile.something1] & 6) { // check input file OK
		g_Log.Add(LogError, L"Can't open input file!");
		Done(false);
	}
	g_Log.Add(LogError, L"Creating parser...");

	if (!reinterpret_cast<bool(*)(Parser*, const wchar_t*)>(0x40D3C0)(&parser, wfilename.c_str())) { // give file to parser   5BE2B4
		g_Log.Add(LogError, L"Failed to create parser");
		Done(false);
	}

	g_Log.Add(LogError, L"Registering constants...");

//	reinterpret_cast<void(*)(unsigned char*, const wchar_t*, int)>(0x4612A0)(&parser.padding[0x178], L"PSTATE_IDLE", 0);
//	reinterpret_cast<void(*)(unsigned char*, const wchar_t*, int)>(0x4612A0)(&parser.padding[0x178], L"PSTATE_MOVE_AROUND", 1);
//	reinterpret_cast<void(*)(unsigned char*, const wchar_t*, int)>(0x4612A0)(&parser.padding[0x178], L"PSTATE_DO_NOTHING", 2);
//	reinterpret_cast<void(*)(unsigned char*, const wchar_t*, int)>(0x4612A0)(&parser.padding[0x178], L"PSTATE_ATTACK", 3);
//	reinterpret_cast<void(*)(unsigned char*, const wchar_t*, int)>(0x4612A0)(&parser.padding[0x178], L"PSTATE_CHASE", 4);
//	reinterpret_cast<void(*)(unsigned char*, const wchar_t*, int)>(0x4612A0)(&parser.padding[0x178], L"PSTATE_FLEE", 5);
//	reinterpret_cast<void(*)(unsigned char*, const wchar_t*, int)>(0x4612A0)(&parser.padding[0x178], L"PSTATE_GET_ITEM", 6);
//	reinterpret_cast<void(*)(unsigned char*, const wchar_t*, int)>(0x4612A0)(&parser.padding[0x178], L"PSTATE_FOLLOW", 7);
//	reinterpret_cast<void(*)(unsigned char*, const wchar_t*, int)>(0x4612A0)(&parser.padding[0x178], L"PSTATE_DECAYING", 8);
//	reinterpret_cast<void(*)(unsigned char*, const wchar_t*, int)>(0x4612A0)(&parser.padding[0x178], L"PSTATE_MOVE_TO_WAY_POINT", 9);
//	reinterpret_cast<void(*)(unsigned char*, const wchar_t*, int)>(0x4612A0)(&parser.padding[0x178], L"PSTATE_USE_SKILL", 10);
//	reinterpret_cast<void(*)(unsigned char*, const wchar_t*, int)>(0x4612A0)(&parser.padding[0x178], L"PSTATE_MOVE_TO", 11);
//	reinterpret_cast<void(*)(unsigned char*, const wchar_t*, int)>(0x4612A0)(&parser.padding[0x178], L"PSTATE_EFFECT_ACTION", 12);
//	reinterpret_cast<void(*)(unsigned char*, const wchar_t*, int)>(0x4612A0)(&parser.padding[0x178], L"PSTATE_EFFECT_ACTION2", 13);
//	reinterpret_cast<void(*)(unsigned char*, const wchar_t*, int)>(0x4612A0)(&parser.padding[0x178], L"PSTATE_PET_DEFAULT", 14);
//	reinterpret_cast<void(*)(unsigned char*, const wchar_t*, int)>(0x4612A0)(&parser.padding[0x178], L"PSTATE_MOVE_TO_TARGET", 15);
//	reinterpret_cast<void(*)(unsigned char*, const wchar_t*, int)>(0x4612A0)(&parser.padding[0x178], L"PSTATE_MOVE_SUPERPOINT", 16);
//	reinterpret_cast<void(*)(unsigned char*, const wchar_t*, int)>(0x4612A0)(&parser.padding[0x178], L"PSTATE_MOVE_FREEWAY", 17);

//	reinterpret_cast<void(*)(unsigned char*, const wchar_t*, int)>(0x4612A0)(&parser.padding[0x178], L"MSTATE_NORMAL", 0);
//	reinterpret_cast<void(*)(unsigned char*, const wchar_t*, int)>(0x4612A0)(&parser.padding[0x178], L"MSTATE_BERSERK", 1);
//	reinterpret_cast<void(*)(unsigned char*, const wchar_t*, int)>(0x4612A0)(&parser.padding[0x178], L"MS_SILENCE", 2);

//	reinterpret_cast<void(*)(unsigned char*, const wchar_t*, int)>(0x4612A0)(&parser.padding[0x178], L"FRIEND", 0);
//	reinterpret_cast<void(*)(unsigned char*, const wchar_t*, int)>(0x4612A0)(&parser.padding[0x178], L"SAME_PARTY", 1);
//	reinterpret_cast<void(*)(unsigned char*, const wchar_t*, int)>(0x4612A0)(&parser.padding[0x178], L"SAME_BLOODPLEDGE", 2);
//	reinterpret_cast<void(*)(unsigned char*, const wchar_t*, int)>(0x4612A0)(&parser.padding[0x178], L"PC", 3);
//	reinterpret_cast<void(*)(unsigned char*, const wchar_t*, int)>(0x4612A0)(&parser.padding[0x178], L"NPC", 4);


	g_Log.Add(LogError, L"Creating output file...");

	reinterpret_cast<void(*)(const char*)>(0x446370)(outputFilename.c_str()); // open output	419D84


//wchar_t buffer[4096];
//wsprintf(buffer, L"offset[%d]", &parser);
//MessageBox(0, buffer, L"offset", 0);


	reinterpret_cast<void(*)(int, int, int, int, int, int)>(0x446530)( // write header	//419E40
		sizeof(void*), 427, 408, 235, 125, 0);

	*reinterpret_cast<UINT32*>(reinterpret_cast<char*>(&parser) + 0x110) = 4; // mode?	///A??????????



//wsprintf(buffer, L"offset[%d]", &parser);
//MessageBox(0, buffer, L"offset", 0);


	g_Log.Add(LogError, L"Compiling...");

	bool error = reinterpret_cast<UINT32(*)(Parser*)>(0x612630)(&parser); // compile		5D7F70		//sub_405CD0 *v1


	int errors = *reinterpret_cast<UINT32*>(0x2EBD7F0); // get error count	37886C0

	reinterpret_cast<void(*)()>(0x446710)(); // close output file		//419F00

	if (error || errors) {
		g_Log.Add(LogError, L"Compilation failed, error count = %d", errors);
		Done(false);
	} else {
		g_Log.Add(LogError, L"Compilation done");
	}

	Done(true);
}

void Compiler::Done(bool status)
{
	if (close && status) {
		exit(0);
	}
	if (closeOnError && !status) {
		exit(1);
	}
	for (;;) {
		Sleep(100);
	}
}

