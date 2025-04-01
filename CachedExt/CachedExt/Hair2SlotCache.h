#pragma once

class Hair2Slot {
public:
	static void Initialize();

	//hooke
	//LoadSelectedCharacter -> CUser::AssembleSSQInfo -> Assemble
	//append hair2 hairall dbid
	//ddd ddd ddd ddd
	//ddd ddd ddd ddd
	static int HookAssembleSSQInfo(char*, int, const char*, int, int, int, int, int, int, int, int, int, int, int, int);

	static void HookSocketSend(CSocket*, const char* format, int opcode, int nSocketIndex, int nBlobSize, char* nBlob);
	
};