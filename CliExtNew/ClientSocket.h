#pragma once

class CClientSocket
{
public:
	/* 00 */ UINT _unkn00[18];
	/* 48 */ BYTE inBuff[0x4000];
	void Send(int len, char * buff);
	static void Init();
};