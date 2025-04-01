#pragma once
#include <windows.h>

class CPacket
{
	size_t pos;
	bool readonly;
	CHAR buff[16382];
	PUCHAR readBuff;
public:
	CPacket();
	CPacket(PUCHAR packet);
	CPacket(CHAR* packet, int Setsize);
	void WriteC(BYTE cData);
	void WriteH(INT16 hData);
	void WriteD(INT32 dData);
	void WriteF(double fData);
	void WriteE(float dData);
	void WriteQ(INT64 iData);
	void WriteB(int nBuffSize, PCHAR Buff);
	void WriteB(int nBuffSize, const unsigned char* Buff);
	void WriteS(PWCHAR wText);
	void WriteS(const wchar_t* wText);
	void WriteS2(const wchar_t* wszText);
	size_t GetSize();
	PCHAR GetBuff();
	PUCHAR GetBuffRead();
	BYTE ReadC();
	INT16 ReadH();
	INT32 ReadD();
	UINT ReadDU();
	INT64 ReadQ();
	double ReadF();
	PWCHAR ReadS();
	char *ReadB(int nLen);
	virtual ~CPacket();
};