#pragma once

class CIOBuffer
{
public:
	/* 0000 */ int _unkn0000;
	/* 0004 */ int _unkn0004;
	/* 0008 */ int _unkn0008;
	/* 000C */ int _unkn000C;
	/* 0010 */ unsigned char buff[8192];
	/* 2010 */ int nPacketSize;
	/* 2014 */ int m_pNext;
	/* 2018 */ int m_RefCount;
	/* 201C */ int _unkn201C;
	/* 2020 */ int _unkn2020;
	/* 2024 */ int _unkn2024;
	/* 2028 */ int _unkn2028;
	/* 202C */ int m_threadIndex;
	/* 2030 */ int _unkn2030;
	/* 2034 */ int _unkn2034;
	/* 2038 */ int _unkn2038;
	/* 203C */ int _unkn203C;

	//Extended variables
	/* 2040 */ unsigned char buffEx[16384];
};