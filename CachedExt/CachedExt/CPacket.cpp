#include "CachedExt.h"
#include "CPacket.h"

CPacket::CPacket()
{
	pos = 0;
	readonly = false;
	readBuff = NULL;
	memset(buff, 0, 16382);
}

CPacket::CPacket(PUCHAR packet)
{
	readBuff = packet;
	readonly = true;
	pos = 0;
}

CPacket::CPacket(CHAR* packet, int Setsize)
{
	//memset(buff, 0, 16382);
	memcpy(buff, packet, sizeof(buff));
	readonly = true;
	if(!Setsize)
		pos = 0;
	else
		pos = Setsize;
}

CPacket::~CPacket()
{
}

void CPacket::WriteC(BYTE cData)
{
	if(sizeof(BYTE) < (16382-pos))
	{
		*(BYTE*)(&buff[pos]) = cData;
		pos+=sizeof(BYTE);
	}else
		g_Log.Add(CLog::Error, "[%s] buffer overflow.", __FUNCTION__);
}

void CPacket::WriteH(INT16 iData)
{
	if(sizeof(INT16) < (16382-pos))
	{
		*(INT16*)(&buff[pos]) = iData;
		pos+=sizeof(INT16);
	}else
		g_Log.Add(CLog::Error, "[%s] buffer overflow.", __FUNCTION__);
}

void CPacket::WriteD(INT32 iData)
{
	if(sizeof(INT32) < (16382-pos))
	{
		*(INT32*)(&buff[pos]) = iData;
		pos+=sizeof(INT32);
	}else
		g_Log.Add(CLog::Error, "[%s] buffer overflow.", __FUNCTION__);
}

void CPacket::WriteF(double dData)
{
	if(sizeof(double) < (16382-pos))
	{
		*(double*)(&buff[pos]) = dData;
		pos+=sizeof(double);
	}else
		g_Log.Add(CLog::Error, "[%s] buffer overflow.", __FUNCTION__);
}

void CPacket::WriteE(float dData)
{
	if(sizeof(float) < (16382-pos))
	{
		*(float*)(&buff[pos]) = dData;
		pos+=sizeof(float);
	}else
		g_Log.Add(CLog::Error, "[%s] buffer overflow.", __FUNCTION__);
}

void CPacket::WriteQ(INT64 iData)
{
	if(sizeof(INT64) < (16382-pos))
	{
		*(INT64*)(&buff[pos]) = iData;
		pos+=sizeof(INT64);
	}else
		g_Log.Add(CLog::Error, "[%s] buffer overflow.", __FUNCTION__);
}

void CPacket::WriteB(int nBuffSize, PCHAR Buff)
{
	if(nBuffSize < (16382-pos))
	{
		memcpy_s(&buff[pos], (16382-pos), Buff, nBuffSize);
		pos+=nBuffSize;
	}
	else
		g_Log.Add(CLog::Error, "[%s] buffer overflow.", __FUNCTION__);
}

void CPacket::WriteB(int nBuffSize, const unsigned char* Buff)
{
	if(nBuffSize < (16382-pos))
	{
		memcpy_s(&buff[pos], (16382-pos), Buff, nBuffSize);
		pos+=nBuffSize;
	}
	else
		g_Log.Add(CLog::Error, "[%s] buffer overflow.", __FUNCTION__);
}

void CPacket::WriteS(PWCHAR wszText)
{
	size_t nLen = wcslen(wszText);
	nLen *= 2; nLen += 2;
	if(nLen < (16382-pos))
	{
		wcscpy_s((PWCHAR)&buff[pos], (16382-pos), wszText);
		pos += nLen;
	}
	else
		g_Log.Add(CLog::Error, "[%s] buffer overflow - required[%d] left[%d].", __FUNCTION__, nLen, (16382-pos));
}
void CPacket::WriteS(const wchar_t* wszText)
{
	size_t nLen = wcslen(wszText);
	nLen *= 2; nLen += 2;
	if(nLen < (16382-pos))
	{
		wcscpy_s((PWCHAR)&buff[pos], (16382-pos), wszText);
		pos += nLen;
	}
	else
		g_Log.Add(CLog::Error, "[%s] buffer overflow - required[%d] left[%d].", __FUNCTION__, nLen, (16382-pos));
}

void CPacket::WriteS2(const wchar_t* wszText)
{
	size_t nLen = wcslen(wszText);
	nLen *= 2; //nLen += 2;
	if(nLen < (16382-pos))
	{
		wcscpy((PWCHAR)&buff[pos], wszText);

		pos += nLen;
	}
	else
		g_Log.Add(CLog::Error, "[%s] buffer overflow - required[%d] left[%d].", __FUNCTION__, nLen, (16382-pos));
}

size_t CPacket::GetSize()
{
	return pos;
}

PCHAR CPacket::GetBuff()
{
	return buff;
}

/* Not needed atm - unfinished mby for trash */
PUCHAR CPacket::GetBuffRead()
{
	return readBuff;
}

BYTE CPacket::ReadC()
{
	BYTE bRetn = readBuff[pos];
	pos += sizeof(BYTE);
	return bRetn;
}

INT16 CPacket::ReadH()
{
	INT16 wRetn = *(INT16*)&readBuff[pos];
	pos += sizeof(INT16);
	return wRetn;
}

INT32 CPacket::ReadD()
{
	INT32 dRetn = *(INT32*)&readBuff[pos];
	pos += sizeof(INT32);
	return dRetn;
}

UINT CPacket::ReadDU()
{
	INT32 dRetn = *(UINT*)&readBuff[pos];
	pos += sizeof(UINT);
	return dRetn;
}

INT64 CPacket::ReadQ()
{
	INT64 dRetn = *(INT64*)&readBuff[pos];
	pos += sizeof(INT64);
	return dRetn;
}

double CPacket::ReadF()
{
	double dRetn = *(double*)&readBuff[pos];
	pos += sizeof(double);
	return dRetn;
}

PWCHAR CPacket::ReadS()
{
	PWCHAR wszStr = (PWCHAR)&readBuff[pos];
	size_t nLen = wcslen(wszStr);
	nLen *= 2;
	nLen += 2;
	pos += nLen;
	return wszStr;
}

char *CPacket::ReadB(int nLen)
{
	char *cBuff = (char*)&readBuff[pos];
	pos += nLen;
	return cBuff;
}