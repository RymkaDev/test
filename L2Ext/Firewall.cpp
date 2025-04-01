#include "StdAfx.h"
#include "Firewall.h"
#include "HookManager.h"

CFirewall g_Firewall;

CFirewall::CFirewall() : hFile(0)
{
	memset(actionType, 0, sizeof(actionType));
	memset(minTimestamp, 0, sizeof(minTimestamp));
}

CFirewall::~CFirewall()
{
	if(hFile)
	{
		CloseHandle(hFile);
	}
}

void CFirewall::Init()
{
	g_Log.Add(CLog::Blue, "[%s] Initializing", __FUNCTION__);
	if( GetFileAttributes(TEXT("FirewallLog.txt")) != INVALID_FILE_ATTRIBUTES)
	{
		tm ti;
		time_t rawtime;
		time ( &rawtime );
		localtime_s(&ti, &rawtime );

		wstringstream newName;
		newName << "FirewallLog.txt." << (ti.tm_year+1900) << "-" << (ti.tm_mon+1) << "-" << ti.tm_mday << "-" << ti.tm_hour << "-" << ti.tm_min << ".bak";
		MoveFile(TEXT("FirewallLog.txt"), newName.str().c_str());
	}

	m_Lock.Enter();
	hFile = CreateFile(TEXT("FirewallLog.txt"), GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	m_Lock.Leave();
	AddLog(TEXT("Initializing"));
	LoadINI();
	if(enabled)
	{
		g_Log.Add(CLog::Blue, "[%s] Feature is enabled. Connection Limit[%d], Ban Duration[%d]", __FUNCTION__, m_banDuration);
	}else
	{
		g_Log.Add(CLog::Blue, "[%s] Feature is disabled.", __FUNCTION__);
	}
}

void CFirewall::LoadINI()
{
	TCHAR File[260];
	GetCurrentDirectory(MAX_PATH,File);
	lstrcat(File, TEXT("\\Firewall.ini"));
	const TCHAR* sectionName = TEXT("Firewall");
	enabled = GetPrivateProfileInt(sectionName, TEXT("Enabled"), 0, File);

	m_banDuration = GetPrivateProfileInt(sectionName, TEXT("BanDuration"), 300, File);

	{
		for(int n=0;n<256;n++)
		{
			wstringstream sName;
			if(n < 16 )
			{
				sName << L"OpCode_0" << uppercase << hex << n;
			}else
			{
				sName << L"OpCode_" << uppercase << hex << n;
			}

			WCHAR tmp[512];
			memset(tmp, 0, sizeof(tmp));

			if( GetPrivateProfileString(sectionName, sName.str().c_str(), 0, tmp, sizeof(tmp), File) )
			{
				int action = 0;
				DWORD timestamp = 0;
				wstringstream str(tmp);
				WCHAR c = 0;
				str >> timestamp >> c >> action;
				actionType[n] = action;
				minTimestamp[n] = timestamp;
		//		g_Log.Add(CLog::Blue, "Firewall setting: opcode[%x] loadedStr[%S] parsed: action[%d] timestamp[%d]", n, tmp, action, timestamp);
			}
		}
	}

}

void CFirewall::AddLog(wstring log)
{
	tm timeinfo;
	time_t rawtime;
	time ( &rawtime );
	localtime_s(&timeinfo, &rawtime );

	wstringstream str;

	str << (timeinfo.tm_year+1900) << L"/" << (timeinfo.tm_mon+1) << L"/" << timeinfo.tm_mday << L" " << timeinfo.tm_hour << L":" << timeinfo.tm_min << L":" << timeinfo.tm_sec << L" " << log << L"\n";
	
	DWORD written;
	wstring output(str.str());
	m_Lock.Enter();
	WriteFile(hFile, output.c_str(), (DWORD)(output.size() * 2), &written, NULL);
	m_Lock.Leave();
}

void CFirewall::OnPacketRecv(CUserSocket *pSocket, BYTE opCode, bool &drop, bool &kick)
{
	if(pSocket && enabled)
	{
		if( minTimestamp[opCode] > 0 )
		{
			//check timestamp
			DWORD currentTick = GetTickCount();
			//if( opCode == 0xCD )
			//	g_Log.Add(CLog::Error, "[%s] Debug1[%d] Debug2[%d] Diff[%d] OpCode[%x].", __FUNCTION__, pSocket->pED->packetTimestamp[opCode], currentTick, (pSocket->pED->packetTimestamp[opCode] - currentTick), opCode );

			if( pSocket->pED->packetTimestamp[opCode] > currentTick )
			{
				DWORD diff = pSocket->pED->packetTimestamp[opCode] - currentTick;
				switch(actionType[opCode] )
				{
				case ACTION_TYPE_LOG:
					{
						struct in_addr addr;
						pSocket->GetAddress(&addr);
						wstringstream str;
						if( pSocket->pUser->ValidUser() )
						{
							str << L"Packet flood opCode[" << hex << opCode << L"] diff time [" << dec << diff << L"] ms from IP[" << inet_ntoa(addr) << L"] User[" << pSocket->pUser->pSD->wszName << L"]";
						}else
						{
							str << L"Packet flood opCode[" << hex << opCode << L"] diff time [" << dec << diff << L"] ms from IP[" << inet_ntoa(addr) << L"]";
						}
						AddLog(str.str());
						break;
					}
				case ACTION_TYPE_DROP:
					{
						drop = true;
						break;
					}
				case ACTION_TYPE_LOG_DROP:
					{
						struct in_addr addr;
						pSocket->GetAddress(&addr);
						wstringstream str;
						if( pSocket->pUser->ValidUser() )
						{
							str << L"Packet flood opCode[" << hex << opCode << L"] diff time [" << dec << diff << L"] ms from IP[" << inet_ntoa(addr) << L"] User[" << pSocket->pUser->pSD->wszName << L"] - dropped";
						}else
						{
							str << L"Packet flood opCode[" << hex << opCode << L"] diff time [" << dec << diff << L"] ms from IP[" << inet_ntoa(addr) << L"] - dropped";
						}
						AddLog(str.str());
						drop = true;
						break;
					}
				case ACTION_TYPE_KICK:
					{
						kick = true;
						break;
					}
				case ACTION_TYPE_LOG_KICK:
					{
						struct in_addr addr;
						pSocket->GetAddress(&addr);
						wstringstream str;
						if( pSocket->pUser->ValidUser() )
						{
							str << L"Packet flood opCode[" << hex << opCode << L"] diff time [" << dec << diff << L"] ms from IP[" << inet_ntoa(addr) << L"] User[" << pSocket->pUser->pSD->wszName << L"] - kicked";
						}else
						{
							str << L"Packet flood opCode[" << hex << opCode << L"] diff time [" << dec << diff << L"] ms from IP[" << inet_ntoa(addr) << L"] - kicked";
						}
						AddLog(str.str());
						kick = true;
						break;
					}
				default:
					{
						break;
					}
				}
			}else
			{
				pSocket->pED->packetTimestamp[opCode] = currentTick + minTimestamp[opCode];
			}
		}
	}
}