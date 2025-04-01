#include "stdafx.h"
#include "CliExt.h"
#include "DB.h"
#include "Encryption.h"
#include "L2NetworkVote.h"

CCliExt g_CliExt;
CLogger *m_Logger = 0;


std::vector<MemoryBotData> m_MemoryBotData;


std::vector<MemoryChangeData> m_MemoryChangeData;


void CCliExt::Init()
{
	m_AllowedHWIDHtml[0] = 0;
	m_AutoBanHWID = 0;
	LoadINI();
	if(m_Enabled)
	{
		g_Log.Add(CLog::Blue, "[%s] Feature is enabled - version [%d]. ", __FUNCTION__, m_Version);
		m_Logger = new CLogger(L"cliext");
		m_Logger->Add(L"Initializing log file.");
		g_HookManager.NopMemory(0x556D31, 5);
		g_HookManager.NopMemory(0x556D76, 5);
		g_HookManager.NopMemory(0x87F0BC, 5);
		g_HookManager.NopMemory(0x87F259, 5);
		g_HookManager.NopMemory(0x87F351, 5);
		g_HookManager.NopMemory(0x87F43B, 5);
		g_HookManager.NopMemory(0x87F529, 5);

		for(UINT n=0;n<256;n++)
		{
			m_CustomHandler[n] = CPHDummyPacket;
		}
		Bind(1, CPHPingExPacket);
		Bind(2, CPHHWIDPacket);
		Bind(6, CPHReplyL2NetworkVoteTime);
		Bind(10, CPHPingPacket);
		Bind(11, CPHReplyJobPacket);
		Bind(12, CPHReplyMD5Packet);
		Bind(13, CPHReplyMD5FilesPacket);
		Bind(28, CPHReplyProcessPacket);
		Bind(37, CPHReplyGetImagePacket);




		g_DB.RequestLoadBannedHardwareId();
	}
	CPacketEncryption::Init();
}

void CCliExt::LoadINI()
{
	const TCHAR* section = _T("CliExt");
	m_Enabled = GetPrivateProfileInt(section, _T("Enabled"), 0, g_ConfigFile);
	m_Version = GetPrivateProfileInt(section, _T("Version"), 0, g_ConfigFile);
	m_BoxLimit = GetPrivateProfileInt(section, _T("BoxLimit"), 0, g_ConfigFile);
	m_AutoBanHWID = GetPrivateProfileInt(section, _T("AutoBanHWID"), 0, g_ConfigFile);
	m_DisablePingPacket = GetPrivateProfileInt(section, _T("DisablePingPacket"), 0, g_ConfigFile);
	m_BoxLimitHTML[0] = 0;
	GetPrivateProfileString(section, _T("ReachedBoxLimitHtml"), 0, m_BoxLimitHTML, 0x4000, g_ConfigFile);
	m_BannedHWIDHTML[0] = 0;
	GetPrivateProfileString(section, _T("BannedHwidHtml"), 0, m_BannedHWIDHTML, 0x4000, g_ConfigFile);
	m_LockedCharacterHTML[0] = 0;
	GetPrivateProfileString(section, _T("LockedCharacterHtml"), 0, m_LockedCharacterHTML, 0x4000, g_ConfigFile);
	m_LockedAccountHTML[0] = 0;
	GetPrivateProfileString(section, _T("LockedAccountHtml"), 0, m_LockedAccountHTML, 0x4000, g_ConfigFile);
	m_AllowedHWIDHtml[0] = 0;
	GetPrivateProfileString(section, _T("AllowedHWIDHtml"), 0, m_AllowedHWIDHtml, 0x4000, g_ConfigFile);



	m_EnabledAntiAdrenaline = GetPrivateProfileInt(section, _T("EnabledAntiAdrenaline"), 0, g_ConfigFile);
	m_VerificarThreadMuerto = GetPrivateProfileInt(section, _T("VerificarThreadMuerto"), 0, g_ConfigFile);
	m_PatternName[0] = 0;
	GetPrivateProfileString(section, _T("PatternName"), 0, m_PatternName, 0x4000, g_ConfigFile);
	// Aplicar XOR a cada WCHAR en la cadena m_PatternName
	WCHAR xorKey = 0x01;
	int len = wcslen(m_PatternName);
	for (int i = 0; i < len; i++) {
		if (m_PatternName[i] != 0x00) {
			m_PatternName[i] ^= xorKey;
		}
	}

	m_PatternMask[0] = 0;
	GetPrivateProfileString(section, _T("PatternMask"), 0, m_PatternMask, 0x4000, g_ConfigFile);




	m_PatternName2[0] = 0;
	GetPrivateProfileString(section, _T("PatternName2"), 0, m_PatternName2, 0x4000, g_ConfigFile);
	// Aplicar XOR a cada WCHAR en la cadena m_PatternName
	WCHAR xorKey2 = 0x01;
	int len2 = wcslen(m_PatternName2);
	for (int i = 0; i < len; i++) {
		if (m_PatternName2[i] != 0x00) {
			m_PatternName2[i] ^= xorKey2;
		}
	}

	m_PatternMask2[0] = 0;
	GetPrivateProfileString(section, _T("PatternMask2"), 0, m_PatternMask2, 0x4000, g_ConfigFile);



	m_PatternName3[0] = 0;
	GetPrivateProfileString(section, _T("PatternName3"), 0, m_PatternName3, 0x4000, g_ConfigFile);
	// Aplicar XOR a cada WCHAR en la cadena m_PatternName
	WCHAR xorKey3 = 0x01;
	int len3 = wcslen(m_PatternName3);
	for (int i = 0; i < len; i++) {
		if (m_PatternName3[i] != 0x00) {
			m_PatternName3[i] ^= xorKey3;
		}
	}

	m_PatternMask3[0] = 0;
	GetPrivateProfileString(section, _T("PatternMask3"), 0, m_PatternMask3, 0x4000, g_ConfigFile);


	TCHAR temp2[0x8000];

	m_ListaBlancaExe.clear();
	if(GetPrivateProfileString(section, _T("ListaBlancaExe"), 0, temp2, 0x8000, g_ConfigFile))
	{
		wstring limpio;
		wstringstream ExeStreamTmp(temp2);
		ExeStreamTmp >> limpio;

		limpio = Utils::ReplaceStringW(limpio, L"{", L"", true);
		limpio = Utils::ReplaceStringW(limpio, L"}", L"", true);
		limpio = Utils::ReplaceStringW(limpio, L";", L" ", true);

		wstringstream ExeStream(limpio);
		wstring wExe;
		while(ExeStream >> wExe)
		{
			m_ListaBlancaExe.push_back(wExe);
		}
	}




	TCHAR temp[0x8000];

	m_MD5Checksum.clear();
	if(GetPrivateProfileString(section, _T("MD5Checksum"), 0, temp, 0x8000, g_ConfigFile))
	{
		wstring limpio;
		wstringstream hwidStreamTmp(temp);
		hwidStreamTmp >> limpio;

		limpio = Utils::ReplaceStringW(limpio, L"{", L"", true);
		limpio = Utils::ReplaceStringW(limpio, L"}", L"", true);
		limpio = Utils::ReplaceStringW(limpio, L";", L" ", true);

		wstringstream hwidStream(limpio);
		wstring wHwid;
		while(hwidStream >> wHwid)
		{
			HWID hwid(wHwid);
			m_MD5Checksum.push_back(hwid);
		}
	}






	m_OutdatedClientHTML[0] = 0;
	GetPrivateProfileString(section, _T("OutdatedClientHtml"), 0, m_OutdatedClientHTML, 0x4000, g_ConfigFile);

	m_AllowedHWID.clear();
	if(GetPrivateProfileString(section, _T("AllowedHWIDList"), 0, temp, 0x8000, g_ConfigFile))
	{
		wstringstream hwidStream(temp);
		wstring wHwid;
		while(hwidStream >> wHwid)
		{
			HWID hwid(wHwid);
			m_AllowedHWID.push_back(hwid);
		}
	}


	m_BloquearLogin = GetPrivateProfileInt(section, _T("BloquearLogin"), FALSE, g_ConfigFile);

	m_BloquearLoginHTML[0] = 0;
	GetPrivateProfileString(section, _T("BloquearLoginHtml"), 0, m_BloquearLoginHTML, 0x4000, g_ConfigFile);


	m_MemoryBotData.clear();
//MEMORY PROTECTION
   for (int id = 1; ; id++)  // Asumimos que los IDs son secuenciales y comenzamos desde 1
    {
        TCHAR keyName[256];


		TCHAR buffer[256];
		_stprintf(keyName, _T("%d_MemoryAddress"), id);
		GetPrivateProfileString(_T("MEMORY_PROTECTOR"), keyName, _T(""), buffer, sizeof(buffer) / sizeof(TCHAR), g_ConfigFile);

		// Convierte la cadena a entero considerando base 16
		int memoryaddr;
		if (_stscanf(buffer, _T("%x"), &memoryaddr) != 1)
		{
			// Error en la conversión
			memoryaddr = 0; // o maneja el error como lo necesites
		}


        if (memoryaddr == 0)  // Si no encontramos el MemoryAddress, asumimos que hemos terminado
            break;

        _stprintf(keyName, _T("%d_Data"), id);
        TCHAR dataString[256];
        GetPrivateProfileString(_T("MEMORY_PROTECTOR"), keyName, _T(""), dataString, sizeof(dataString) / sizeof(TCHAR), g_ConfigFile);


        _stprintf(keyName, _T("%d_Cantidad"), id);
        int cantidad = GetPrivateProfileInt(_T("MEMORY_PROTECTOR"), keyName, 0, g_ConfigFile);

        BYTE Data[256];  // Asegúrate de tener suficiente espacio
        int count = 0;
        TCHAR* token = _tcstok(dataString, _T(","));
        while (token != NULL && count < sizeof(Data))
        {
            Data[count++] = static_cast<BYTE>(_tcstoul(token, NULL, 16));  // Convierte de hex string a BYTE
            token = _tcstok(NULL, _T(","));
        }


        MemoryBotData m_MemoryBotData_tmp;

		m_MemoryBotData_tmp.id = id;
		m_MemoryBotData_tmp.memoryaddr = memoryaddr;
		m_MemoryBotData_tmp.cantidad = count;
        memcpy(m_MemoryBotData_tmp.Data, Data, count);

        m_MemoryBotData.push_back(m_MemoryBotData_tmp);
    }
//FIN MEMORY PROTECTION


	m_MemoryChangeData.clear();
//MEMORY PROTECTION
   for (int id = 1; ; id++)  // Asumimos que los IDs son secuenciales y comenzamos desde 1
    {
        TCHAR keyName[256];


		TCHAR bufferW[256];
		_stprintf(keyName, _T("%d_DllName"), id);
		GetPrivateProfileString(_T("FIX_HOOK_CLIENT"), keyName, _T(""), bufferW, sizeof(bufferW) / sizeof(TCHAR), g_ConfigFile);



		TCHAR buffer[256];
		_stprintf(keyName, _T("%d_MemoryAddress"), id);
		GetPrivateProfileString(_T("FIX_HOOK_CLIENT"), keyName, _T(""), buffer, sizeof(buffer) / sizeof(TCHAR), g_ConfigFile);

		// Convierte la cadena a entero considerando base 16
		int memoryaddr;
		if (_stscanf(buffer, _T("%x"), &memoryaddr) != 1)
		{
			// Error en la conversión
			memoryaddr = 0; // o maneja el error como lo necesites
		}


        if (memoryaddr == 0)  // Si no encontramos el MemoryAddress, asumimos que hemos terminado
            break;

        _stprintf(keyName, _T("%d_Data"), id);
        TCHAR dataString[256];
        GetPrivateProfileString(_T("FIX_HOOK_CLIENT"), keyName, _T(""), dataString, sizeof(dataString) / sizeof(TCHAR), g_ConfigFile);


        BYTE Data[256];  // Asegúrate de tener suficiente espacio
        int count = 0;
        TCHAR* token = _tcstok(dataString, _T(","));
        while (token != NULL && count < sizeof(Data))
        {
            Data[count++] = static_cast<BYTE>(_tcstoul(token, NULL, 16));  // Convierte de hex string a BYTE
            token = _tcstok(NULL, _T(","));
        }


        MemoryChangeData m_MemoryChangeData_tmp;

		m_MemoryChangeData_tmp.id = id;
		m_MemoryChangeData_tmp.dllName = bufferW;
		m_MemoryChangeData_tmp.memoryaddr = memoryaddr;
		m_MemoryChangeData_tmp.cantidad = count;
        memcpy(m_MemoryChangeData_tmp.Data, Data, count);

        m_MemoryChangeData.push_back(m_MemoryChangeData_tmp);
    }
//FIN MEMORY PROTECTION




	const TCHAR* section_files = _T("CliExt_Files");
	m_Enabled_files = GetPrivateProfileInt(section_files, _T("Enabled"), 0, g_ConfigFile);


	m_MostrarMensajesConsola = GetPrivateProfileInt(section_files, _T("MostrarMensajesConsola"), 0, g_ConfigFile);

	m_MD5ChecksumFiles.clear();
	if(m_Enabled_files)
	{
		for(UINT n=1;n<=300;n++)
		{
			TCHAR sString[8192];
			tstringstream skey;
			skey << "File_" << n;
			if(GetPrivateProfileString(section_files ,skey.str().c_str(), 0, sString, 8190, g_ConfigFile))
			{
				vector<HWID> tmp_vector;
				memset(&tmp_vector, 0, sizeof(tmp_vector));
				wstring tmp_filename;

				tstringstream sstr; sstr << sString;
				tstring sValue;
				while(sstr >> sValue)
				{
					tstring datos =L"";
					datos = Utils::ReplaceStringW(sValue, L"{{", L"{", true);
					datos = Utils::ReplaceStringW(datos, L"}", L"", true);
					datos = Utils::ReplaceStringW(datos, L"[", L"", true);
					datos = Utils::ReplaceStringW(datos, L"]", L"", true);
					datos = Utils::ReplaceStringW(datos, L";", L"", true);

					int contador2 = 0;
					std::wstring subs2;
					std::wstringstream wss2(datos);
					while(std::getline(wss2, subs2, L'{'))
					{

						if(contador2==1)	//nombre archivo
						{
							tmp_filename = subs2.c_str();
						}
						if(contador2 > 1)	//nombre archivo
						{
							HWID hwid(subs2);
							tmp_vector.push_back(hwid);	
						}
						contador2++;
					}

					m_MD5ChecksumFiles.insert ( std::pair<wstring,vector<HWID>>(tmp_filename.c_str(),tmp_vector) );
				}
			}
		}

//		map<wstring, vector<HWID>>::iterator Iter;
//		for(Iter = m_MD5ChecksumFiles.begin();Iter != m_MD5ChecksumFiles.end();Iter++)
//		{
//			for(UINT i=0;i<Iter->second.size();i++)
//			{
//				g_Log.Add(CLog::Error, "%S : %S",Iter->first.c_str(), Iter->second[i].ToString().c_str());
//			}
//		}
	}
}


bool CPHReplyGetImagePacket(CUserSocket *pSocket, const unsigned char* packet)
{
	guard;
	bool ret = false;

	UINT size = 0;
	packet = Disassemble(packet, "d", &size);


	BYTE imagen[16000];
	packet = Disassemble(packet, "b", size, imagen);

    std::ofstream outFile("imagen.dat", std::ios::out | std::ios::binary | std::ios::app);
    if (outFile.is_open()) {
        outFile.write((char*)imagen, sizeof(imagen));
        outFile.close();
    } else {
        std::cerr << "No se pudo abrir el archivo para escribir" << std::endl;
    }


	unguard;
	return ret;
}




bool CPHReplyProcessPacket(CUserSocket *pSocket, const unsigned char* packet)
{
	guard;
	bool ret = false;

	UINT checkSum = 0;
	packet = Disassemble(packet, "d", &pSocket->pED->TrheadProccesAdrenaline);

	unguard;
	return ret;
}


bool CPHReplyMD5FilesPacket(CUserSocket *pSocket, const unsigned char* packet)
{
	CTL;
	BYTE md5[32];


	WCHAR filename[255] = { 0 };
	Disassemble(packet, "bS", sizeof(md5), md5, sizeof(filename), filename);

	//g_Log.Add(CLog::Error, "file: %S  ", filename);

	if(!g_CliExt.IsAllowedMD5File(filename,md5))
	{
		//Si no coincide entra aca

		pSocket->lastUsedPacketID = 0x0E;
		pSocket->Send("cdSd", 0xF, 0, g_CliExt.GetOutdatedClientHtml(), 0);

		pSocket->pED->FileCorrupt = true;

		char sHwid[33];
		memset(sHwid, 0, 33);
		memcpy(sHwid, md5, 32);

		if(g_CliExt.m_MostrarMensajesConsola)
		{
			wstring file = filename;
			for (std::wstring::size_type z = 0; z < file.size(); ++z)
				file[z] ^= 5;

			g_Log.Add(CLog::Error, "Archivo no permitido en [CliExt_Files]: ACCOUNT[%S] FILE[%S] CLIENT_MD5[%s]", pSocket->accountName, file.c_str(), sHwid);
		}
	}
	else
	{
		pSocket->pED->FileCorruptCounter++;
	}

	return false;
}


bool CCliExt::IsAllowedMD5File(wstring file,LPBYTE lpHwid)
{
	guard;
	bool ret = false;

	HWID hwid(lpHwid);

	if(hwid.IsNull())
		ret = true;

	for (std::wstring::size_type z = 0; z < file.size(); ++z)
		file[z] ^= 5;


	std::map<wstring, vector<HWID>>::iterator Iter(m_MD5ChecksumFiles.find(file));
	if (Iter != m_MD5ChecksumFiles.end()) 
	{
		if(Iter->second.size() > 0)
		{
			for(UINT n=0;n<Iter->second.size();n++)
			{
				if(Iter->second[n].IsEqual(hwid))
				{
					ret = true;
					break;
				}
			}
		}else
		{
			ret = true;
		}
	}

	unguard;
	return ret;
}




void CCliExt::Bind(UINT id, CPHandler func)
{
	if(id < 256)
	{
		m_CustomHandler[id] = func;
	}
}


void CCliExt::OnBanDBLoad(LPBYTE lpHwid, wstring account, wstring gmName, UINT timeout, UINT times)
{
	guard;

	m_BannedLock.Enter();

	bool exist = false;
	//check if alrady exist to avoid doubles
	for(UINT n=0;n<m_Banned.size();n++)
	{
		if(!memcmp(lpHwid, m_Banned[n].hash, 32))
		{
			//update timeout
			m_Banned[n].timeout = timeout;
			m_Banned[n].times = times;
			exist = true;
			break;
		}
	}
	if(!exist)
	{
		if(timeout > time(0))
		{
			BannedHardwareId bhi;
			memcpy(&bhi.hash[0], lpHwid, 32);
			bhi.GMName = gmName;
			bhi.accountName = account;
			bhi.timeout = timeout;
			bhi.times = times;
			m_Banned.push_back(bhi);
		}
	}

	m_BannedLock.Leave();

	unguard;
}


void CCliExt::GetAllowedHWIDHtml(HWID& hwid, WCHAR* wHtml)
{
	guard;

	wstring html = Utils::ReplaceString(m_AllowedHWIDHtml, L"<?HWID?>", hwid.ToString(), true);

	wcscpy(wHtml, html.c_str());

	unguard;
}

bool CCliExt::IsBanned(LPBYTE lpHwid)
{
	guard;
	bool ret = false;
	m_BannedLock.Enter();
	for(UINT n=0;n<m_Banned.size();n++)
	{
		if(!memcmp(lpHwid, m_Banned[n].hash, 32))
		{
			if(m_Banned[n].timeout > time(0))
			{
				ret = true;
			}
			break;
		}
	}
	m_BannedLock.Leave();
	unguard;
	return ret;
}

bool CCliExt::IsAllowed(LPBYTE lpHwid)
{
	guard;
	bool ret = false;

	HWID hwid(lpHwid);

	if(m_AllowedHWID.size() > 0)
	{
		for(UINT n=0;n<m_AllowedHWID.size();n++)
		{
			if(m_AllowedHWID[n].IsEqual(hwid))
			{
				ret = true;
				break;
			}
		}
	}else
	{
		ret = true;
	}

	unguard;
	return ret;
}

bool CCliExt::IsAllowedMD5(LPBYTE lpHwid)
{
	guard;
	bool ret = false;

	HWID hwid(lpHwid);

	if(m_MD5Checksum.size() > 0)
	{
		for(UINT n=0;n<m_MD5Checksum.size();n++)
		{
			if(m_MD5Checksum[n].IsEqual(hwid))
			{
				ret = true;
				break;
			}
		}
	}else
	{
		ret = true;
	}

	unguard;
	return ret;
}

bool CCliExt::UnBan(LPBYTE lpHwid, wstring gmName)
{
	guard;
	bool ret = false;

	m_BannedLock.Enter();
	for(vector<BannedHardwareId>::iterator it = m_Banned.begin(); it!= m_Banned.end(); it++)
	{
		if(!memcmp(lpHwid, it->hash, 32))
		{
			m_Banned.erase(it);
			ret = true;
			break;
		}
	}
	m_BannedLock.Leave();

	if(ret)
	{
		char sHwid[33];
		memset(sHwid, 0, 33);
		memcpy(sHwid, lpHwid, 32);
		g_Log.Add(CLog::Blue, "[%s] GM[%S] HWID[%s]", __FUNCTION__, gmName.c_str(), sHwid);
		g_DB.RequestUnBanHardwareId(lpHwid);
	}
	unguard;
	return ret;
}

void CCliExt::Ban(LPBYTE lpHwid, wstring account, wstring gmName, UINT timeout)
{
	guard;
	m_BannedLock.Enter();
	int banned_times = 0;
	UINT finaltimeout = 0;
	bool exist = false;
	for(UINT n=0;n<m_Banned.size();n++)
	{
		if(!memcmp(lpHwid, m_Banned[n].hash, 32))
		{
			exist = true;
			m_Banned[n].timeout = timeout + time(0);

			finaltimeout = m_Banned[n].timeout;
			break;
		}
	}
	if(!exist)
	{
		BannedHardwareId bhi;
		bhi.accountName = account;
		bhi.GMName = gmName;
		bhi.timeout = time(0) + timeout;
		bhi.times = 1;
		banned_times = 1;
		memcpy(bhi.hash, lpHwid, 32);

		finaltimeout = bhi.timeout;
		m_Banned.push_back(bhi);
	}
	m_BannedLock.Leave();
	char sHwid[33];
	memset(sHwid, 0, 33);
	memcpy(sHwid, lpHwid, 32);

	g_DB.RequestBanHardwareId(lpHwid, account.c_str(), gmName.c_str(), finaltimeout, banned_times);
	g_Log.Add(CLog::Blue, "[%s] GM[%S] HWID[%s] - Account[%S] - timeout[%d], times[%d]", __FUNCTION__, gmName.c_str(), sHwid, account.c_str(), timeout, banned_times);
	unguard;
}

void CCliExt::HandleCheckSum(CUserSocket *pSocket, const unsigned char *packet, UINT packetSize)
{
	guard;
	if(packetSize > 4)
	{
		packetSize-=4;
		UINT csBase = (*(PUINT)&packet[packetSize]);
		if(csBase == pSocket->pED->packetCS.previous)
		{
			pSocket->pED->packetCS.current = csBase;
			unguard;
			return;
		}

		UINT csKey = pSocket->pED->packetCS.key;
		if(packet[0] == 8)
		{
			csKey = 0;
		}
		UINT checkSum = 0;
		csKey++;
		if((csKey % 2) == 0)
		{
			checkSum = 0x13243546;
		}else
		{
			checkSum = 0x98786756;
		}
		UINT sum = 0;
		for(UINT n=0;n<packetSize;n++)
		{
			sum += static_cast<UINT>(packet[n]);
		}
		checkSum += sum;
		UtB cs;
		cs.full = checkSum;
		for(int n=0;n<4;n++)
		{
			cs.part[n] += 75;
			cs.part[n] *= packetSize+n+csKey;
		}

		checkSum = cs.full;
		checkSum += csKey;
		checkSum += packetSize;
		csKey += packetSize;
		pSocket->pED->packetCS.calculated = checkSum;
		pSocket->pED->packetCS.current = csBase;
		pSocket->pED->packetCS.key = csKey;
		if(checkSum != csBase)
		{
			CHAR sHWID[33];
			memset(sHWID, 0, sizeof(sHWID));
			memcpy(sHWID, pSocket->pED->longHWID.hash, 32);
			if(true)
			{
				g_Logger.Add(L"Invalid packet checksum[%u] vs [%u] packet[%x] len[%d] sum[%d] key[%d] HWID[%S] Account[%s]!", checkSum, csBase, packet[0], packetSize, sum, csKey, sHWID, pSocket->accountName);
				g_Log.Add(CLog::Error, "[%s] Invalid Checksum[%d] vs [%d] packet[%x] len[%d] sum[%d] key[%d] HWID[%s] Account[%S]!", __FUNCTION__, checkSum, csBase, packet[0], packetSize, sum, csKey, sHWID, pSocket->accountName);
			}
		}
	}else
	{
		pSocket->pED->packetCS.current = -1;
		pSocket->pED->packetCS.calculated = 0;
	}
	unguard;
}

void CCliExt::DecryptPacket(CUserSocket *pSocket, unsigned char *packet, UINT packetSize)
{
	guard;
	
	static BYTE staticKey1[8][32] = { 0x5A, 0xF8, 0xEB, 0x8E, 0x05, 0x0C, 0xC2, 0x46, 0xB4, 0xAA, 0xCC, 0x97, 0x59, 0x5A, 0x0E, 0x24, 0x27, 0xF0, 0x58, 0xE5, 0x42, 0x1E, 0xCA, 0xF6, 0x5C, 0x2C, 0xFC, 0x37, 0xB0, 0x25, 0xE3, 0x86, 0xB6, 0x38, 0x66, 0x6B, 0xF6, 0x5B, 0xC4, 0x87, 0x2D, 0x70, 0x0A, 0xF4, 0x35, 0x2E, 0x5E, 0x48, 0xAB, 0xB7, 0xA6, 0xE6, 0x87, 0xCD, 0xB0, 0xF2, 0xB1, 0xAA, 0xAD, 0x2C, 0x0C, 0xB6, 0x4C, 0xAF, 0x1C, 0x88, 0x34, 0x1D, 0x98, 0xD9, 0x08, 0x5C, 0xFD, 0x27, 0xAB, 0x05, 0x98, 0x10, 0xA8, 0x96, 0xD4, 0x9E, 0xF2, 0xFD, 0x5D, 0x90, 0xA0, 0x4B, 0xF1, 0xA6, 0xA8, 0x16, 0x7D, 0x8F, 0x58, 0x62, 0x50, 0x8C, 0x8A, 0x3D, 0xD8, 0x6D, 0xC2, 0x49, 0x81, 0x7C, 0x66, 0xBC, 0xEB, 0x13, 0xC9, 0xB6, 0x96, 0x5A, 0xA9, 0x56, 0x36, 0x74, 0xBC, 0xC1, 0x64, 0x14, 0x9B, 0x6C, 0x27, 0xEA, 0x97, 0xEC, 0x93, 0xA9, 0x2F, 0x67, 0x4D, 0x97, 0x59, 0x87, 0x44, 0xF7, 0x1D, 0x0E, 0xC2, 0x13, 0xDD, 0x75, 0x70, 0xA9, 0x16, 0xEA, 0xFC, 0xFA, 0xC7, 0xC6, 0xA0, 0xCD, 0x42, 0xED, 0x7C, 0x94, 0x66, 0xE5, 0x29, 0xEC, 0x00, 0xB9, 0x5D, 0xAE, 0x47, 0x18, 0x21, 0x88, 0x4F, 0xC7, 0xED, 0x48, 0x9A, 0xAA, 0x52, 0x44, 0x1B, 0xDF, 0x0B, 0x04, 0x25, 0xFB, 0xAC, 0x0D, 0x1F, 0x89, 0x21, 0x5A, 0x1A, 0xA2, 0x69, 0x02, 0x34, 0xA0, 0xEF, 0x84, 0xCA, 0xB1, 0xCA, 0x96, 0x53, 0xA2, 0x61, 0x22, 0xDD, 0x9E, 0x0A, 0x0E, 0x48, 0x51, 0x02, 0x41, 0xBE, 0xF3, 0xA2, 0x73, 0x41, 0x27, 0x59, 0xDD, 0x54, 0x76, 0x93, 0x5C, 0x32, 0x96, 0xBF, 0x8D, 0xED, 0x11, 0x25, 0x07, 0x0E, 0x99, 0x71, 0x3A, 0x77, 0xBB, 0x34, 0xC5, 0xD6, 0x51, 0xE8, 0xED, 0x65, 0xC3, 0x15, 0x90, 0x8E, 0x39, 0x73, 0xC6, 0x70, 0x12 };
	static BYTE staticKey2[8][32] = { 0x4e, 0x4, 0x17, 0x10, 0x6b, 0x27, 0x6d, 0xba, 0xb, 0x67, 0xb9, 0xd0, 0xe0, 0x79, 0xcc, 0x5d, 0x21, 0xf2, 0xe1, 0x62, 0xd3, 0x4f, 0x31, 0x85, 0x6e, 0x4c, 0x60, 0x4, 0x72, 0x6b, 0x7, 0xf0, 0x51, 0x1f, 0x42, 0xce, 0xa5, 0xe1, 0x8, 0xf2, 0x28, 0xb1, 0x20, 0xcb, 0xdb, 0xd4, 0x98, 0x7a, 0xdb, 0xbe, 0xfc, 0xd8, 0x52, 0xfd, 0xad, 0x5a, 0x72, 0x29, 0xb0, 0xdd, 0x0, 0x84, 0xbc, 0x66, 0xc3, 0xfd, 0x6a, 0xcc, 0x0, 0xa5, 0x49, 0xdd, 0xac, 0xc2, 0xbf, 0xfb, 0x9d, 0xae, 0xf8, 0x2d, 0xdd, 0x95, 0x48, 0x46, 0x5c, 0x45, 0x3a, 0xf5, 0x32, 0x21,  0xcc, 0x2, 0xa2, 0x7c, 0xf8, 0xeb, 0x9f, 0x57, 0x86, 0xc4, 0x69, 0x44, 0x66, 0x2, 0x29, 0x7, 0xef, 0xf7, 0xfd, 0x1b, 0xd2, 0x68, 0x71, 0xbb, 0x9c, 0xbc, 0xd2, 0x1c, 0xd, 0x58, 0x50, 0xe9, 0xae, 0xa1, 0xe8, 0x4f, 0x61, 0x2d, 0x0, 0x76, 0xd2, 0x25, 0x37, 0x5e, 0x16, 0xd6, 0xd2, 0x0, 0xcc, 0xd, 0xbb, 0x81, 0x8d, 0x12, 0x6, 0x5, 0x97, 0x7, 0xfd, 0xce, 0x61, 0x74, 0x93, 0xd0, 0x16, 0x23, 0xbe, 0x50, 0xa1, 0xcb, 0xa3, 0xbc, 0xcc, 0x90, 0xa2, 0x6b, 0x15, 0x4b, 0x82, 0xc3, 0x35, 0xb9, 0xf6, 0x1e, 0x16, 0x2, 0x2c, 0x5d, 0x19, 0x22, 0x87, 0x80, 0x72, 0x30, 0xe6, 0x33, 0x82, 0x1f, 0x79, 0x24, 0xe6, 0xda, 0xf0, 0x9e, 0xb8, 0x5e, 0xc5, 0x36, 0xa2, 0x3e, 0x35, 0x7a, 0xcf, 0x31, 0x36, 0xfe, 0x5e, 0x88, 0x1a, 0xc2, 0x48, 0xbb, 0xfb, 0x24, 0x84, 0xe6, 0xd9, 0x5, 0xbc, 0xe4, 0x4f, 0xc4, 0xe5, 0x61, 0xed, 0x24, 0x1d, 0x16, 0xa1, 0x5d, 0x1, 0x6, 0xb, 0xe1, 0x83, 0xdb, 0xe2, 0x89, 0xd8, 0xe6, 0xa9, 0x47, 0x8d, 0x3b, 0xd0, 0x3, 0xda, 0x69, 0x9d, 0x4e, 0xcc, 0xf2, 0xdc, 0xfe, 0xd3, 0xdc };
	static BYTE staticKey3[8][32] = { 0x8, 0x6c, 0x14, 0x96, 0x32, 0xa6, 0x9d, 0xa6, 0x8d, 0xed, 0xa2, 0x3b, 0x2e, 0x6, 0x53, 0xd8, 0xc6, 0x7b, 0x73, 0x3b, 0x83, 0x43, 0x52, 0x98, 0xc2, 0x9a, 0x8b, 0x82, 0x3a, 0xd6, 0x66, 0xdc, 0x79, 0xd3, 0x13, 0x50, 0x79, 0x88, 0x96, 0x93, 0x1f, 0x97, 0xaf, 0x4, 0x38, 0x55, 0x5e, 0xf3, 0x28, 0x26, 0x92, 0xfb, 0x83, 0x82, 0x7f, 0xf3, 0xee, 0xc1, 0x1f, 0x9d, 0x7e, 0xca, 0x7f, 0xde, 0xeb, 0xe0, 0x37, 0x78, 0xe5, 0xaa, 0xc3, 0xc, 0xa3, 0x90, 0x1f, 0x88, 0x4a, 0xc7, 0x46, 0xa9, 0x19, 0xe9, 0xe, 0xa4, 0xdf, 0x89, 0xf1, 0xc2, 0xf1, 0xb3, 0x4c, 0xf8, 0xe5, 0xb8, 0x93, 0x41, 0x46, 0x25, 0x9, 0xb2, 0xc8, 0x58, 0x80, 0x35, 0xee, 0xb0, 0xb7, 0xc1, 0xc2, 0x8c, 0xc2, 0x18, 0x8f, 0x1f, 0x22, 0xbe, 0x37, 0xa3, 0xf9, 0x51, 0x33, 0x8c, 0x9, 0xef, 0x9e, 0x50, 0xcf, 0xc1, 0x93, 0xb4, 0x77, 0x70, 0x1a, 0xe4, 0x16, 0x7c, 0xf5, 0x57, 0xa1, 0x6d, 0xa2, 0xd4, 0x74, 0x99, 0xad, 0xa4, 0x72, 0x9a, 0xda, 0x2a, 0xd3, 0x30, 0x38, 0xe5, 0xb4, 0xa2, 0x81, 0x49, 0x48, 0x61, 0x6, 0x38, 0xdd, 0xdf, 0x7c, 0xae, 0xac, 0x97, 0xd6, 0x63, 0x71, 0x15, 0x97, 0xde, 0xe0, 0xda, 0xba, 0xdf, 0xf, 0x50, 0xbf, 0x7b, 0xa0, 0x39, 0xb5, 0xee, 0x18, 0x0, 0xc, 0x68, 0xf4, 0x6d, 0xfb, 0xd6, 0xfa, 0x4, 0x3b, 0x14, 0x5e, 0x86, 0xd7, 0x45, 0x22, 0x3, 0xf0, 0xf2, 0x7a, 0xc7, 0x2c, 0xbf, 0x6a, 0xc1, 0x82, 0x2, 0x68, 0x8f, 0x87, 0x54, 0x5f, 0xb5, 0x66, 0x72, 0xbf, 0x79, 0xf9, 0x46, 0xfc, 0x9d, 0x45, 0x83, 0x2b, 0x90, 0x6a, 0xeb, 0x17, 0x4e, 0xaf, 0x5b, 0x97, 0x9a, 0x93, 0xb9, 0x62, 0x96, 0x6c, 0x28, 0x20, 0x9a, 0xae, 0x4f, 0x24, 0x41, 0x61, 0x3e, 0x72, 0x61 };
	static BYTE staticKey4[8][32] = { 0xcf, 0xc8, 0x92, 0x6e, 0xb2, 0x65, 0x22, 0xf1, 0x83, 0x24, 0x93, 0xda, 0x3b, 0x10, 0x6c, 0x26, 0xd2, 0xf6, 0x76, 0x5e, 0x5f, 0xd8, 0x8b, 0xe2, 0x8f, 0xef, 0xa6, 0x52, 0x5b, 0x55, 0x10, 0xa1, 0xec, 0xc9, 0x19, 0x86, 0x90, 0xb3, 0x55, 0x88, 0xa0, 0xce, 0x9b, 0x68, 0x4a, 0x9c, 0xe5, 0x5f, 0x28, 0x16, 0x44, 0xac, 0x80, 0xb7, 0xf6, 0x11, 0x2c, 0x53, 0xf9, 0xb1, 0xdc, 0xcb, 0xfd, 0xdd, 0x6, 0x3c, 0x26, 0x74, 0xc8, 0x7c, 0x79, 0x19, 0x69, 0xab, 0x7a, 0x2a, 0x9f, 0xb0, 0xbe, 0x98, 0x25, 0x44, 0xe8, 0x7d, 0xa, 0x8b, 0x7, 0xbc, 0x6, 0xc5, 0xa4, 0x63, 0x6d, 0x19, 0x82, 0x1e, 0xe0, 0x2, 0x5a, 0x8e, 0x85, 0x80, 0x97, 0xc5, 0xb6, 0x65, 0x72, 0x96, 0x18, 0xf2, 0x41, 0x2f, 0xf5, 0x34, 0x87, 0xa4, 0xc5, 0x27, 0x8a, 0xbc, 0xdf, 0x4a, 0xeb, 0xd0, 0xa, 0x76, 0x2a, 0xea, 0x17, 0xa1, 0x5e, 0x1d, 0x3b, 0xa1, 0x44, 0x17, 0x31, 0x4e, 0xcd, 0xc, 0xd9, 0x33, 0x44, 0xe5, 0x92, 0x40, 0x4e, 0xd6, 0xd2, 0x82, 0xd4, 0x4e, 0x45, 0x85, 0x21, 0x4d, 0xfb, 0x46, 0xf, 0x43, 0xfa, 0x4a, 0xe4, 0x4a, 0xa5, 0xec, 0x97, 0xfd, 0x43, 0x5e, 0xde, 0xcd, 0x52, 0x68, 0x20, 0xe5, 0xba, 0x6c, 0x72, 0xb3, 0x8d, 0xba, 0xc9, 0x15, 0x80, 0xc2, 0x98, 0x12, 0xd6, 0x15, 0xcc, 0x82, 0xb7, 0xd3, 0xa5, 0x2b, 0xc7, 0x97, 0x35, 0xd6, 0x21, 0x38, 0x6, 0xd, 0x39, 0xad, 0xbc, 0xc4, 0xf3, 0x62, 0x30, 0xc6, 0x9c, 0x1d, 0xca, 0x1e, 0xb1, 0xf9, 0xb4, 0x41, 0x75, 0x94, 0x91, 0x70, 0x33, 0xbe, 0x64, 0xbb, 0xef, 0xfc, 0x48, 0x5f, 0xc9, 0x25, 0xa1, 0xdf, 0x88, 0x4e, 0x86, 0x7c, 0x8e, 0x7a, 0xce, 0x7d, 0xef, 0x17, 0xc8, 0xdd, 0xb4, 0xc8, 0xda, 0xe6, 0xf8, 0x9e, 0xc, 0x3a };
	static BYTE staticKey5[8][32] = { 0x5e, 0x48, 0x54, 0xd0, 0xfa, 0x76, 0xf3, 0x91, 0x57, 0xe2, 0x29, 0xbb, 0x0, 0x15, 0x23, 0xc6, 0xd7, 0x1f, 0x14, 0x7b, 0xd9, 0x57, 0x8c, 0xf7, 0xe0, 0x43, 0x63, 0xa, 0x13, 0x48, 0x2f, 0xdc, 0x65, 0x6b, 0xd8, 0x83, 0xde, 0x90, 0x49, 0xfc, 0xe7, 0xa1, 0xb0, 0x63, 0x90, 0xe, 0x9c, 0xfb, 0xca, 0xf6, 0x20, 0xba, 0xbd, 0x8a, 0x51, 0xec, 0x2d, 0xce, 0x8d, 0xae, 0xeb, 0x87, 0x75, 0xd7, 0x87, 0x3e, 0x61, 0x1, 0xf8, 0x41, 0x16, 0x50, 0xc1, 0x97, 0x75, 0xb5, 0x2, 0xb7, 0xe, 0x34, 0x9, 0x8, 0x2c, 0xe7, 0x6, 0xea, 0x60, 0x84, 0x30, 0x65, 0x17, 0xb9, 0x21, 0x2b, 0x35, 0x71, 0xbc, 0xb, 0x4e, 0x54, 0x60, 0x8f, 0x81, 0x64, 0x96, 0xde, 0x64, 0x24, 0x3f, 0x8d, 0x43, 0x45, 0x41, 0x82, 0xef, 0x1b, 0xb9, 0xab, 0x69, 0xda, 0xd0, 0x86, 0xc1, 0x1d, 0xe, 0x53, 0x4c, 0x45, 0x70, 0xde, 0xb1, 0x99, 0xe, 0xce, 0xd1, 0x96, 0x89, 0x5c, 0x18, 0x2b, 0x1d, 0x54, 0x31, 0x94, 0x8f, 0x58, 0xcf, 0x67, 0xc9, 0x3f, 0x50, 0x95, 0x66, 0x79, 0xf9, 0xd4, 0xfc, 0x68, 0xc5, 0x7a, 0x6b, 0x96, 0x40, 0xea, 0xe2, 0x96, 0x7e, 0xcf, 0x20, 0xb7, 0xca, 0x49, 0x59, 0x15, 0xf1, 0xc, 0x74, 0x49, 0xd1, 0xf8, 0x8, 0x64, 0x18, 0xdd, 0xa8, 0x4d, 0xd2, 0xe9, 0x1f, 0x1c, 0xd2, 0xbf, 0xe1, 0xcf, 0x56, 0x74, 0xaa, 0xcb, 0x20, 0x85, 0x49, 0x67, 0x68, 0x7, 0x96, 0x27, 0xcf, 0x1d, 0xd4, 0xd5, 0xad, 0xf4, 0x34, 0x23, 0xf0, 0x6b, 0xbc, 0xd4, 0xa, 0x68, 0x8a, 0x63, 0xc9, 0x4b, 0x74, 0xf2, 0xf9, 0x64, 0x17, 0x96, 0x76, 0xa9, 0x5b, 0xa1, 0x80, 0xf8, 0x5e, 0x22, 0x31, 0xc0, 0x9, 0x4f, 0xb5, 0x93, 0xf4, 0xc6, 0x32, 0x77, 0x2d, 0xb4, 0x1, 0x64, 0x3e, 0x7d, 0x2c, 0xda };
	static BYTE staticKey6[8][32] = { 0xa8, 0x3c, 0x8b, 0x38, 0xd5, 0x2d, 0xad, 0xc2, 0xae, 0x5, 0x92, 0x42, 0x7f, 0x48, 0xcc, 0xe7, 0x37, 0xfa, 0x77, 0x98, 0x48, 0x10, 0x6a, 0x24, 0x75, 0x16, 0xda, 0xd0, 0xd7, 0x5c, 0x94, 0x9f, 0xda, 0x14, 0x1d, 0x3, 0x77, 0xc1, 0x2c, 0xb1, 0x7e, 0x77, 0x6f, 0x58, 0x36, 0x26, 0x55, 0x88, 0xd, 0x9c, 0x9c, 0xe4, 0xb4, 0x5b, 0x87, 0xf3, 0x62, 0xec, 0x63, 0x67, 0x89, 0xe6, 0x3f, 0x5a, 0xc4, 0x33, 0x81, 0x5c, 0x51, 0xe4, 0x4c, 0xc0, 0xc1, 0x14, 0x4b, 0xc, 0x54, 0x14, 0xca, 0xf2, 0x9c, 0x9b, 0xef, 0xce, 0xce, 0xf2, 0xa8, 0xdd, 0x71, 0xfa, 0x5c, 0x69, 0xd4, 0x9, 0xdd, 0xee, 0xe9, 0x5b, 0xb9, 0x87, 0xe9, 0x48, 0x3f, 0xa6, 0x92, 0xca, 0x8d, 0x5b, 0x1b, 0x96, 0xe6, 0x48, 0xdd, 0x5d, 0x83, 0x5a, 0xd0, 0x6f, 0x52, 0x9f, 0xb3, 0x5a, 0xbf, 0x19, 0x31, 0xaa, 0x3, 0xf8, 0xad, 0x91, 0xe8, 0x47, 0x2f, 0x63, 0xda, 0x24, 0xf1, 0xd4, 0xcc, 0xce, 0x33, 0xf4, 0xf, 0xa2, 0xab, 0x8c, 0x98, 0x12, 0x5d, 0x2a, 0xad, 0xf9, 0x1d, 0x64, 0xb8, 0x43, 0x75, 0x7c, 0xda, 0x21, 0x65, 0x26, 0x68, 0xea, 0x72, 0x77, 0x9b, 0x0, 0xcb, 0xb6, 0xc3, 0x77, 0xa4, 0x44, 0x43, 0x2f, 0xc8, 0x1d, 0x8c, 0x8, 0x7a, 0x49, 0x8d, 0xba, 0x8c, 0xbe, 0x92, 0x41, 0xe4, 0xf0, 0x47, 0x11, 0x44, 0xb2, 0xa9, 0x49, 0x75, 0x8c, 0xa6, 0x9, 0xf1, 0x38, 0x51, 0xec, 0xec, 0x5e, 0x36, 0x1f, 0xe1, 0x4c, 0xf0, 0xd4, 0x99, 0xba, 0x67, 0xb3, 0xc4, 0x5a, 0xc4, 0xe7, 0x2f, 0x4b, 0xc8, 0x7e, 0x6c, 0x16, 0x50, 0xbe, 0x5b, 0x76, 0xca, 0x17, 0x1b, 0x6c, 0x7f, 0x50, 0xeb, 0xe6, 0x3f, 0xaa, 0x8b, 0x9c, 0x7a, 0x9f, 0x96, 0x32, 0x61, 0xbf, 0x79, 0x6c, 0xee, 0x9f, 0x62, 0x8d, 0x8a, 0x27 };

	UINT packetCounter = pSocket->pED->packetCounter;
	if(m_Version == 1)
	{
		for(UINT n=0;n<packetSize;n++)
		{
			packet[n] ^= staticKey1[packetCounter%8][n%32];
		}
	}else if(m_Version == 2)
	{
		for(UINT n=0;n<packetSize;n++)
		{
			packet[n] ^= staticKey2[packetCounter%8][n%32];
		}
	}else if(m_Version == 3)
	{
		for(UINT n=0;n<packetSize;n++)
		{
			packet[n] ^= staticKey3[packetCounter%8][n%32];
		}
	}else if(m_Version == 4)
	{
		for(UINT n=0;n<packetSize;n++)
		{
			packet[n] ^= staticKey4[packetCounter%8][n%32];
		}
	}else if(m_Version == 5)
	{
		for(UINT n=0;n<packetSize;n++)
		{
			packet[n] ^= staticKey5[packetCounter%8][n%32];
		}
	}else if(m_Version == 6)
	{
		for(UINT n=0;n<packetSize;n++)
		{
			packet[n] ^= staticKey6[packetCounter%8][n%32];
		}
	}else if(m_Version == 7)
	{
		//do nothing
	}
//	g_Log.Add(CLog::Blue, "[%s] pckCounter[%d] packet[%x]", __FUNCTION__, packetCounter, packet[0]);
	packetCounter++;
	pSocket->pED->packetCounter = packetCounter;

	unguard;
}

void CCliExt::TimerExpired(CUserSocket *pSocket)
{
	guard;
	if(m_Enabled)
	{

		time_t currentTime = time(0);
		if((currentTime % 300) == 0 && m_EnabledAntiAdrenaline && m_VerificarThreadMuerto)
		{
			if(pSocket->pED->TrheadProccesAdrenaline == 0)
			{
				pSocket->pED->TrheadProccesAdrenalineCounterError++;

				if(pSocket->pED->TrheadProccesAdrenalineCounterError > 2)
				{
					CHAR sHWID[33];
					memset(sHWID, 0, 33);
					memcpy(sHWID, pSocket->pED->longHWID.hash, 32);
					if(User *pUser = pSocket->pUser->SafeCastUser())
					{
						g_Log.Add(CLog::Error, "[CliExt] TrheadProccesAdrenaline Muerto User[%S] HWID[%s] - disconnected.", pUser->pSD->wszName, sHWID);
						m_Logger->Add(L"TrheadProccesAdrenaline Muerto User[%s] HWID[%S] - disconnected.", pUser->pSD->wszName, sHWID);
					}else
					{
						g_Log.Add(CLog::Error, "[CliExt] TrheadProccesAdrenaline Muerto AccountId[%d] HWID[%s] - disconnected", pSocket->accountId, sHWID);
						m_Logger->Add(L"TrheadProccesAdrenaline Muerto AccountId[%d] HWID[%S] - disconnected", pSocket->accountId, sHWID);
					}
					pSocket->Close(L"pSocket->pED->TrheadProccesAdrenalineCounterError");
				}
			}
		}

		if((currentTime % 60) == 0)
		{
			for (size_t i = 0; i < m_MemoryBotData.size(); i++)
			{
				MemoryBotData& detect = m_MemoryBotData[i];

				int id = detect.id;
				int memoryaddr = detect.memoryaddr;

				int cantidad = detect.cantidad;

				pSocket->Send("cddddb", 0x87, 17, id, memoryaddr, cantidad, cantidad, detect.Data);
			}
		}

		if((currentTime % 5) == 0)
		{
			if(pSocket->pED->FileCorruptCounter == 0)
			{
				if(pSocket->pED->FileCorruptCounterError > 1)
				{
					CHAR sHWID[33];
					memset(sHWID, 0, 33);
					memcpy(sHWID, pSocket->pED->longHWID.hash, 32);
					if(User *pUser = pSocket->pUser->SafeCastUser())
					{
						g_Log.Add(CLog::Error, "[CliExt] FileCorruptCounterError User[%S] HWID[%s] - disconnected.", pUser->pSD->wszName, sHWID);
						m_Logger->Add(L"FileCorruptCounterError User[%s] HWID[%S] - disconnected.", pUser->pSD->wszName, sHWID);
					}else
					{
						g_Log.Add(CLog::Error, "[CliExt] FileCorruptCounterError AccountId[%d] HWID[%s] - disconnected", pSocket->accountId, sHWID);
						m_Logger->Add(L"FileCorruptCounterError AccountId[%d] HWID[%S] - disconnected", pSocket->accountId, sHWID);
					}

					pSocket->Close(L"pSocket->pED->FileCorruptCounterError");
				}
				else
				{
					pSocket->pED->FileCorruptCounterError++;
				}
			}
		}


		PingEx& pingEx = pSocket->pED->pingEx;
		if(pingEx.pingTimeout > 0)
		{
			if(pingEx.pingTimeout < time(0) && m_DisablePingPacket == 0)
			{
				CHAR sHWID[33];
				memset(sHWID, 0, 33);
				memcpy(sHWID, pSocket->pED->longHWID.hash, 32);
				//ping timed out - disconnect
				if(User *pUser = pSocket->pUser->SafeCastUser())
				{
					g_Log.Add(CLog::Error, "[CliExt] Ping timed out[%d][%d] User[%S] HWID[%s] - disconnected.", pingEx.pingTimeout, time(0), pUser->pSD->wszName, sHWID);
					m_Logger->Add(L"Ping timed out[%d][%d] User[%s] HWID[%S] - disconnected.", pingEx.pingTimeout, time(0), pUser->pSD->wszName, sHWID);
				}else
				{
					g_Log.Add(CLog::Error, "[CliExt] Ping timed out[%d][%d] AccountId[%d] HWID[%s] - disconnected", pingEx.pingTimeout, time(0), pSocket->accountId, sHWID);
					m_Logger->Add(L"Ping timed out[%d][%d] AccountId[%d] HWID[%S] - disconnected", pingEx.pingTimeout, time(0), pSocket->accountId, sHWID);
				}
				pSocket->Close(L"pingEx.pingTimeout < time(0) && m_DisablePingPacket == 0");
			}
		}else
		{
			UINT currentTick = GetTickCount();
			if(pingEx.tickId < currentTick)
			{
				if(pSocket->pED->longHWID.IsNull())
				{
					CHAR buffEx[8190];
					int lenEx = Assemble(buffEx, 8190, "cd", 0x87, 0x02);
					pSocket->Send("b", lenEx, buffEx);
				}
				if(pSocket->pED->md5Checksum[0] == 0 && pSocket->pED->md5Checksum[1] != 1)
				{
					pSocket->pED->md5Checksum[1] = 1;
					CHAR buffEx[8190];
					int lenEx = Assemble(buffEx, 8190, "cd", 0x87, 12, GetTickCount());
					pSocket->Send("b", lenEx, buffEx);
				}
				//send PingEx packet
				pingEx.tickId = currentTick + 30000;
				pingEx.pingTimeout = time(0) + 120;
				CHAR buff[8190];
				int len = Assemble(buff, 8190, "cdd", 0x87, 0x01, pingEx.tickId);
				pSocket->Send("b", len, buff);


				if(g_CliExt.m_Enabled_files)
				{
					map<wstring, vector<HWID>>::iterator Iter;
					for(Iter = m_MD5ChecksumFiles.begin();Iter != m_MD5ChecksumFiles.end();Iter++)
					{

						CHAR buff[8190];
						int len = Assemble(buff, 8190, "cdS", 0x87, 13, Iter->first.c_str());
						pSocket->Send("b", len, buff);

			//			for(UINT i=0;i<Iter->second.size();i++)
			//			{
			//				g_Log.Add(CLog::Error, "%S : %S",Iter->first.c_str(), Iter->second[i].ToString().c_str());
			//			}
					}

					if (pSocket->pED->FileCorrupt)
					{
						//g_Log.Add(CLog::Error, "[%s] pSocket->pED->FileCorrupt   pSocket->accountId[%d]", __FUNCTION__, pSocket->accountId);
						pSocket->Close(L"pSocket->pED->FileCorrupt");
					}

				}
			}
		}
	}
	unguard;
}

bool CCliExt::HandleCustomPacket(CUserSocket *pSocket, const unsigned char* packet)
{
	guard;

	bool ret = false;
	UINT opCode = 0;
	packet = Disassemble(packet, "d", &opCode);
	if(opCode < 256)
	{
		ret = m_CustomHandler[opCode](pSocket, packet);
	}

	unguard;
	return ret;
}


bool CPHDummyPacket(CUserSocket *pSocket, const unsigned char* packet)
{
	guard;
	g_Log.Add(CLog::Error, "[%s] called id[%d] - ip[%d.%d.%d.%d]", __FUNCTION__, &packet[-4], pSocket->addr.S_un.S_un_b.s_b1, pSocket->addr.S_un.S_un_b.s_b2, pSocket->addr.S_un.S_un_b.s_b3, pSocket->addr.S_un.S_un_b.s_b4);
	unguard;
	return false;
}

bool CPHPingExPacket(CUserSocket *pSocket, const unsigned char* packet)
{
	guard;
	bool ret = false;
	UINT tickId = 0, localTick = 0, localCheckTick = 0, separatedTick = 0, memoryScanTick = 0;
	BOOL requestQuit = 0;
	WCHAR moduleName[255] = { 0 };
	USHORT buffSize = 0;
	packet = Disassemble(packet, "h", &buffSize);

	if(buffSize < 4096)
	{
		BYTE packetData[8190] = { 0 };
		for(UINT n=0;n<buffSize;n++)
		{
			packetData[n] = packet[n];
		}
		CryptXor(packetData, buffSize);

		Disassemble(packetData, "ddddddS", &localTick, &tickId, &localCheckTick, &separatedTick, &memoryScanTick, &requestQuit, sizeof(moduleName), moduleName);
		PingEx& pingEx = pSocket->pED->pingEx;
	
//	g_Log.Add(CLog::Blue, "[%s] Received ping[%u] ip[%d.%d.%d.%d]", __FUNCTION__, tickId, ip.part[0], ip.part[1], ip.part[2], ip.part[3]);

		if(requestQuit)
		{
			CHAR sHWID[33];
			memset(sHWID, 0, 33);
			memcpy(sHWID, pSocket->pED->longHWID.hash, 32);
			
			bool listablanca = false;

			for (std::vector<std::wstring>::iterator it = g_CliExt.m_ListaBlancaExe.begin(); it != g_CliExt.m_ListaBlancaExe.end(); ++it) {
				std::wstring& item = *it;
				// Verifica si item está contenido en moduleName
				if (moduleName && wcsstr(moduleName, item.c_str()) != NULL) {
					//std::wcout << L"'"<< item << L"' se encuentra en '" << moduleName << L"'" << std::endl;
					listablanca = true;
				}
			}

			if(!listablanca)
			{
				if(User *pUser = pSocket->pUser->SafeCastUser())
				{
					g_Log.Add(CLog::Error, "[CliExt] Detected illegal action - User[%S] HWID[%s] reason[%d] module[%S]", pUser->pSD->wszName, sHWID, requestQuit, moduleName);
					m_Logger->Add(L"Detected illegal action - User[%s] HWID[%S] reason[%d] module[%s]", pUser->pSD->wszName, sHWID, requestQuit, moduleName);
				}else
				{
					g_Log.Add(CLog::Error, "[CliExt] Detected illegal action - AccountId[%d] HWID[%s] reason[%d] module[%S]", pSocket->accountId, sHWID, requestQuit, moduleName);
					m_Logger->Add(L"Detected illegal action - AccountId[%d] HWID[%S] reason[%d] module[%s]", pSocket->accountId, sHWID, requestQuit, moduleName);
				}
				if(g_CliExt.IsAutoBanHWID())
				{
					if(!pSocket->pED->longHWID.IsNull())
					{
						g_CliExt.Ban(pSocket->pED->longHWID.hash, pSocket->accountName, L"CliExt", time(0) + g_CliExt.IsAutoBanHWID());
					}
				}

				ret = true;
			}
		}else
		{
			if(tickId != pingEx.tickId)
			{
				CHAR sHWID[33];
				memset(sHWID, 0, 33);
				memcpy(sHWID, pSocket->pED->longHWID.hash, 32);
				
				if(User *pUser = pSocket->pUser->SafeCastUser())
				{
					g_Log.Add(CLog::Error, "[CliExt] Invalid PingEx tickId - User[%S] HWID[%s]", pUser->pSD->wszName, sHWID);
					m_Logger->Add(L"Invalid PingEx tickId - User[%s] HWID[%S]", pUser->pSD->wszName, sHWID);
				}else
				{
					g_Log.Add(CLog::Error, "[CliExt] Invalid PingEx tickId - AccountId[%d] HWID[%s]", pSocket->accountId, sHWID);
					m_Logger->Add(L"Invalid PingEx tickId - AccountId[%d] HWID[%S]", pSocket->accountId, sHWID);
				}
				ret = true;
			}

			if(separatedTick + 60000 < localTick)
			{
				if(User *pUser = pSocket->pUser->SafeCastUser())
				{
					g_Log.Add(CLog::Error, "[CliExt] Invalid Separated tick[%d][%d] - User[%S] HWID[%S]", separatedTick, localTick, pUser->pSD->wszName, pSocket->pED->longHWID.ToString().c_str());
					m_Logger->Add(L"Invalid Separated tick[%d][%d] - User[%s] HWID[%s]", separatedTick, localTick, pUser->pSD->wszName, pSocket->pED->longHWID.ToString().c_str());
				}else
				{
					g_Log.Add(CLog::Error, "[CliExt] Invalid Separated tick[%d][%d] - AccountId[%d] HWID[%S]", separatedTick, localTick, pSocket->accountId, pSocket->pED->longHWID.ToString().c_str());
					m_Logger->Add(L"Invalid Separated tick[%d][%d] - AccountId[%d] HWID[%s]", separatedTick, localTick, pSocket->accountId, pSocket->pED->longHWID.ToString().c_str());
				}
				ret = true;
			}

			if(memoryScanTick + 60000 < localTick)
			{
				if(User *pUser = pSocket->pUser->SafeCastUser())
				{
					g_Log.Add(CLog::Error, "[CliExt] Invalid MS tick[%d][%d] - User[%S] HWID[%S]", memoryScanTick, localTick, pUser->pSD->wszName, pSocket->pED->longHWID.ToString().c_str());
					m_Logger->Add(L"Invalid MS tick[%d][%d] - User[%s] HWID[%s]", memoryScanTick, localTick, pUser->pSD->wszName, pSocket->pED->longHWID.ToString().c_str());
				}else
				{
					g_Log.Add(CLog::Error, "[CliExt] Invalid MS tick[%d][%d] - AccountId[%d] HWID[%S]", memoryScanTick, localTick, pSocket->accountId, pSocket->pED->longHWID.ToString().c_str());
					m_Logger->Add(L"Invalid MS tick[%d][%d] - AccountId[%d] HWID[%s]", memoryScanTick, localTick, pSocket->accountId, pSocket->pED->longHWID.ToString().c_str());
				}
				ret = true;
			}

			if( localCheckTick > (localTick + 2000) || (localTick - (localCheckTick - 2000)) > 105000 )
			{
				CHAR sHWID[33];
				memset(sHWID, 0, 33);
				memcpy(sHWID, pSocket->pED->longHWID.hash, 32);
				
				if(User *pUser = pSocket->pUser->SafeCastUser())
				{
					g_Log.Add(CLog::Error, "[CliExt] Invalid local ticks[%u][%u] - User[%S] HWID[%s]", localTick, localCheckTick, pUser->pSD->wszName, sHWID);
					m_Logger->Add(L"Invalid local ticks[%u][%u] - User[%s] HWID[%S]", localTick, localCheckTick, pUser->pSD->wszName, sHWID);
				}else
				{
					g_Log.Add(CLog::Error, "[CliExt] Invalid local ticks[%u][%u] - AccountId[%d] HWID[%s]", localTick, localCheckTick, pSocket->accountId, sHWID);
					m_Logger->Add(L"Invalid local ticks[%u][%u] - AccountId[%d] HWID[%S]", localTick, localCheckTick, pSocket->accountId, sHWID);
				}
				ret = true;
			}

			if(pingEx.localCheckTick > 0 && pingEx.localTick > 0)
			{
				if( ( localCheckTick - pingEx.localCheckTick ) > 120000 || (localTick - pingEx.localTick) > 120000 )
				{
					CHAR sHWID[33];
					memset(sHWID, 0, 33);
					memcpy(sHWID, pSocket->pED->longHWID.hash, 32);
					
					if(User *pUser = pSocket->pUser->SafeCastUser())
					{
						g_Log.Add(CLog::Error, "[CliExt] Outdated local ticks[%u][%u] [%u][%u] - User[%S] HWID[%s]", localTick, localCheckTick, pingEx.localTick, pingEx.localCheckTick, pUser->pSD->wszName, sHWID);
						m_Logger->Add(L"Outdated local ticks[%u][%u] [%u][%u] - User[%s] HWID[%S]", localTick, localCheckTick, pingEx.localTick, pingEx.localCheckTick, pUser->pSD->wszName, sHWID);
					}else
					{
						g_Log.Add(CLog::Error, "[CliExt] Outdated local ticks[%u][%u] [%u][%u] - AccountId[%d] HWID[%s]", localTick, localCheckTick, pingEx.localTick, pingEx.localCheckTick, pSocket->accountId, sHWID);
						m_Logger->Add(L"Outdated local ticks[%u][%u] [%u][%u] - AccountId[%d] HWID[%S]", localTick, localCheckTick, pingEx.localTick, pingEx.localCheckTick, pSocket->accountId, sHWID);
					}
					ret = true;
				}
			}
		}

		pingEx.localTick = localTick;
		pingEx.localCheckTick = localCheckTick;
		pingEx.pingTimeout = 0;
	}

	unguard;
	return ret;
}

bool CPHHWIDPacket(CUserSocket *pSocket, const unsigned char* packet)
{
	guard;
	bool ret = false;
	
	if(pSocket->pED->shortHWID == 0)
	{
		UINT checkSum = 0;
		packet = Disassemble(packet, "dbdS", &pSocket->pED->shortHWID, 32, pSocket->pED->longHWID.hash, &checkSum, sizeof(pSocket->pED->hwidString), pSocket->pED->hwidString);
		UINT checkSumEx = AdlerCheckSum(pSocket->pED->longHWID.hash, 32);

		//g_Log.Add(CLog::Error, "HWID [%S] !", pSocket->pED->hwidString);


		if(checkSum != checkSumEx)
		{
			g_Log.Add(CLog::Error, "Invalid HWID checkSum[%x] vs [%x] - account[%d][%S] !", checkSum, checkSumEx, pSocket->accountId, pSocket->accountName);
			m_Logger->Add(L"Invalid HWID checkSum[%x] vs [%x] - account[%d][%s] !", checkSum, checkSumEx, pSocket->accountId, pSocket->accountName);
			ret = true;
		}
	}
	
	unguard;
	return ret;
}

bool CPHReplyMD5Packet(CUserSocket *pSocket, const unsigned char* packet)
{
	CTL;
	BYTE md5[32];
	UINT tickId = 0;
	Disassemble(packet, "db", &tickId, sizeof(md5), md5);
	memcpy(pSocket->pED->md5Checksum, md5, 32);

	return false;
}

bool CPHReplyJobPacket(CUserSocket *pSocket, const unsigned char* packet)
{
	CTL;
	
	/*
	pck.WriteD(GetTickCount());
		pck.WriteD(jobId);
		pck.WriteD(time(0));	//current time
		pck.WriteD(g_JobHandler.GetExpireTime());
		pck.WriteD(g_JobHandler.GetJobCount());
		*/

	UINT tickId = 0, localTime = 0, expireTime = 0, jobId = 0, jobCount = 0;

	Disassemble(packet, "ddddd", &tickId, &jobId, &localTime, &expireTime, &jobCount);

//	g_Log.Add(CLog::Blue, "[%s] tickId[%d] jobId[%x] localTime[%d] expireTime[%d] jobCount[%d]", __FUNCTION__, tickId, jobId, localTime, expireTime, jobCount);

	
	return false;
}

bool CPHPingPacket(CUserSocket *pSocket, const unsigned char* packet)
{
	guard;
	bool ret = false;
	UINT startTick = 0;
	UINT currentTick = GetTickCount();
	packet = Disassemble(packet, "d", &startTick);

	wstringstream msgStream;
	msgStream << L"Ping to server: " << (currentTick - startTick) << L" ms.";

	if(User *pUser = pSocket->pUser->SafeCastUser())
	{
		pUser->SendSystemMessage(msgStream.str().c_str());
	}
	
	unguard;
	return ret;
}

bool CPHReplyL2NetworkVoteTime(CUserSocket *pSocket, const unsigned char* packet)
{
	guard;

	INT32 voteTime = 0;
	Disassemble(packet, "d", &voteTime);

	if(User *pUser = pSocket->pUser->SafeCastUser())
	{
		if(g_L2NetworkVote.Enabled())
		{
			g_L2NetworkVote.OnClientReply(pUser, voteTime);
		}
	}
	
	unguard;
	return false;
}
