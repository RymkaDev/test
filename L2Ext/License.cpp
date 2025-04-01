#include "stdafx.h"
#include "License.h"
#include "HWID.h"

extern TCHAR g_LicenseName[256];

#pragma optimize("", off)

namespace License
{
	CLicense& CLicense::GetInstance()
	{
		static CLicense m_Instance;
		return m_Instance;
	}

	void CLicense::Init()
	{
		VIRTUALIZER_TIGER_BLACK_START;
		m_LicenseName = g_LicenseName;
		//license name
		const WCHAR vang[] = { L'V', L'a', L'n', L'g', 0 };

		//features for the licens - vang
		m_Data[vang].push_back(LicenseExtUse);
		m_Data[vang].push_back(LicenseSkillMaster);
		m_Data[vang].push_back(LicenseInstanceZone);
		m_Data[vang].push_back(LicenseSubStack);
		m_Data[vang].push_back(LicenseChatManager);
		m_Data[vang].push_back(LicenseRebirth);
		m_Data[vang].push_back(LicenseChampionNpc);
		m_Data[vang].push_back(LicenseDBNpcMaker);
		m_Data[vang].push_back(LicenseRecipeManager);
		m_Data[vang].push_back(LicenseHtmlPIN);
		m_Data[vang].push_back(LicensePvPAnnounce);

		VIRTUALIZER_TIGER_BLACK_END;
	}

	void CLicense::SendPostRequest()
	{

	}

	bool CLicense::CanUse(LicenseType licenseType)
	{
		/*
		VIRTUALIZER_TIGER_BLACK_START;
		bool canUse = false;

		map<wstring, vector<LicenseType>>::iterator iter = m_Data.find(m_LicenseName);
		if(iter != m_Data.end())
		{
			vector<LicenseType>& licenses = iter->second;
			for(UINT n=0;n<licenses.size();n++)
			{
				if(licenses[n] == licenseType)
				{
					canUse = true;
					break;
				}
			}
		}

		VIRTUALIZER_TIGER_BLACK_END;

		return canUse;
		*/

		//VIRTUALIZER_TIGER_BLACK_START;
		bool canuse = false;

		//PC's
		HWID Hwid(L"F78F094CDB8E31AE4F8A3DE157E6E933"); //FOTIS PC
		HWID Hwid2(L"961EEBA9A8A113D6F9F95931C91810B7"); //XRYS PC

		//SERVERS
		HWID Hwid3(L"1D243A50840FC6F5A234E5EF2A43A1DF"); //SERVERBOX 54.36.111.156
		HWID Hwid4(L"9D31D5F071F81DE7E5C5BE3290B14232"); //SERVERBOX -TEST SERVER FOTIS

		//New Server
		HWID Hwid5(L"76F14C549F2E59E4C648373F9E7841DF"); //SERVERBOX 147.135.254.190 L2FROZEN

		if(!memcmp(Hwid.hash, g_HWID.GetHash(), 32))
			return true;
		if(!memcmp(Hwid2.hash, g_HWID.GetHash(), 32))
			return true;
		if(!memcmp(Hwid3.hash, g_HWID.GetHash(), 32))
			return true;
		if(!memcmp(Hwid4.hash, g_HWID.GetHash(), 32))
			return true;
		if(!memcmp(Hwid5.hash, g_HWID.GetHash(), 32))
			return true;

		//VIRTUALIZER_TIGER_BLACK_END;

		return true;
	}
}

#pragma optimize("", on)
