#pragma once

namespace License
{
	enum LicenseType
	{
		LicenseNone = 0,
		LicenseExtUse,
		LicenseSkillMaster,
		LicenseInstanceZone,
		LicenseSubStack,
		LicenseChatManager,
		LicenseRebirth,
		LicenseChampionNpc,
		LicenseDBNpcMaker,
		LicenseRecipeManager,
		LicenseHtmlPIN,
		LicensePvPAnnounce,
		LicenseCount
	};

	class CLicense
	{
		map<wstring, vector<LicenseType>> m_Data;
		wstring m_LicenseName;
		string m_PostReply;
	public:
		static CLicense& GetInstance();
		void Init();
		void SendPostRequest();
		inline string GetPostReply() { return m_PostReply; };
		bool CanUse(LicenseType licenseType);
	};
}
