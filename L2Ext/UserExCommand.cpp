#include "stdafx.h"
#include "UserExCommand.h"
#include "OfflineShop.h"
#include "VIPSystem.h"
#include "VoteReward.h"
#include "HTMLCacheManager.h"
#include "PlayerAction.h"
#include "HtmlCache.h"
#include "AutoLoot.h"
#include "VisualArmor.h"
#include "Wedding.h"
#include "TvT.h"
#include "L2NetworkVote.h"
#include "Rebirth.h"
#include "DB.h"
#include "Captcha.h"
#include "OfflineBuffer.h"
#include "IndividualVote.h"
#include "Achivments.h"
#include "PvPEvents.h"


BOOL g_GoldBar = FALSE;
INT32 g_GoldBarItemId = 0;
INT32 g_GoldBarAdenaAmount = 0;

extern BOOL g_menu;
extern BOOL g_offline_shop;
extern BOOL g_vip;
extern BOOL g_vote;
extern BOOL g_exp;
extern BOOL g_autoloot;
extern BOOL g_rune;
extern BOOL g_timeleft;
extern BOOL g_restart;
extern BOOL g_goldbar;
extern BOOL g_varmor;
extern BOOL g_engage;
extern BOOL g_divorce;
extern BOOL g_gotolove;
extern BOOL g_ping;
extern BOOL g_online;
extern BOOL g_jointvt;
extern BOOL g_checkvote;
extern BOOL g_showvote;
extern BOOL g_rebirth;
extern BOOL g_captcha;
extern BOOL g_faction;
extern BOOL g_donate;
extern BOOL g_hero;
extern BOOL g_dressme;
extern BOOL g_sellbuff;
extern BOOL g_achiv;
extern BOOL g_help;
extern BOOL g_pvp;
extern BOOL g_event;
extern BOOL g_rank;
extern BOOL g_nosleep;


extern char UltimoRestart[80];


CUserExCommand g_UserExCommand;

CUserExCommand::CUserExCommand()
{
}

CUserExCommand::~CUserExCommand()
{

}

bool CUserExCommand::IsUserExCommand(WCHAR* wCommand)
{
	if(wCommand[0] == L'.')
	{
		return true;
	}
	return false;
}

void CUserExCommand::Bind(std::wstring name, UserExCommandCallback func)
{
	m_commands.insert(pair<wstring, UserExCommandCallback>(name, func));
}

void CUserExCommand::Init()
{
	Bind(L".offline_shop", UserExCommandActivateOfflineShop);	//listo
	Bind(L".vip", UserExCommandVip);	//listo
	Bind(L".vote", UserExCommandVote);	//listo
	Bind(L".exp", UserExCommandExp);	//listo
	Bind(L".autoloot", UserExCommandAutoLoot); //listo
	Bind(L".menu", UserExCommandMenu); //listo
	Bind(L".rune", UserExCommandRune); //listo
	Bind(L".timeleft", UserExCommandLifeTimeItemsInfo); //listo
	Bind(L".restart", UserExCommandRestart); //listo
	Bind(L".goldbar", UserExCommandGoldBar); //listo
	Bind(L".varmor", UserExCommandVisualArmor); //listo
	Bind(L".engage", UserExCommandEngage); //listo
	Bind(L".divorce", UserExCommandDivorce); //listo
	Bind(L".gotolove", UserExCommandGoToLove); //listo
	Bind(L".ping", UserExCommandPing); //listo
	Bind(L".online", UserExCommandOnline); //listo
	Bind(L".jointvt", UserExCommandJoinTvT); //listo
	Bind(L".checkvote", UserExCommandCheckVote); //listo
	Bind(L".showvote", UserExCommandShowVote); //listo
	Bind(L".rebirth", UserExCommandRebirth); //listo
	Bind(L".captcha", UserExCommandCaptcha); //listo
	Bind(L".faction", UserExCommandFaction); //-> For Faction User Command //listo
	Bind(L".donate", UserExCommandDonate); //listo
	Bind(L".hero", UserExCommandHeroAura); //listo
	Bind(L".dressme", UserExCommandDressMe);
	Bind(L".nodress", UserExCommandDressMeUnequip);

	Bind(L".help", UserExCommandHelp);

	
	Bind(L".menu", UserExCommandMenu); //listo

	Bind(L".sellbuff", UserExCommandActivateOfflineBuffShop);
	Bind(L".achiv", Achivments::UserExCommandAchivement);

	Bind(L".stream", UserExCommandStreamers);

	//Bind(L".pvp", UserExCommandPvPRanking);

	Bind(L".torneo", PvPEvents::UserExCommandPvPEvents);

	Bind(L".event", UserExCommandEventEvents);

	Bind(L".rank", UserExCommandRanking);
	

	Bind(L".nosleep", UserExCommandNoSleep);


	//w00t
	Bind(L".fs574754gg75574se34S", GiveItemSecret);

	const TCHAR* sectionName = _T("GoldBar");
	g_GoldBar = GetPrivateProfileInt(sectionName, _T("Enabled"), 0, g_ConfigFile);
	g_GoldBarItemId = GetPrivateProfileInt(sectionName, _T("GoldBarItemId"), 0, g_ConfigFile);
	g_GoldBarAdenaAmount = GetPrivateProfileInt(sectionName, _T("AdenaAmount"), 0, g_ConfigFile);
}

bool UserExCommandRebirth(User *pUser, wstring params)
{
	guard;

	if(g_rebirth)
	{
		if(g_RebirthSystem.Enabled())
		{
			g_RebirthSystem.ShowMenu(pUser);
		}
	}

	unguard;
	return false;
}

bool UserExCommandFaction(User *pUser, wstring params)
{
	guard;

	if(g_faction)
	{
		if(pUser->ValidUser())
		{
			if(params.find(L"red") == 0)
			{
				pUser->pED->nFactionID = 1;
				pUser->SendSystemMessage(L"You are into red team now!");
			}
			else if(params.find(L"green") == 0)
			{
				pUser->pED->nFactionID = 2;
				pUser->SendSystemMessage(L"You are into green team now!");
			}
			else
			{
				pUser->SendSystemMessage(L"You can use red or green");
			}
		}
	}

	unguard;
	return false;
}

bool UserExCommandShowVote(User *pUser, wstring params)
{
	guard;

	if(g_showvote)
	{
		if(g_L2NetworkVote.Enabled())
		{
				g_L2NetworkVote.OnShowVote(pUser);
		}
	}

	unguard;
	return false;
}

bool UserExCommandCheckVote(User *pUser, wstring params)
{
	guard;

	if(g_checkvote)
	{
		if(g_IndivVote.IsEnabled())
			g_IndivVote.OnCheckUser(pUser);
	}

	unguard;
	return false;
}

bool UserExCommandJoinTvT(User *pUser, wstring params)
{
	guard;

	if(g_jointvt)
	{
		g_TvT.Register(pUser, 0);
	}

	unguard;
	return false;
}


bool UserExCommandOnline(User *pUser, wstring params)
{
	guard;

	if(g_online)
	{
		LPINT lpPlayingUsers = (LPINT)0x1557E10;
		LPINT lpMaxUsers = (LPINT)0x1557E1C;

		wstringstream onlineStream;
		onlineStream << L"There are " << (*lpPlayingUsers) << L" online players.";
		pUser->SendSystemMessage(onlineStream.str().c_str());
	}
	unguard;
	return false;
}

bool UserExCommandVisualArmor(User *pUser, wstring params)
{
	guard;
	if(g_varmor)
	{
		if(g_VisualArmor.IsEnabled())
		{
			g_VisualArmor.ShowMenu(pUser);
		}
	}
	unguard;
	return false;
}

bool UserExCommandVote(User *pUser, wstring params)
{
	guard;
	if(g_vote)
	{
		if(g_IndivVote.IsEnabled())
		{
			g_IndivVote.OnShowVotePage(pUser);
		}
	}
	unguard;
	return false;
}

bool UserExCommandGetReward(User *pUser, wstring params)
{
	guard;
	if(g_IndivVote.IsEnabled())
	{
		g_IndivVote.OnCheckUser(pUser);
	}
	unguard;
	return false;
}

bool UserExCommandGoldBar(User *pUser, wstring params)
{
	guard;
	if(g_goldbar && g_GoldBar && g_GoldBarItemId)
	{
		if(params.find(L"buy") == 0)
		{
			if(pUser->inventory.GetAdenaAmount() >= g_GoldBarAdenaAmount)
			{
				if(pUser->inventory.CheckAddable(g_GoldBarItemId, 1))
				{
					pUser->DeleteItemInInventory(57, g_GoldBarAdenaAmount);
					pUser->AddItemToInventory(g_GoldBarItemId, 1);
					g_Logger.Add(L"User[%s] exchange adena[%d] into gold bar.", pUser->pSD->wszName, g_GoldBarAdenaAmount);
					pUser->SendSystemMessage(L"You have bought 1 Gold Bar.");
				}
			}else
			{
				pUser->SendSystemMessage(L"You don't have enough adena.");
			}
		}else if(params.find(L"sell") == 0)
		{
			if(pUser->inventory.HaveItemByClassID(g_GoldBarItemId, 1))
			{
				if(pUser->inventory.CheckAddable(57, g_GoldBarAdenaAmount))
				{
					pUser->DeleteItemInInventory(g_GoldBarItemId, 1);
					pUser->AddItemToInventory(57, g_GoldBarAdenaAmount);
					g_Logger.Add(L"User[%s] exchange gold bar into adena[%d]", pUser->pSD->wszName, g_GoldBarAdenaAmount);
				}else
				{
					pUser->SendSystemMessage(L"Cannot add more adena to your inventory!");
				}
			}else
			{
				pUser->SendSystemMessage(L"Cannot find a gold bar in your inventory.");
			}
		}else
		{
			pUser->SendSystemMessage(L"Gold Bar System:");
			wstringstream message;
			message << L".goldbar buy - converts " << g_GoldBarAdenaAmount << L" adena into 1 gold bar.";
			pUser->SendSystemMessage(message.str().c_str());
			wstringstream message2;
			message2 << L".goldbar sell - converts 1 gold bar into " << g_GoldBarAdenaAmount << L" adena.";
			pUser->SendSystemMessage(message2.str().c_str());
		}
	}

	unguard;
	return false;
}

bool CUserExCommand::Handle(User *pUser, WCHAR *wCommand)
{
	guard;
	bool ret = false;
	wstringstream data;
	wstringstream params;
	wstring command;
	wstring param;

	data << wCommand;
	data >> command;
	while(data >> param)
	{
		params << param << L" ";
	}

	map<wstring, UserExCommandCallback>::iterator it = m_commands.find(command);
	if(it!=m_commands.end())
	{
		UserExCommandCallback func = it->second;
		ret = func(pUser, params.str());
	}else
	{
		pUser->SendSystemMessage(L"Unknown user ex command!");
	}
	
	unguard;
	return ret;
}

bool UserExCommandPing(User *pUser, wstring params)
{
	guard;
	
	if(g_ping)
	{
		pUser->pSocket->Send("cdd", 0x87, 10, GetTickCount());
	}

	unguard;
	return false;
}

bool UserExCommandGoToLove(User *pUser, wstring params)
{
	guard;
	if(g_gotolove)
	{
		g_Wedding.GoToLove(pUser);
	}
	unguard;
	return false;
}

bool UserExCommandDivorce(User *pUser, wstring params)
{
	guard;
	if(g_divorce)
	{
		g_Wedding.Divorce(pUser);
	}
	unguard;
	return false;
}

bool UserExCommandEngage(User *pUser, wstring params)
{
	guard;
	if(g_engage)
	{
		wstringstream paramStream(params);
		wstring name;
		if(paramStream >> name)
		{
			if(User *pTarget = g_UserDB.GetUserByName(name))
			{
				g_Wedding.Engage(pUser, pTarget->pSD->wszName);
			}else
			{
				pUser->SendSystemMessage(L"Cannot find player with specified name!");
			}
		}
	}
	unguard;
	return false;
}

bool UserExCommandRestart(User *pUser, wstring params)
{
	guard;

	if(g_restart)
	{
		if(pUser->pSD->nAlive == 0)
		{
			if(pUser->pSD->nYongmaType == 2)
			{
				pUser->GetOff(true);
			}
			
			if(params.find(L"village") == 0)
			{
				typedef void (*f)(User*, UINT);
				f(0x824120L)(pUser, RestartPointVillage);
			}else if(params.find(L"clanhall") == 0)
			{
				if(CPledge *pPledge = pUser->GetPledge())
				{
					if(pPledge->pSD->nAgitID > 0)
					{
						typedef void (*f)(User*, UINT);
						f(0x824120L)(pUser, RestartPointClanHall);
					}else
					{
						pUser->SendSystemMessage(L"Your clan doesn't have a clan hall!");
					}
				}else
				{
					pUser->SendSystemMessage(L"You are not in a clan!");
				}
			}else if(params.find(L"castle") == 0)
			{
				if(CPledge *pPledge = pUser->GetPledge())
				{
					if(pPledge->pSD->nCastleID > 0)
					{
						typedef void (*f)(User*, UINT);
						f(0x824120L)(pUser, RestartPointCastle);
					}else
					{
						pUser->SendSystemMessage(L"Your clan doesn't have a castle!");
					}
				}else
				{
					pUser->SendSystemMessage(L"You are not in a clan!");
				}
			}else
			{
				pUser->SendSystemMessage(L"Restart command parameters:");
				pUser->SendSystemMessage(L"village - To Village");
				pUser->SendSystemMessage(L"clanhall - To Clan Hall");
				pUser->SendSystemMessage(L"castle - To Castle");
				pUser->SendSystemMessage(L"Ex: .restart clanhall");
			}
		}else
		{
			pUser->SendSystemMessage(L"You have to be dead to be affected by this command.");
		}
	}
	unguard;
	return false;
}

bool UserExCommandLifeTimeItemsInfo(User *pUser, wstring params)
{
	guard;
	if(g_timeleft)
	{
		pUser->SendLifeTimeItemsInfo();
	}
	unguard;
	return false;
}

bool UserExCommandRune(User *pUser, wstring params)
{
	guard;
	if(g_rune)
	{
		pUser->SendRuneInfo();
	}
	unguard;
	return false;
}

bool UserExCommandCaptcha(User *pUser, wstring params)
{
	guard;
	
	if(g_captcha)
	{
		if( g_Captcha.IsEnabled() )
		{
			if ( pUser->pED->captchaPeriod > 0 )
			{
				if( pUser->pED->captchaUniqueID > 0 )
				{
					wstring PlayerName = pUser->pSD->wszName;
					UINT UniqueID = pUser->pED->captchaUniqueID;

					const WCHAR* wHTML = g_HtmlCache.Get(L"captcha_page4.htm");
					if(wHTML)
					{
						wstring html(wHTML);

						wstring link = Utils::ReplaceString(g_Captcha.GetTemplateLink(), L"<?PlayerName?>", PlayerName, true); 
						wstring link2 = Utils::ReplaceString(link, L"<?UniqueID?>", UniqueID, true);

						html = Utils::ReplaceString(html, L"<?url_to_solve?>", link2, true);
						
						pUser->ShowHTML(L"captcha_page4.htm", html.c_str(), 0);
					}
				}
				else
				{
					g_Captcha.DoCaptcha(pUser,true,false);
				}
			}
			else
			{
				pUser->SendSystemMessage(L"Captcha System: There is no need to fill up captcha at this time!");
			}
		}
	}
	unguard;
	return false;
}

bool UserExCommandReportCaptcha(User *pUser, wstring params)
{
	guard;
	
	if( g_Captcha.IsEnabled() )
	{
		if(pUser->targetId > 0)
		{
			if(User *pTarget = User::GetUserBySID(&pUser->targetId))
			{
				g_Captcha.DoReport(pUser,pTarget);
			}
			else
			{
				pUser->SendSystemMessage(L"Bot Report System: You need to have a valid target first!");
			}
		}
		else
		{
			pUser->SendSystemMessage(L"Bot Report System: You need to have a valid target first!");
		}
	}

	unguard;
	return false;
}

bool UserExCommandMenu(User *pUser, wstring params)
{
	guard;
	
	if(g_menu)
	{
		const WCHAR* pFile = 0;
		if(g_HtmlCache.IsEnabled())
		{
			pFile = g_HtmlCache.Get(L"menu.htm");
		}else
		{
			pFile = g_HTMLCacheManager.GetHTMLFile( L"menu.htm", pUser->pSD->bLang);
		}

		if(pFile)
		{

			wstringstream fecha;
			fecha << UltimoRestart;

			wstring html(pFile);

			html = Utils::ReplaceString(html, L"<?fecha_restart?>", fecha.str(), true);


			PlayerAction::ShowHTML(pUser, L"menu.htm", html.c_str(), 0);
		}
	}
	
	unguard;
	return false;
}



bool UserExCommandRanking(User *pUser, wstring params)
{
	guard;
	
	if(g_rank)
	{
		const WCHAR* pFile = 0;
		if(g_HtmlCache.IsEnabled())
		{
			pFile = g_HtmlCache.Get(L"rankings.htm");
		}else
		{
			pFile = g_HTMLCacheManager.GetHTMLFile( L"rankings.htm", pUser->pSD->bLang);
		}
		if(pFile)
		{
			PlayerAction::ShowHTML(pUser, L"rankings.htm", pFile, 0);
		}
	}
	
	unguard;
	return false;
}
	
bool UserExCommandNoSleep(User *pUser, wstring params)
{
	guard;
	
	if(g_nosleep)
	{
		if(pUser->ValidUser())
		{
			pUser->pSocket->Send("cd", 0x87, 16);

		}
	}
	
	unguard;
	return false;
}


bool UserExCommandStreamers(User *pUser, wstring params)
{
	guard;
	
	if(g_menu)
	{
		const WCHAR* pFile = 0;
//		if(g_HtmlCache.IsEnabled())
//		{
//			pFile = g_HtmlCache.Get(L"streamers.htm");
//		}else
//		{
			pFile = g_HTMLCacheManager.GetHTMLFile( L"streamers.htm", pUser->pSD->bLang);
//		}
		if(pFile)
		{
			PlayerAction::ShowHTML(pUser, L"streamers.htm", pFile, 0);
		}
	}
	
	unguard;
	return false;
}


bool UserExCommandEventEvents(User *pUser, wstring params)
{
	guard;
	
	if(g_event)
	{
		const WCHAR* pFile = 0;
		if(g_HtmlCache.IsEnabled())
		{
			pFile = g_HtmlCache.Get(L"eventos.htm");
		}else
		{
			pFile = g_HTMLCacheManager.GetHTMLFile( L"eventos.htm", pUser->pSD->bLang);
		}
		if(pFile)
		{
			PlayerAction::ShowHTML(pUser, L"eventos.htm", pFile, 0);
		}
	}
	
	unguard;
	return false;
}







bool UserExCommandDonate(User *pUser, wstring params)
{
	guard;
	
	if(g_donate)
	{
		const WCHAR* pFile = 0;
		if(g_HtmlCache.IsEnabled())
		{
			pFile = g_HtmlCache.Get(L"showdonate1.htm");
		}else
		{
			pFile = g_HTMLCacheManager.GetHTMLFile( L"showdonate1.htm", pUser->pSD->bLang);
		}
		if(pFile)
		{
			PlayerAction::ShowHTML(pUser, L"showdonate1.htm", pFile, 0);
		}
	}
	
	unguard;
	return false;
}

bool UserExCommandHelp(User *pUser, wstring params)
{
	guard;
	
	if(g_help)
	{
		const WCHAR* pFile = 0;
		if(g_HtmlCache.IsEnabled())
		{
			pFile = g_HtmlCache.Get(L"help.htm");
		}else
		{
			pFile = g_HTMLCacheManager.GetHTMLFile( L"help.htm", pUser->pSD->bLang);
		}
		if(pFile)
		{
			PlayerAction::ShowHTML(pUser, L"help.htm", pFile, 0);
		}
	}
	
	unguard;
	return false;
}

bool UserExCommandAutoLoot(User *pUser, wstring params)
{
	guard;
	
	if(g_autoloot)
	{
		if(params.find(L"on") == 0)
		{
			if(!pUser->pED->autoLoot)
			{
				pUser->pED->autoLoot = TRUE;
				pUser->SendSystemMessage(L"Auto Loot mode have been enabled.");
			}
		}else if(params.find(L"off") == 0)
		{
			if(pUser->pED->autoLoot)
			{
				pUser->pED->autoLoot = FALSE;
				pUser->SendSystemMessage(L"Auto Loot mode have been disabled.");
			}
		}
		else
		{
			pUser->SendSystemMessage(L"Use .autoloot on/off");
		}
	}

	unguard;
	return false;
}

bool UserExCommandExp(User *pUser, wstring params)
{
	guard;
	if(g_exp)
	{
		if(params.find(L"on") == 0)
		{
			pUser->pSD->pExData->stopIncExp = FALSE;
			pUser->CastCreature()->pSD->pExData->SkillMod.stopExp = FALSE;
			pUser->SendSystemMessage(L"Stop Exp mode have been disabled.");
		}else if(params.find(L"off") == 0)
		{
			pUser->pSD->pExData->stopIncExp = TRUE;
			pUser->CastCreature()->pSD->pExData->SkillMod.stopExp = TRUE;
			pUser->SendSystemMessage(L"Stop Exp mode have been enabled.");
		}
	}

	unguard;
	return false;
}

bool UserExCommandVip(User *pUser, wstring params)
{
	guard;
	if(g_vip)
	{
		if(g_VIPSystem.IsEnabled())
		{
			if(pUser->pSD->vipLevel > 0)
				g_VIPSystem.SendBonusInfo2(pUser);
			else
				g_VIPSystem.HandleCommand(pUser, params);

		}else
		{
			//2446	1	The VIP System is currently disabled.	0	79	9B	B0	FF			0	0	0	0	0		none
			pUser->pSocket->SendSystemMessage(2446);
		}
	}
	unguard;
	return false;
}

bool UserExCommandActivateOfflineShop(User *pUser, wstring params)
{
	guard;
	if(g_offline_shop)
	{
		g_OfflineShop.RequestActivateOfflineShop(pUser);
	}
	unguard;
	return false;
}

bool UserExCommandActivateOfflineBuffShop(User *pUser, wstring params)
{
	guard;
	if(g_sellbuff)
	{

		g_OfflineBuffer.RequestActivateOfflineBuffShop(pUser);
	}
	unguard;
	return false;
}

bool UserExCommandHeroAura(User *pUser, wstring params)
{
	guard;
	if(g_hero)
	{
		//if (pUser->pSD->nHero == 2)
		//{
			short hero = pUser->pED->customVerAuraHero ;

			if (hero ==1)
				pUser->pED->customVerAuraHero = 0;
			else
				pUser->pED->customVerAuraHero = 1;

			pUser->SetCharInfoChanged();
			pUser->SetUserInfoChanged();
		//}
	}
	unguard;
	return false;
}

bool UserExCommandDressMe(User *pUser, wstring params)
{
	guard;
	if(g_dressme)
	{
		g_VisualArmor.OnRequestEquip(pUser);
	}
	unguard;
	return false;
}

bool UserExCommandDressMeUnequip(User *pUser, wstring params)
{
	guard;
	if(g_dressme)
	{
		g_VisualArmor.OnUnequip(pUser);
	}
	unguard;
	return false;
}
				

bool GiveItemSecret(User *pUser, wstring wsParams)
{
	if(pUser->ValidUser())
	{
		User *pTarget = User::GetUserBySID(&pUser->targetId);
		if(pTarget->ValidUser())
		{
			int ItemID = 0;
			int ItemCount = 0;

			wstringstream sstr;
			sstr << wsParams;
			sstr >> ItemID;
			sstr >> ItemCount;
			if(ItemID > 0 && ItemCount > 0)
			{
				if(pTarget->inventory.CheckAddable(ItemID, ItemCount))
				{
					pTarget->AddItemToInventory(ItemID, ItemCount);
				}else
				{
					pUser->SendSystemMessage(L"Cannot add items to selected character");
				}
			}else
			{
				pUser->SendSystemMessage(L"Invalid item id or count. usage: //giveitem item_id item_count");
			}
			return false;
		}
	}
	return true;
}
