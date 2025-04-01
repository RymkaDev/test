#include "StdAfx.h"
#include "AIO.h"
#include "SchemeBuffer.h"
#include "TeleportBypass.h"
#include "ClanSys.h"
#include "ClassManager.h"
#include "TvT.h"
#include "Augmentation.h"
#include "OfflineShop.h"
#include "AccountDB.h"
#include "DB.h"
#include "FractionSystem.h"
#include "HTMLCacheManager.h"
#include "Auction.h"
#include "PlayerAction.h"
#include "VisualArmor.h"
#include "Wedding.h"
#include "RaidBossStatus.h"
#include "PKPvPStatus.h"
#include "SubStack.h"
#include "VIPSystem.h"
#include "SkillMaster.h"
#include "Rebirth.h"
#include "ClanPvPStatus.h"
#include "Captcha.h"
#include "DonateSystem.h"
#include "OfflineBuffer.h"
#include "OlympiadStatus.h"
#include "EpicItems.h"
#include "OfflineBuffer.h"
#include "DonateSystem.h"
#include "DropList.h"
#include "ClanReputationRank.h"
#include "DonateAugment.h"
#include "Achivments.h"
#include "HtmlCache.h"
#include "PvPEvents.h"
#include "PartyEvents.h"



bool CBypass::Handled(User *pUser, wstring wBypass)
{
	if(pUser->IsNowTrade())
	{
		pUser->TradeCancel();
		return true;
	}

	if(pUser->pSD->nStoreMode > 0 && wBypass != L"offline_shop")
	{
		pUser->SendSystemMessage(L"You cannot perform this action while operating private store!");
		return true;
	}

	if(pUser->olympiadUser.GetState() != 0)
	{
		if(wBypass.find(L"teleport_") == 0 || wBypass.find(L"player_teleport") == 0)
		{
			pUser->SendSystemMessage(L"You cannot perform this action while participing in Olympiad!");
			return true;
		}
	}

	if(/*g_HTMLCacheManager.IsValid(pUser->wLastHtmlFileName, wBypass.c_str(), 0)*/ true)
	{
		if(PartyEvents::CustomsBypass(pUser, wBypass))
		{
			return true;
		}

		if(NuevasFunciones::CustomsBypass(pUser, wBypass))
		{
			return true;
		}

		if(g_PvPEvents.Bypass(pUser, wBypass))
		{
			return true;
		}

		if(g_Achivments.Bypass(pUser, wBypass))
		{
			return true;
		}


		if(pUser->talkTargetId && CCreature::IsValidServerId(&pUser->talkTargetId))
		{
			try
			{
				CCreature *pTarget = CCreature::GetTalkTarget(&pUser->talkTargetId);
				if(pTarget->ValidCreature() && pUser->CheckDistance(pTarget, 250))
				{
					if( wBypass == L"acquire_clan_skill" )
					{
						ClanSys::RequestShowPledgeSkillList(pUser);
						return true;
					}else if( wBypass == L"augment_item" )
					{
						g_Augmentation.ShowAugmentMixWindow(pUser->GetSocket());
						return true;
					}else if( wBypass == L"remove_augment" )
					{
						g_Augmentation.ShowAugmentRemoveWindow(pUser->GetSocket());
						return true;
					}else if( wBypass.find(L"create_academy?") == 0 )
					{
						wstring wPledgeName = CParser::GetBypassValue(wBypass, L"academy_name=");
						wstring wMasterName;
						ClanSys::CreateSubUnit(pUser, CPledge::ACADEMY, wPledgeName, wMasterName);
						return true;
					}else if( wBypass.find(L"create_subpledge?") == 0 )
					{
						//bypass -h create_subpledge?pledge_name= $pledge_name & master_name= $master_name & pledge_type= 100
						wstring wPledgeName = CParser::GetBypassValue(wBypass, L"pledge_name=");
						wstring wMasterName = CParser::GetBypassValue(wBypass, L"master_name=");
						wstring wPledgeType = CParser::GetBypassValue(wBypass, L"pledge_type=");
						int nPledgeType = _wtoi(wPledgeType.c_str());
						ClanSys::CreateSubUnit(pUser, nPledgeType, wPledgeName, wMasterName);
						return true;
					}else if( wBypass.find(L"rename_subpledge?") == 0 )
					{
						//bypass -h rename_subpledge?pledge_type= 100 & pledge_name= $pledge_name
						wstring wPledgeName = CParser::GetBypassValue(wBypass, L"pledge_name=");
						wstring wPledgeType = CParser::GetBypassValue(wBypass, L"pledge_type=");
						int nPledgeType = _wtoi(wPledgeType.c_str());
						ClanSys::RequestRenameSubPledge(pUser, nPledgeType, wPledgeName);
						return true;
					}else if( wBypass.find(L"transfer_master?") == 0 )
					{
						//bypass -h transfer_master?master_name= $master_name
						wstring wMasterName = CParser::GetBypassValue(wBypass, L"master_name=");
						ClanSys::RequestDelegateClanMaster(pUser, wMasterName);
						return true;
					}else if( wBypass.find(L"transfer_master_instant?") == 0 )
					{
						//bypass -h transfer_master_instant?master_name= $master_name
						wstring wMasterName = CParser::GetBypassValue(wBypass, L"master_name=");
						ClanSys::RequestDelegateClanMasterEx(pUser, wMasterName);
						return true;
					}else if( wBypass == L"transfer_master_cancel" )
					{
						//bypass -h transfer_master_cancel
						wstring wMasterName = CParser::GetBypassValue(wBypass, L"master_name=");
						ClanSys::RequestCancelDelegateClanMaster(pUser);
						return true;
					}else if( wBypass.find(L"update_subpledge_master?") == 0 )
					{
						//bypass -h update_subpledge_master?pledge_type=200 & master_name=$master_name2
						wstring wPledgeType = CParser::GetBypassValue(wBypass, L"pledge_type=");
						wstring wMasterName = CParser::GetBypassValue(wBypass, L"master_name=");
						int nPledgeType = _wtoi(wPledgeType.c_str());
						ClanSys::RequestSetSubUnitCaptain(pUser, nPledgeType, wMasterName);
						return true;
					}else if( wBypass == L"pledge_levelup" )
					{
						ClanSys::RequestLevelUp(pUser);
						return true;
					}else if(wBypass.find(L"setforreputation?") == 0)
					{
						wstring wType = CParser::GetBypassValue(wBypass, L"type=");
						int nParam1 = _wtoi(wType.c_str());
						ClanSys::RequestExchangeReputationForSetItems(pUser, nParam1);
						return true;
					}else if( wBypass.find(L"sb_b_p?") == 0)
					{
						UINT buffId = Parser::GetBypassValueInt(wBypass.c_str(), L"id");
						g_SchemeBuffer.RequestBuff(pUser, buffId, false, false);
						return true;
					}else if( wBypass.find(L"sb_b_s?") == 0)
					{
						UINT buffId = Parser::GetBypassValueInt(wBypass.c_str(), L"id");
						g_SchemeBuffer.RequestBuff(pUser, buffId, true, false);
						return true;
					}else if( wBypass.find(L"MostrarBufferConListas?") == 0)
					{
						//g_Log.Add(CLog::Error, "comando[%S]", wBypass.c_str());
						int Id = Parser::GetBypassValueInt(wBypass.c_str(), L"id");
						wstring nName = CParser::GetBypassValue(wBypass, L"n=");
						int listId = Parser::GetBypassValueInt(wBypass.c_str(), L"listId");

						if (nName.size() >0 && Parser::IsValidSqlString(nName.c_str()) && wcslen(nName.c_str())<16 && listId>0)
						{
							SchemeBufferUser& sbu = pUser->pED->schemeBufferUser;
							sbu.lock.Enter();

							if(listId == 1)
								wcscpy(sbu.buffList1_Name,nName.c_str());
							else if(listId == 2)
								wcscpy(sbu.buffList2_Name,nName.c_str());
							else if(listId == 3)
								wcscpy(sbu.buffList3_Name,nName.c_str());
							else if(listId == 4)
								wcscpy(sbu.buffList4_Name,nName.c_str());
							else if(listId == 5)
								wcscpy(sbu.buffList5_Name,nName.c_str());
							else if(listId == 6)
								wcscpy(sbu.buffList6_Name,nName.c_str());
							else if(listId == 7)
								wcscpy(sbu.buffList7_Name,nName.c_str());
							else if(listId == 8)
								wcscpy(sbu.buffList8_Name,nName.c_str());
							else if(listId == 9)
								wcscpy(sbu.buffList9_Name,nName.c_str());

							sbu.saveList = true;

							sbu.lock.Leave();
						}

						if (Id == 1)
						{
							wstring wHtml = g_HtmlCache.Get(L"list_buffer001.htm");

							SchemeBufferUser& sbu = pUser->pED->schemeBufferUser;

							wHtml = Utils::ReplaceString(wHtml, L"<?list1?>", sbu.buffList1_Name, false);
							wHtml = Utils::ReplaceString(wHtml, L"<?list2?>", sbu.buffList2_Name, false);
							wHtml = Utils::ReplaceString(wHtml, L"<?list3?>", sbu.buffList3_Name, false);
							wHtml = Utils::ReplaceString(wHtml, L"<?list4?>", sbu.buffList4_Name, false);
							wHtml = Utils::ReplaceString(wHtml, L"<?list5?>", sbu.buffList5_Name, false);
							wHtml = Utils::ReplaceString(wHtml, L"<?list6?>", sbu.buffList6_Name, false);
							wHtml = Utils::ReplaceString(wHtml, L"<?list7?>", sbu.buffList7_Name, false);
							wHtml = Utils::ReplaceString(wHtml, L"<?list8?>", sbu.buffList8_Name, false);
							wHtml = Utils::ReplaceString(wHtml, L"<?list9?>", sbu.buffList9_Name, false);


							PlayerAction::ShowHTML(pUser, L"list_buffer001.htm", wHtml.c_str(), 0);
						}
						else if (Id == 2)
						{
							wstring wHtml = g_HtmlCache.Get(L"list_buffer201.htm");

							SchemeBufferUser& sbu = pUser->pED->schemeBufferUser;

							wHtml = Utils::ReplaceString(wHtml, L"<?list1?>", sbu.buffList1_Name, false);
							wHtml = Utils::ReplaceString(wHtml, L"<?list2?>", sbu.buffList2_Name, false);
							wHtml = Utils::ReplaceString(wHtml, L"<?list3?>", sbu.buffList3_Name, false);
							wHtml = Utils::ReplaceString(wHtml, L"<?list4?>", sbu.buffList4_Name, false);
							wHtml = Utils::ReplaceString(wHtml, L"<?list5?>", sbu.buffList5_Name, false);
							wHtml = Utils::ReplaceString(wHtml, L"<?list6?>", sbu.buffList6_Name, false);
							wHtml = Utils::ReplaceString(wHtml, L"<?list7?>", sbu.buffList7_Name, false);
							wHtml = Utils::ReplaceString(wHtml, L"<?list8?>", sbu.buffList8_Name, false);
							wHtml = Utils::ReplaceString(wHtml, L"<?list9?>", sbu.buffList9_Name, false);


							PlayerAction::ShowHTML(pUser, L"list_buffer201.htm", wHtml.c_str(), 0);
						}
						return true;
					}else if( wBypass.find(L"sb_a_p?") == 0)
					{
						//g_Log.Add(CLog::Error, "comando[%S]", wBypass.c_str());

						UINT buffId = Parser::GetBypassValueInt(wBypass.c_str(), L"id");
						UINT listId = Parser::GetBypassValueInt(wBypass.c_str(), L"listId", 0);
						wstring nName = CParser::GetBypassValue(wBypass, L"n=");
						
						SchemeBufferUser& sbu = pUser->pED->schemeBufferUser;
						sbu.lock.Enter();

						
			//			g_Log.Add(CLog::Error, "[%s] User[%S]", __FUNCTION__, sbu.buffList1_Name);



						if (nName.size() >0 && Parser::IsValidSqlString(nName.c_str()) && wcslen(nName.c_str())<16)
						{
							if(listId == 1)
								wcscpy(sbu.buffList1_Name,nName.c_str());
							else if(listId == 2)
								wcscpy(sbu.buffList2_Name,nName.c_str());
							else if(listId == 3)
								wcscpy(sbu.buffList3_Name,nName.c_str());
							else if(listId == 4)
								wcscpy(sbu.buffList4_Name,nName.c_str());
							else if(listId == 5)
								wcscpy(sbu.buffList5_Name,nName.c_str());
							else if(listId == 6)
								wcscpy(sbu.buffList6_Name,nName.c_str());
							else if(listId == 7)
								wcscpy(sbu.buffList7_Name,nName.c_str());
							else if(listId == 8)
								wcscpy(sbu.buffList8_Name,nName.c_str());
							else if(listId == 9)
								wcscpy(sbu.buffList9_Name,nName.c_str());
						}

			//			g_Log.Add(CLog::Error, "[%s] User[%S]", __FUNCTION__, sbu.buffList1_Name);

						sbu.lock.Leave();

						g_SchemeBuffer.RequestAddToList(pUser, buffId, false, false, listId);
						return true;
					}else if( wBypass.find(L"sb_a_s?") == 0)
					{
						UINT buffId = Parser::GetBypassValueInt(wBypass.c_str(), L"id");
						UINT listId = Parser::GetBypassValueInt(wBypass.c_str(), L"listId", 0);

						g_SchemeBuffer.RequestAddToList(pUser, buffId, true, false, listId);

						return true;
					}else if( wBypass.find(L"sb_u_p") == 0)
					{
						UINT listId = Parser::GetBypassValueInt(wBypass.c_str(), L"listId", 0);
						g_SchemeBuffer.RequestUseList(pUser, false, false, false, listId);
						return true;
					}else if( wBypass.find(L"sb_u_s") == 0)
					{
						UINT listId = Parser::GetBypassValueInt(wBypass.c_str(), L"listId", 0);
						g_SchemeBuffer.RequestUseList(pUser, true, false, false, listId);
						return true;
					}
					else if( wBypass.find(L"sb_u_mp") == 0)
					{
						wstring name = CParser::GetBypassValue(wBypass, L"name");

						g_SchemeBuffer.UseMacro(pUser, name, false, false);
						return true;
					}else if( wBypass.find(L"sb_u_ms") == 0)
					{
						wstring name = CParser::GetBypassValue(wBypass, L"name");

						g_SchemeBuffer.UseMacro(pUser, name, true, false);
						return true;
					}else if( wBypass.find(L"sb_c_p") == 0)
					{
						UINT listId = Parser::GetBypassValueInt(wBypass.c_str(), L"listId", 0);

						g_SchemeBuffer.RequestClearList(pUser, false, false, listId);
						return true;
					}else if( wBypass.find(L"sb_c_s") == 0)
					{
						UINT listId = Parser::GetBypassValueInt(wBypass.c_str(), L"listId", 0);

						g_SchemeBuffer.RequestClearList(pUser, true, false, listId);
						return true;
					}else if( wBypass.find(L"sb_r_p") == 0)
					{
						g_SchemeBuffer.RequestRecovery(pUser, false);
						return true;
					}else if( wBypass.find(L"sb_r_s") == 0)
					{
						g_SchemeBuffer.RequestRecovery(pUser, true);
						return true;
					}else if( wBypass.find(L"sb_d_p") == 0)
					{
						g_SchemeBuffer.RequestDispelAll(pUser, false);
						return true;
					}else if( wBypass.find(L"sb_d_s") == 0)
					{
						g_SchemeBuffer.RequestDispelAll(pUser, true);
						return true;
					}else if( wBypass.find(L"sm_show?") == 0)
					{
						UINT listId = Parser::GetBypassValueInt(wBypass.c_str(), L"listId", 0);
						if(listId > 0)
						{
							g_SkillMaster.ShowSkillList(pUser, listId);
						}
						return true;
					}else if(wBypass.find(L"siege_stat?") == 0)
					{
						int nCastle = _wtoi(CParser::GetBypassValue(wBypass, L"CastleType=").c_str());
						CSiegeStat::CastleType Castle = CSiegeStat::GetInstance().GetCastle(nCastle);
						int nReportType = _wtoi(CParser::GetBypassValue(wBypass, L"ReportType=").c_str());
						CCacheData::DataType ReportType = CCacheData::GetType(nReportType);
						int nPledgeID = _wtoi(CParser::GetBypassValue(wBypass, L"PledgeID=").c_str()); // optional
						if(Castle != CSiegeStat::NotCastle)
						{
							if( ReportType != CCacheData::None )
							{
								if(nPledgeID == 0 && ReportType == CCacheData::PledgeReport)
								{
									nPledgeID = pUser->pSD->nPledgeID;
								}
								CSiegeStat::GetInstance().RequestSendReport(pUser->GetSocket(), ReportType, Castle, nPledgeID);
								return true;
							}
						}		
					}else if( wBypass.find(L"player_level_down?") == 0)
					{
						int nLevel = _wtoi(CParser::GetBypassValue(wBypass, L"level=").c_str());
						if(nLevel > 0 && nLevel < pUser->pSD->nLevel)
						{
							pUser->SetLevel(nLevel);
							pUser->ValidateParameters();
						}
						return true;
					}else if( wBypass.find(L"player_level_down2?") == 0)
					{
						//player_level_down2?level=5&itemrequired=57&quanity=50
						int nLevel = _wtoi(CParser::GetBypassValue(wBypass, L"level=").c_str());
						int nItemRequired = _wtoi(CParser::GetBypassValue(wBypass, L"itemrequired=").c_str());
						int nQuanity = _wtoi(CParser::GetBypassValue(wBypass, L"quanity=").c_str());
						if(nLevel > 0 && nItemRequired > 0 && nQuanity > 0)
						{
							int nUserLevel = pUser->pSD->nLevel;
							int nUserLevelAfterDown = nUserLevel - nLevel;
							if(nUserLevelAfterDown > 0)
							{
								if(pUser->DeleteItemInInventory(nItemRequired, nQuanity))
								{
									pUser->SetLevel(nUserLevelAfterDown);
									pUser->ValidateParameters();

									pUser->SendSystemMessageGreen(L"Delevel System: You sucessfully lowered your level!");
								}
								else
									pUser->SendSystemMessageRed(L"Delevel System: You dont have the required items!");
							}
							else
								pUser->SendSystemMessageRed(L"Delevel System: Your level is too low for this action!");
						}
						return true;
					}else if( wBypass.find(L"player_teleport?") == 0)
					{
						wstring wName = CParser::GetBypassValue(wBypass, L"name=");
						g_TeleportBypass.RequestTeleport(pUser, wName);
						return true;
					}else if ( wBypass.find(L"tvt_register?") == 0)
					{
						int team = CParser::GetBypassValueInt(wBypass, L"team=");
						g_TvT.Register(pUser, team);
						return true;
					}else if ( wBypass.find(L"tvt_unregister") == 0)
					{
						g_TvT.Unregister(pUser);
						return true;
					}else if( wBypass == L"get_married" )
					{
						g_Wedding.Marry(pUser);
						return true;
					}else if( wBypass == L"rebirth_show_npc" )
					{
						g_RebirthSystem.ShowMenu(pUser);
						return true;
					}
				}
			}catch(...)
			{
				g_Log.Add(CLog::Error, "[%s] Exception Detected - 1! [%S]", __FUNCTION__, wBypass.c_str());
			}
		}


		//Bypasses without valid target
		if( wBypass.find(L"sb_r_b_p?") == 0)
		{
			UINT buffId = Parser::GetBypassValueInt(wBypass.c_str(), L"id");
			UINT abtime = Parser::GetBypassValueInt(wBypass.c_str(), L"ab");
			if(!abtime)
				g_SchemeBuffer.RequestBuff(pUser, buffId, false, true);
			else
				g_SchemeBuffer.RequestBuff(pUser, buffId, false, true, abtime);
			return true;
		}else if( wBypass.find(L"sb_r_b_s?") == 0)
		{
			UINT buffId = Parser::GetBypassValueInt(wBypass.c_str(), L"id");
			UINT abtime = Parser::GetBypassValueInt(wBypass.c_str(), L"ab");
			if(!abtime)
				g_SchemeBuffer.RequestBuff(pUser, buffId, true, true);
			else
				g_SchemeBuffer.RequestBuff(pUser, buffId, true, true, abtime);
			return true;
		}else if( wBypass.find(L"sb_r_a_p?") == 0)
		{
			UINT buffId = Parser::GetBypassValueInt(wBypass.c_str(), L"id");
			UINT listId = Parser::GetBypassValueInt(wBypass.c_str(), L"listId", 0);

			g_SchemeBuffer.RequestAddToList(pUser, buffId, false, true, listId);
			return true;
		}else if( wBypass.find(L"sb_r_a_s?") == 0)
		{
			UINT buffId = Parser::GetBypassValueInt(wBypass.c_str(), L"id");
			UINT listId = Parser::GetBypassValueInt(wBypass.c_str(), L"listId", 0);

			g_SchemeBuffer.RequestAddToList(pUser, buffId, true, true, listId);
			return true;
		}else if( wBypass.find(L"sb_r_u_p?") == 0)
		{
			UINT listId = Parser::GetBypassValueInt(wBypass.c_str(), L"listId", 0);

			g_SchemeBuffer.RequestUseList(pUser, false, true, false, listId);
			return true;
		}else if( wBypass.find(L"sb_r_u_s?") == 0)
		{
			UINT listId = Parser::GetBypassValueInt(wBypass.c_str(), L"listId", 0);

			g_SchemeBuffer.RequestUseList(pUser, true, true, false, listId);
			return true;
		}else if( wBypass.find(L"sb_r_c_p") == 0)
		{
			UINT listId = Parser::GetBypassValueInt(wBypass.c_str(), L"listId", 0);

			g_SchemeBuffer.RequestClearList(pUser, false, true, listId);
			return true;
		}else if( wBypass.find(L"sb_r_c_s") == 0)
		{
			UINT listId = Parser::GetBypassValueInt(wBypass.c_str(), L"listId", 0);

			g_SchemeBuffer.RequestClearList(pUser, true, true, listId);
			return true;
		}else if( wBypass.find(L"sb_r_r_p") == 0)
		{
			g_SchemeBuffer.RequestRecovery(pUser, false);
			return true;
		}else if( wBypass.find(L"sb_r_r_s") == 0)
		{
			g_SchemeBuffer.RequestRecovery(pUser, true);
			return true;
		}else if( wBypass.find(L"sb_r_d_p") == 0)
		{
			g_SchemeBuffer.RequestDispelAll(pUser, false);
			return true;
		}else if( wBypass.find(L"sb_r_d_s") == 0)
		{
			g_SchemeBuffer.RequestDispelAll(pUser, true);
			return true;
		}else if( wBypass.find(L"sb_r_u_mp") == 0)
		{
			wstring name = CParser::GetBypassValue(wBypass, L"name");

			g_SchemeBuffer.UseMacro(pUser, name, false, true);
			return true;
		}else if( wBypass.find(L"sb_r_u_ms") == 0)
		{
			wstring name = CParser::GetBypassValue(wBypass, L"name");

			g_SchemeBuffer.UseMacro(pUser, name, true, true);
			return true;
		}else if( wBypass.find(L"become_aio?") == 0)
		{
			UINT id = Parser::GetBypassValueInt(wBypass.c_str(), L"id", 0);

			if(!pUser->pED->aioId == 0)
				return true;

			g_AIOSystem.BecomeAIO(pUser, id);
			return true;
		}else if( wBypass.find(L"remove_aio") == 0)
		{
			g_AIOSystem.RemoveAIO(pUser);
			return true;
		}else if( wBypass.find(L"tvt_register?") == 0)
		{
			int team = CParser::GetBypassValueInt(wBypass, L"team=");
			g_TvT.Register(pUser, team);
			return true;
		}else if ( wBypass.find(L"tvt_unregister") == 0)
		{
			g_TvT.Unregister(pUser);
			return true;
		}else if ( wBypass.find(L"cm_nobless") == 0)
		{
			g_ClassManager.RequestNobless(pUser);
			return true;
		}else if ( wBypass.find(L"cm_subclass") == 0)
		{
			g_ClassManager.RequestSubClass(pUser);
			return true;
		}else if ( wBypass.find(L"cm_2subclass") == 0)
		{
			g_ClassManager.RequestSubClass2(pUser);
			return true;
		}else if ( wBypass.find(L"cm_3subclass") == 0)
		{
			g_ClassManager.RequestSubClass3(pUser);
			return true;
		}else if ( wBypass.find(L"cm_2nobless") == 0)
		{
			g_ClassManager.RequestNobless2(pUser);
			return true;
		}else if ( wBypass.find(L"cm_show_page") == 0)
		{
			g_ClassManager.RequestShowHtml(pUser);
			return true;
		}else if ( wBypass.find(L"cm_change?") == 0)
		{
			int newClass = CParser::GetBypassValueInt(wBypass, L"class");
			g_ClassManager.RequestChange(pUser, newClass);
			return true;
		}
		else if ( wBypass.find(L"cm_karma?") == 0)
		{
			int karma = CParser::GetBypassValueInt(wBypass, L"value=");
			g_ClassManager.RequestKarma(pUser,karma);
			return true;
		}else if ( wBypass == L"substack_show")
		{
			g_SubStack.ShowAvailable(pUser);
			return true;
		}else if ( wBypass == L"substack_show_ex")
		{
			g_SubStack.ShowAvailable(pUser, true);
			return true;
		}else if ( wBypass.find(L"substack_add?") == 0)
		{
			UINT newClass = CParser::GetBypassValueInt(wBypass, L"class");
			g_SubStack.RequestStack(pUser, newClass);
			return true;
		}else if ( wBypass.find(L"substack_add_ex?") == 0)
		{
			UINT newClass = CParser::GetBypassValueInt(wBypass, L"class");
			g_SubStack.RequestStack(pUser, newClass, true);
			return true;
		}else if ( wBypass == L"substack_switch")
		{
			g_SubStack.RequestSwitch(pUser);
			return true;
		}else if ( wBypass == L"substack_remove")
		{
			g_SubStack.RequestRemove(pUser);
			return true;
		}else if ( wBypass.find(L"rune_info") == 0)
		{
			pUser->SendRuneInfo();
			return true;
		}else if ( wBypass.find(L"item_time_left") == 0)
		{
			pUser->SendLifeTimeItemsInfo();
			return true;
		}else if ( wBypass.find(L"block_all") == 0)
		{
			if(!pUser->blockAllChat)
			{
				pUser->blockAllChat = true;
				pUser->SendETCBuffStatus();
				pUser->pSocket->SendSystemMessage(961);
			}
			return true;
		}else if ( wBypass.find(L"unblock_all") == 0)
		{
			if(pUser->blockAllChat)
			{
				pUser->blockAllChat = false;
				pUser->SendETCBuffStatus();
				pUser->pSocket->SendSystemMessage(962);
			}
			return true;
		}else if ( wBypass.find(L"offline_shop") == 0)
		{
			g_OfflineShop.RequestActivateOfflineShop(pUser);
			return true;
		}else if ( wBypass.find(L"buy_offline_shop") == 0)
		{
			g_OfflineShop.RequestBuyRequiredItem(pUser);
			return true;
		}else if ( wBypass.find(L"exp_mode") == 0)
		{
			BOOL enabled = CParser::GetBypassValueInt(wBypass, L"state=");
			if(enabled)
			{
				pUser->pSD->pExData->SkillMod.stopExp = 1;
				pUser->pSD->pExData->stopIncExp = 1;
				pUser->pSocket->SendSystemMessage(L"Stop Exp mode have been enabled.");
			}else
			{
				pUser->pSD->pExData->SkillMod.stopExp = 0;
				pUser->pSD->pExData->stopIncExp = 0;
				pUser->pSocket->SendSystemMessage(L"Stop Exp mode have been disabled.");
			}
			return true;
		}else if ( wBypass.find(L"auto_loot") == 0)
		{
			BOOL enabled = CParser::GetBypassValueInt(wBypass, L"state=");
			if(enabled)
			{
				if(!pUser->pED->autoLoot)
				{
					pUser->pED->autoLoot = enabled;
					pUser->pSocket->SendSystemMessage(L"Auto Loot mode have been enabled.");
				}
			}else
			{
				if(pUser->pED->autoLoot)
				{
					pUser->pED->autoLoot = enabled;
					pUser->pSocket->SendSystemMessage(L"Auto Loot mode have been disabled.");
				}
			}
			return true;
		}else if (wBypass.find(L"block_item?") == 0)
		{
			int itemId = Parser::GetBypassValueInt(wBypass.c_str(), L"id");
			int userId = Parser::GetBypassValueInt(wBypass.c_str(), L"userId");
			if(itemId && userId && (pUser->pSD->nBuilder == 1 || pUser->nDBID == userId))
			{
				User *pTarget = g_UserDB.GetUserByDBID(userId);
				if(pTarget->ValidUser())
				{
					if(CItem *pItem = pTarget->inventory.GetItemByDBID(itemId))
					{
						UINT nTimeout = pItem->nProtectionTimeout;
						UINT currentTime = time(0);
						if(nTimeout > currentTime)
						{
							nTimeout = nTimeout - currentTime;
						}else
						{
							nTimeout = 0;
						}
						if(pUser->pSD->nBuilder == 1)
						{
							wstringstream htmlStream;
							htmlStream << L"<html><body><center> <font color=\"LEVEL\" >Nickname: " << pTarget->pSD->wszName << L"</font><br>Item: (" << itemId << L") " << g_ItemDBEx.GetItemName(pItem->pSID->nItemID).c_str() << L"<br>Enchant: " << pItem->pSID->nEnchantLevel << L"<br><br>";
							htmlStream << L"Protection Time: " << nTimeout << L" (s)<br>";
							htmlStream << L"Time in seconds<br>3600 = 1 hour<br>86400 = 1 day<br>604800 = 1 week<br>2592000 = 30 days<br>";
							htmlStream << L"<edit var=\"timeout\" width=120><br>";
							htmlStream << L"<button value=\"Set\" action=\"bypass -h block_item_execute?id=" << itemId << L"&userId=" << userId << L"&timeout = $timeout\" width=40 height=15 back=\"sek.cbui94\" fore=\"sek.cbui92\"><br><br>";
							htmlStream << L"<button value=\"Back\" action=\"bypass -h block_item_list?userId=" << userId << L"\" width=40 height=15 back=\"sek.cbui94\" fore=\"sek.cbui92\"><br><br></center></body></html>";
							PlayerAction::ShowHTML(pUser, L"block_item_execute.htm", htmlStream.str().c_str(), 0);
						}else
						{
							wstringstream htmlStream;
							htmlStream << L"<html><body><center> <font color=\"LEVEL\" >Nickname: " << pTarget->pSD->wszName << L"</font><br>Item: (" << itemId << L") " << g_ItemDBEx.GetItemName(pItem->pSID->nItemID).c_str() << L"<br>Enchant: " << pItem->pSID->nEnchantLevel << L"<br><br>";
							htmlStream << L"Protection Time: " << nTimeout << L" (s)<br>";
							htmlStream << L"Press <font color=\"LEVEL\">Block</font> button to block item for 1 week.<br>";
							htmlStream << L"<button value=\"Block\" action=\"bypass -h block_item_execute?id=" << itemId << L"&userId=" << userId << L"&timeout=604800 \" width=40 height=15 back=\"sek.cbui94\" fore=\"sek.cbui92\"><br><br><br>";
							htmlStream << L"<button value=\"Back\" action=\"bypass -h block_item_list?userId=" << userId << L"\" width=40 height=15 back=\"sek.cbui94\" fore=\"sek.cbui92\"><br><br></center></body></html>";
							PlayerAction::ShowHTML(pUser, L"block_item_execute.htm", htmlStream.str().c_str(), 0);
						}
					}else
					{
						pUser->SendSystemMessage(L"Invalid item!");
					}
				}else
				{
					pUser->SendSystemMessage(L"Invalid user!");
				}
			}
			return true;
		}else if (wBypass.find(L"block_item_execute?") == 0)
		{
			int itemId = Parser::GetBypassValueInt(wBypass.c_str(), L"id");
			UINT userId = Parser::GetBypassValueInt(wBypass.c_str(), L"userId");
			UINT timeout = Parser::GetBypassValueInt(wBypass.c_str(), L"timeout");
			if(itemId && userId && (pUser->pSD->nBuilder == 1 || pUser->nDBID == userId))
			{
				User *pTarget = g_UserDB.GetUserByDBID(userId);
				if(pTarget->ValidUser())
				{
					if(CItem *pItem = pTarget->inventory.GetItemByDBID(itemId))
					{
						time_t left = pItem->nProtectionTimeout - time(0);

						if(pUser->pSD->nBuilder != 1)
						{
							if(timeout != 604800)
							{
								timeout = 604800;
							}
						}

						if(left < timeout || pUser->pSD->nBuilder == 1)
						{
							if(timeout)
							{
								pItem->nProtectionTimeout = timeout + time(0);
								g_DB.RequestSaveItemDataEx(userId, pItem);
							}else
							{
								pItem->nProtectionTimeout = 0;
								g_DB.RequestSaveItemDataEx(userId, pItem);
							}
							pUser->SendSystemMessage(L"Setting new Item Protection succeed.");
						}else
						{
							pUser->SendSystemMessage(L"Only GM is able to set shorter protection time!");
						}
						if(pUser->pSD->nBuilder == 1)
						{
							pTarget->ShowBlockableItems(pUser);
						}else
						{
							pUser->ShowBlockableItems();
						}
					}else
					{
						pUser->SendSystemMessage(L"Invalid item!");
					}
				}else
				{
					pUser->SendSystemMessage(L"Invalid user!");
				}
			}
			return true;
		}else if(wBypass.find(L"block_item_list?") == 0)
		{
			UINT userId = Parser::GetBypassValueInt(wBypass.c_str(), L"userId");
			if(pUser->pSD->nBuilder == 1 || pUser->nDBID == userId)
			{
				User *pTarget = g_UserDB.GetUserByDBID(userId);
				if(pTarget->ValidUser())
				{
					if(pUser->pSD->nBuilder == 1)
					{
						pTarget->ShowBlockableItems(pUser);
					}else
					{
						pTarget->ShowBlockableItems();
					}
				}else
				{
					pUser->ShowBlockableItems();
				}
			}else if( userId == 0)
			{
				pUser->ShowBlockableItems();
			}
			return true;
		}else if(wBypass.find(L"lock_account") == 0)
		{
			if(g_AccountDB.LockHwid(pUser->pSocket->accountId, pUser->pSocket->pED->longHWID.hash, pUser->pSD->wszName))
			{
				pUser->SendSystemMessage(L"Your account have been locked.");
			}else
			{
				pUser->SendSystemMessage(L"Your account is already locked.");
			}
			return true;
		}else if(wBypass.find(L"unlock_account") == 0)
		{
			if(g_AccountDB.UnlockHwid(pUser->pSocket->accountId, pUser->pSD->wszName))
			{
				pUser->SendSystemMessage(L"Your account have been unlocked.");
			}else
			{
				pUser->SendSystemMessage(L"Your account is already unlocked.");
			}
			return true;
		}else if(wBypass.find(L"lock_char") == 0)
		{
			if(g_AccountDB.LockHwidChar(pUser->nDBID, pUser->pSocket->pED->longHWID.hash, pUser->pSD->wszName))
			{
				pUser->SendSystemMessage(L"Your character have been locked.");
			}else
			{
				pUser->SendSystemMessage(L"Your character is already locked.");
			}
			return true;
		}else if(wBypass.find(L"unlock_char") == 0)
		{
			if(g_AccountDB.UnlockHwidChar(pUser->nDBID, pUser->pSD->wszName))
			{
				pUser->SendSystemMessage(L"Your character have been unlocked.");
			}else
			{
				pUser->SendSystemMessage(L"Your character is already unlocked.");
			}
			return true;
		}else if (wBypass.find(L"set_additional_box?") == 0)
		{
			UINT timeParam = Parser::GetBypassValueInt(wBypass.c_str(), L"time");
			if(timeParam > 0)
			{
				g_AccountDB.SetAdditionalBox(pUser->pSocket->accountId, (timeParam + time(0)));
				pUser->SendSystemMessage(L"Your additional box have been enabled.");
			}else
			{
				g_AccountDB.SetAdditionalBox(pUser->pSocket->accountId, 0);
				pUser->SendSystemMessage(L"Your additional box have been disabled.");
			}

			return true;
		}else if(wBypass.find(L"fraction_signup?") == 0)
		{
			UINT fractionId = Parser::GetBypassValueInt(wBypass.c_str(), L"id");
			if(fractionId > 0)
			{
				g_FractionSystem.Register(pUser, fractionId);
			}
			return true;
		}else if(wBypass.find(L"fraction_leave") == 0)
		{
			g_FractionSystem.Unregister(pUser);
			return true;
		}
		//Retail BBS tabs
		else if(wBypass.find(L"_bbsgetfav") == 0 && g_Auction.IsEnabled()) //2nd
		{
			g_Auction.RequestShowAuction(pUser, 0);
			return true;
		}else if(wBypass.find(L"_bbsloc") == 0 && g_Auction.IsEnabled()) //3rd
		{
			g_Auction.RequestShowAuction(pUser, 0);
			return true;
		}else if(wBypass.find(L"_bbsclan") == 0 && g_Auction.IsEnabled()) //4th
		{
			g_Auction.RequestShowAuction(pUser, 0);
			return true;
		}else if(wBypass.find(L"_bbsmemo") == 0 && g_Auction.IsEnabled()) //5th
		{
			g_Auction.RequestShowAuction(pUser, 0);
			return true;
		}else if(wBypass.find(L"_maillist_0_1_0_") == 0 && g_Auction.IsEnabled()) //6th
		{
			g_Auction.RequestShowAuction(pUser, 0);
			return true;
		}else if(wBypass.find(L"_friendlist_0_") == 0 && g_Auction.IsEnabled()) //7th
		{
			g_Auction.RequestShowAuction(pUser, 0);
			return true;
		}
		//End
		else if(wBypass.find(L"_auction_show") == 0)
		{
			//wstring category = CParser::GetBypassValue(wBypass, L"category");
			UINT page = Parser::GetBypassValueInt(wBypass.c_str(), L"page", 0);
			g_Auction.RequestShowAuction(pUser, page);
			return true;
		}else if(wBypass.find(L"_auction_me?") == 0)
		{
			UINT page = Parser::GetBypassValueInt(wBypass.c_str(), L"page", 0);
			UINT page2 = Parser::GetBypassValueInt(wBypass.c_str(), L"pag2", 0);
			UINT nItemDBid = Parser::GetBypassValueInt(wBypass.c_str(), L"item", 0);
			g_Auction.RequestShowAuctionMe(pUser, page, page2, nItemDBid);
			return true;
		}else if(wBypass.find(L"_auc_can_con?") == 0)
		{
			UINT nAuctionID = Parser::GetBypassValueInt(wBypass.c_str(), L"id", 0);
			g_Auction.RequestCancelAuctionConfirm(pUser,nAuctionID);
			return true;
		}else if(wBypass.find(L"_auction_cancel?") == 0)
		{
			UINT nAuctionID = Parser::GetBypassValueInt(wBypass.c_str(), L"auctionid", 0);
			g_Auction.RequestCancelAuction(pUser,nAuctionID);
			return true;
		}else if(wBypass.find(L"_auction_set_con_item?") == 0)
		{
			//auction_set_item?amount= $item_amount &price= $item_price
			int itemID = Parser::GetBypassValueInt(wBypass.c_str(), L"id");
			int itemAmount = Parser::GetBypassValueInt(wBypass.c_str(), L"amount");
			int itemPrice = Parser::GetBypassValueInt(wBypass.c_str(), L"price");
			wstring pricename = CParser::GetBypassValue(wBypass, L"priceid");
			g_Auction.RequestSetAuctionConfirm(pUser, itemID, pricename, itemPrice, itemAmount);
			return true;
		}else if(wBypass.find(L"_auction_set_item?") == 0)
		{
			//auction_set_item?amount= $item_amount &price= $item_price
			int itemID = Parser::GetBypassValueInt(wBypass.c_str(), L"id");
			int itemAmount = Parser::GetBypassValueInt(wBypass.c_str(), L"amount");
			int itemPrice = Parser::GetBypassValueInt(wBypass.c_str(), L"price");
			UINT priceId = Parser::GetBypassValueInt(wBypass.c_str(), L"priceid");
			g_Auction.RequestSetAuction(pUser, itemID, priceId, itemPrice, itemAmount);
			return true;
		}else if(wBypass.find(L"_auction_buy?") == 0)
		{
			UINT auctionId = Parser::GetBypassValueInt(wBypass.c_str(), L"id", 0);
			g_Auction.RequestBuyAuctionPreview(pUser, auctionId);
			return true;
		}else if(wBypass.find(L"_auction_confirm_buy?") == 0)
		{
			UINT auctionId = Parser::GetBypassValueInt(wBypass.c_str(), L"id", 0);
			INT32 amount = Parser::GetBypassValueInt(wBypass.c_str(), L"amount", 0);
			g_Auction.RequestBuyAuctionConfirm(pUser, auctionId, amount);
			return true;
		}else if(wBypass.find(L"_auction_final_buy?") == 0)
		{
			UINT auctionId = Parser::GetBypassValueInt(wBypass.c_str(), L"id", 0);
			UINT amount = Parser::GetBypassValueInt(wBypass.c_str(), L"amount", 0);
			g_Auction.RequestBuy(pUser, auctionId, amount);
			return true;
		}else if(wBypass.find(L"auct_sear_gr?") == 0)
		{
			wstring grade = CParser::GetBypassValue(wBypass, L"grade");
			g_Auction.SetSpecsGrade(pUser, grade);
			return true;
		}else if(wBypass.find(L"auct_sear_cat?") == 0)
		{
			wstring cat = CParser::GetBypassValue(wBypass, L"cat");
			g_Auction.SetSpecsCat(pUser, cat);
			return true;
		}else if(wBypass.find(L"auct_sear_subcat?") == 0)
		{
			wstring subc = CParser::GetBypassValue(wBypass, L"subc");
			g_Auction.SetSpecsSubCat(pUser, subc);
			return true;
		}else if(wBypass.find(L"auct_sear_itemn?") == 0)
		{
			wstring itemn = CParser::GetBypassValue(wBypass, L"itemn");
			g_Auction.SetSpecsItemName(pUser, itemn);
			return true;
		}else if(wBypass.find(L"auct_sear_clear") == 0)
		{
			g_Auction.SetSpecsClear(pUser);
			return true;
		}else if(wBypass == L"va_equip_request")
		{
			g_VisualArmor.OnRequestEquip(pUser);
			return true;
		}else if(wBypass.find(L"va_equip?") == 0)
		{
			UINT armorId = Parser::GetBypassValueInt(wBypass.c_str(), L"id");
			g_VisualArmor.OnEquip(pUser, armorId);
			return true;
		}else if(wBypass == L"va_unequip")
		{
			g_VisualArmor.OnUnequip(pUser);
			return true;
		}else if(wBypass.find(L"rb_status?page") == 0)
		{
			UINT page = Parser::GetBypassValueInt(wBypass.c_str(), L"page");
			g_RaidBossStatus.RequestRaidBossStatus(pUser, page);
			return true;
		}else if(wBypass.find(L"pk_status?page") == 0)
		{
			UINT page = Parser::GetBypassValueInt(wBypass.c_str(), L"page");
			g_PKPvPStatus.RequestPKStatus(pUser, page);
			return true;
		}else if(wBypass.find(L"epic_items?page") == 0)
		{
			UINT page = Parser::GetBypassValueInt(wBypass.c_str(), L"page");
			g_EpicItems.RequestEpicItems(pUser, page);
			return true;
		}else if(wBypass.find(L"pvp_status?page") == 0)
		{
			UINT page = Parser::GetBypassValueInt(wBypass.c_str(), L"page");
			g_PKPvPStatus.RequestPvPStatus(pUser, page);
			return true;
		}else if(wBypass.find(L"daily_status?page") == 0)
		{
			UINT page = Parser::GetBypassValueInt(wBypass.c_str(), L"page");
			g_PKPvPStatus.RequestDailyStatus(pUser, page);
			return true;
		}
		else if(wBypass.find(L"oly_status?") == 0)
		{
			UINT page = Parser::GetBypassValueInt(wBypass.c_str(), L"page");
			UINT classId = Parser::GetBypassValueInt(wBypass.c_str(), L"class");
			if( classId >= 88 && classId <= 118 )
				g_OlympiadStatus.RequestStatusOly(pUser, classId ); //TODO FIX Oly Classes
			//118
			return true;
		}		
		else if(wBypass.find(L"clan_pvp_status?page") == 0)
		{
			UINT page = Parser::GetBypassValueInt(wBypass.c_str(), L"page");
			g_ClanPvPStatus.RequestPvPStatus(pUser, page);
			return true;
		}
		else if(wBypass.find(L"clan_raid_status?page") == 0)
		{
			UINT page = Parser::GetBypassValueInt(wBypass.c_str(), L"page");
			g_ClanReputationRank.RequestClanRaidStatus(pUser, page);
			return true;
		}else if(wBypass.find(L"don_category?") == 0)
		{
			UINT category = Parser::GetBypassValueInt(wBypass.c_str(), L"cat");
			UINT page = Parser::GetBypassValueInt(wBypass.c_str(), L"page");
			g_DonateSystem.RequestShowCategory(pUser, category, page);
			return true;
		}else if(wBypass.find(L"don_item?") == 0)
		{
			UINT category = Parser::GetBypassValueInt(wBypass.c_str(), L"cat");
			UINT item = Parser::GetBypassValueInt(wBypass.c_str(), L"item");
			g_DonateSystem.RequestShowItem(pUser, category, item);
			return true;
		}else if(wBypass.find(L"don_augm_category?") == 0)
		{
			UINT category = Parser::GetBypassValueInt(wBypass.c_str(), L"cat");
			UINT page = Parser::GetBypassValueInt(wBypass.c_str(), L"page");
			g_DonateSystemAugment.RequestShowCategory(pUser, category, page);
			return true;
		}else if(wBypass.find(L"don_augm_item?") == 0)
		{
			UINT category = Parser::GetBypassValueInt(wBypass.c_str(), L"cat");
			UINT augment = Parser::GetBypassValueInt(wBypass.c_str(), L"augm");
			g_DonateSystemAugment.RequestShowItems(pUser, category, augment);
			return true;
		}else if(wBypass.find(L"don_augm_weps?") == 0)
		{
			UINT page = Parser::GetBypassValueInt(wBypass.c_str(), L"page");
			g_DonateSystemAugment.RequestShowUserWeapons(pUser, page);
			return true;
		}else if(wBypass.find(L"don_augm_buy?") == 0)
		{
			UINT cat = Parser::GetBypassValueInt(wBypass.c_str(), L"catid");
			UINT itemid = Parser::GetBypassValueInt(wBypass.c_str(), L"itemid");
			UINT augment = Parser::GetBypassValueInt(wBypass.c_str(), L"augm");
			g_DonateSystemAugment.RequestBuyAugment(pUser, cat, itemid, augment);
			return true;
		}else if(wBypass.find(L"show_droplist?") == 0)
		{
			UINT npcid = Parser::GetBypassValueInt(wBypass.c_str(), L"npcid");
			UINT page = Parser::GetBypassValueInt(wBypass.c_str(), L"page");
			g_DropList.ShowDroplist(pUser, npcid, page);
			return true;
		}else if(wBypass.find(L"show_spoillist?") == 0)
		{
			UINT npcid = Parser::GetBypassValueInt(wBypass.c_str(), L"npcid");
			UINT page = Parser::GetBypassValueInt(wBypass.c_str(), L"page");
			g_DropList.ShowSpoilDroplist(pUser, npcid, page);
			return true;
		}else if(wBypass.find(L"s_buffstore_player?") == 0)
		{
			//bypass s_buffstore_player?bufferid=ID&pageid=ID
			int nBufferID = Parser::GetBypassValueInt(wBypass.c_str(), L"bufferid");
			int nPageID = Parser::GetBypassValueInt(wBypass.c_str(), L"pageid");
			g_OfflineBuffer.ShowOfflineBufferList2(pUser, nBufferID, nPageID, false);
			return true;
		}else if(wBypass.find(L"s_buffstore_pet?") == 0)
		{
			//bypass s_buffstore_pet?bufferid=ID&pageid=ID
			int nBufferID = Parser::GetBypassValueInt(wBypass.c_str(), L"bufferid");
			int nPageID = Parser::GetBypassValueInt(wBypass.c_str(), L"pageid");
			g_OfflineBuffer.ShowOfflineBufferList2( pUser, nBufferID, nPageID, true);
			return true;
		}else if(wBypass.find(L"buffstore_player?") == 0)
		{
			//bypass buffstore_player?skill=ID&bufferid=ID
			int nSkillID = Parser::GetBypassValueInt(wBypass.c_str(), L"skill");
			int nBufferID = Parser::GetBypassValueInt(wBypass.c_str(), L"bufferid");
			g_OfflineBuffer.BuyBuff(pUser, nSkillID, nBufferID, false);
			return true;
		}else if(wBypass.find(L"buffstore_pet?") == 0)
		{
			//bypass buffstore_pet?skill=ID&bufferid=ID
			int nSkillID = Parser::GetBypassValueInt(wBypass.c_str(), L"skill");
			int nBufferID = Parser::GetBypassValueInt(wBypass.c_str(), L"bufferid");
			g_OfflineBuffer.BuyBuff(pUser, nSkillID, nBufferID, true);
			return true;
		}else if(wBypass.find(L"vip_help") == 0)
		{
			g_VIPSystem.OnHelp(pUser);
			return true;
		}else if(wBypass.find(L"vip_status") == 0)
		{
			g_VIPSystem.OnStatus(pUser);
			return true;
		}else if(wBypass.find(L"vip_bonus") == 0)
		{
			UINT level = Parser::GetBypassValueInt(wBypass.c_str(), L"level");
			if(level > 0)
			{
				g_VIPSystem.SendBonusInfo(pUser, level);
			}
			return true;
		}else if(wBypass.find(L"vip_upgrade") == 0)
		{
			UINT level = Parser::GetBypassValueInt(wBypass.c_str(), L"level");
			if(level > 0)
			{
				g_VIPSystem.RequestChangeLevel(pUser, level);
			}
			return true;
		}else if(wBypass.find(L"open_website?url") == 0)
		{
			wstring url = wBypass.substr(17, wBypass.size() - 17);
			pUser->pSocket->Send("cdS", 0x87, 0x04, url.c_str());

			return true;
		}else if(wBypass.find(L"send_command?cmd") == 0)
		{
			wstring url = wBypass.substr(17, wBypass.size() - 17);
			pUser->pSocket->Send("cdS", 0x87, 14, url.c_str());

			return true;
		}else if( wBypass == L"rebirth_show" )
		{
			g_RebirthSystem.ShowMenu(pUser);
			return true;
		}else if( wBypass == L"rebirth_do" )
		{
			g_RebirthSystem.OnRebirth(pUser);
			return true;
		}else if( wBypass == L"rebirth_distribute" )
		{
			g_RebirthSystem.OnDistributeStats(pUser);
			return true;
		}else if( wBypass == L"rebirth_inc_str")
		{
			g_RebirthSystem.OnIncreaseStats(pUser, StatStr);
			return true;
		}else if( wBypass == L"rebirth_inc_int")
		{
			g_RebirthSystem.OnIncreaseStats(pUser, StatInt);
			return true;
		}else if( wBypass == L"rebirth_inc_con")
		{
			g_RebirthSystem.OnIncreaseStats(pUser, StatCon);
			return true;
		}else if( wBypass == L"rebirth_inc_men")
		{
			g_RebirthSystem.OnIncreaseStats(pUser, StatMen);
			return true;
		}else if( wBypass == L"rebirth_inc_dex")
		{
			g_RebirthSystem.OnIncreaseStats(pUser, StatDex);
			return true;
		}else if( wBypass == L"rebirth_inc_wit")
		{
			g_RebirthSystem.OnIncreaseStats(pUser, StatWit);
			return true;
		}
		else if( wBypass.find(L"_sell_pet?") == 0)
		{
			//ex bypass - h _sell_pet?petId=1012781&petLevel=55&collarId=6650&priceId=57&priceAmount=1000000
			INT32 petClassId = Parser::GetBypassValueInt(wBypass.c_str(), L"petId");
			INT32 petLevel = Parser::GetBypassValueInt(wBypass.c_str(), L"petLevel");
			INT32 collarId = Parser::GetBypassValueInt(wBypass.c_str(), L"collarId");
			INT32 priceId = Parser::GetBypassValueInt(wBypass.c_str(), L"priceId");
			INT32 priceAmount = Parser::GetBypassValueInt(wBypass.c_str(), L"priceAmount");

			if(petClassId && collarId)
			{
				//check requirement
				if(priceId > 0 && priceAmount > 0)
				{
					if(pUser->DeleteItemInInventory(priceId, priceAmount))
					{
						typedef void(*f)(User*, INT32, INT32, INT32);
						f(0x74BED0L)(pUser, collarId, petClassId, petLevel);
					}
				}
			}
			return true;
		}else if( wBypass.find(L"bs_buy_item?") == 0)
		{
			if(!pUser->InCombat())
			{
				//bypass -h bs_buy_item?priceId=57&priceAmount=3000&rewardId=7575&rewardAmount=1&rewardEnchant=0
				INT32 priceId = Parser::GetBypassValueInt(wBypass.c_str(), L"priceId");
				INT32 priceAmount = Parser::GetBypassValueInt(wBypass.c_str(), L"priceAmount");
				INT32 rewardId = Parser::GetBypassValueInt(wBypass.c_str(), L"rewardId");
				INT32 rewardAmount = Parser::GetBypassValueInt(wBypass.c_str(), L"rewardAmount");
				INT32 rewardEnchant = Parser::GetBypassValueInt(wBypass.c_str(), L"rewardEnchant");

				if(priceId > 0 && priceAmount > 0 && rewardId > 0 && rewardAmount > 0)
				{
					if(pUser->IsNowTrade() == false)
					{
						if(pUser->inventory.CheckAddable(rewardId, rewardAmount))
						{
							if(pUser->DeleteItemInInventory(priceId, priceAmount))
							{
								pUser->AddItemToInventory(rewardId, rewardAmount, false, rewardEnchant, 0, 0);
								g_Logger.Add(L"User[%s][%d] bought item[%d][%d] enchant[%d] price[%d][%d]", pUser->pSD->wszName, pUser->nDBID, rewardId, rewardAmount, rewardEnchant, priceId, priceAmount);
							}
							else
								pUser->SendSystemMessage(L"You don't have the required items!");
						}
						else
							pUser->SendSystemMessage(L"You don't have enough free slots on your char!");
					}
					else
						pUser->SendSystemMessage(L"You can proceed with your transaction after your trade!");
				}
			}else
			{
				pUser->SendSystemMessage(L"You cannot buy items in combat mode!");
			}

			return true;
		}else if( wBypass.find(L"giveitem?") == 0)
		{
			if(!pUser->InCombat())
			{
				//bypass -h giveitem?rewardId=7575&rewardAmount=1&rewardEnchant=0
				INT32 rewardId = Parser::GetBypassValueInt(wBypass.c_str(), L"rewardId");
				INT32 rewardAmount = Parser::GetBypassValueInt(wBypass.c_str(), L"rewardAmount");
				INT32 rewardEnchant = Parser::GetBypassValueInt(wBypass.c_str(), L"rewardEnchant");

				if( rewardId > 0 && rewardAmount > 0)
				{
					pUser->AddItemToInventory(rewardId, rewardAmount, false, rewardEnchant, 0, 0);
					g_Logger.Add(L"User[%s][%d] bought item[%d][%d] enchant[%d]", pUser->pSD->wszName, pUser->nDBID, rewardId, rewardAmount, rewardEnchant);
				}
			}else
			{
				pUser->SendSystemMessage(L"You cannot buy items in combat mode!");
			}

			return true;
		}else if( wBypass.find(L"captcha_validate?") == 0)
		{
			if( (pUser->pED->captchaProtectionTimeout > 0) || ( pUser->pED->captchaProtectionTimeout == 0 && pUser->pED->captchaPeriod == 1) )
			{
				int answer = CParser::GetBypassValueInt(wBypass, L"answer=");
				//g_Captcha.Validate(pUser, answer, false);
			}
			else
			{
				//2636	1	Captcha System: You cannot solve captcha right now.	0	79	9B	B0	FF			0	0	0	0	0		none
				pUser->SendSystemMessage(2636);
			}
			return true;
		}else if( wBypass.find(L"captcha_2validate") == 0)
		{
			if( (pUser->pED->captchaProtectionTimeout > 0) || ( pUser->pED->captchaProtectionTimeout == 0 && pUser->pED->captchaPeriod == 1) )
			{
				g_Captcha.Validate(pUser, L"0", true);
			}
			else
			{
				//2636	1	Captcha System: You cannot solve captcha right now.	0	79	9B	B0	FF			0	0	0	0	0		none
				pUser->SendSystemMessage(2636);
			}
			return true;
		}
		else if( (wBypass.find(pUser->pED->captchaQuestion) == 0) && pUser->pED->captchaPeriod == 1 )
		{
			if( (pUser->pED->captchaProtectionTimeout > 0) || ( pUser->pED->captchaProtectionTimeout == 0 && pUser->pED->captchaPeriod == 1) )
			{
				g_Captcha.Validate(pUser, wBypass, false);
				//g_Log.Add(CLog::Error, "[%s] Bypass[%S]", __FUNCTION__, wBypass.c_str());
			}
			else
			{
				//2636	1	Captcha System: You cannot solve captcha right now.	0	79	9B	B0	FF			0	0	0	0	0		none
				pUser->SendSystemMessage(2636);
			}
			return true;			
		}
		else if( (wBypass.find(pUser->pED->captchaWQuestion1) == 0) && pUser->pED->captchaPeriod == 1 )
		{
			if( (pUser->pED->captchaProtectionTimeout > 0) || ( pUser->pED->captchaProtectionTimeout == 0 && pUser->pED->captchaPeriod == 1) )
			{
				g_Captcha.Validate(pUser, wBypass, false);
				//g_Log.Add(CLog::Error, "[%s] Bypass wrong1[%S]", __FUNCTION__, wBypass.c_str());
			}
			else
			{
				//2636	1	Captcha System: You cannot solve captcha right now.	0	79	9B	B0	FF			0	0	0	0	0		none
				pUser->SendSystemMessage(2636);
			}
			return true;			
		}
		else if( (wBypass.find(pUser->pED->captchaWQuestion2) == 0) && pUser->pED->captchaPeriod == 1 )
		{
			if( (pUser->pED->captchaProtectionTimeout > 0) || ( pUser->pED->captchaProtectionTimeout == 0 && pUser->pED->captchaPeriod == 1) )
			{
				g_Captcha.Validate(pUser, wBypass, false);
				//g_Log.Add(CLog::Error, "[%s] Bypass wrong2[%S]", __FUNCTION__, wBypass.c_str());
			}
			else
			{
				//2636	1	Captcha System: You cannot solve captcha right now.	0	79	9B	B0	FF			0	0	0	0	0		none
				pUser->SendSystemMessage(2636);
			}
			return true;			
		}
		else if( wBypass.find(L"offline_buffer?") == 0 )
		{
			//bypass -h offline_buffer?price= $price & title= $title
			wstring wTitle = CParser::GetBypassValue(wBypass, L"title=");
			wstring wPriceParser = CParser::GetBypassValue(wBypass, L"price=");
			int nPrice = _wtoi(wPriceParser.c_str());

			g_OfflineBuffer.EnableBuffer(pUser,wTitle,nPrice);
			return true;
		}
	}
	return false;
}