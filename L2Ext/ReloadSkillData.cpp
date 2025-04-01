#include "StdAfx.h"
#include "ReloadSkillData.h"
#include <iostream>
#include <string>


bool ReloadSkillData::ReloadSkills(int skillId)
{
	guard;

	wstring str = ReadFileW(L".\\tmp.log");
	wstringstream sstr;
	sstr << str;
	wstring wLineA;
	wstring wLine;

	bool ret = false;
	int skill_id;
	int skill_lv;

	//						ofstream file("1.txt");

	while(getline(sstr, wLineA))
	{
	skill_id = 0;
	skill_lv = 0;


		wstring wLine = CParser::Trim2(wLineA);

//continue;

		if(wLine.find(L"//") == 0)
			continue;
		else if(wLine.find(L"skill_id"))
		{

			skill_id = _wtoi(CParser::GetValueString(wLine, L"	skill_id").c_str());

			if (skillId == skill_id || skillId == 999999 && skill_id>0)
			{
				if(wLine.find(L"level"))
				{
					skill_lv = _wtoi(CParser::GetValueString(wLine, L"	level").c_str());


					if(CSkillInfo *pSI = g_SkillDB.GetSkillInfo(skill_id, skill_lv))
					{
						//g_Log.Add(CLog::Blue, "pSI->dReuseDelay[%f]", pSI->dReuseDelay);
						
						ret = true;

						if(wLine.find(L"LLLLLLLLLLLmagic_level"))
						{
	//						pSI->nMagicLevel = _wtoi(CParser::GetBypassValue(wLine, L"magic_level=").c_str());
						}
						if(wLine.find(L"LLLLLLLLLLLis_magic"))
						{
	//						pSI->nIsMagic = _wtoi(CParser::GetBypassValue(wLine, L"is_magic=").c_str());
						}
						if(wLine.find(L"LLLLLLLLLLLoperate_type"))
						{
	//						wstring wStr = CParser::GetValueString(wLine, L"operate_type");
	//						if(wStr == L"A1")		pSI->operateType = OperateA1;
	//						else if(wStr == L"A2")	pSI->operateType = OperateA2;
	//						else if(wStr == L"A3")	pSI->operateType = OperateA3;
	//						else if(wStr == L"A4")	pSI->operateType = OperateA4;
	//						else if(wStr == L"P")	pSI->operateType = OperatePassive;
	//						else if(wStr == L"T")	pSI->operateType = OperateToggle;
	//						else if(wStr == L"PP")	pSI->operateType = OperatePP;

//g_Log.Add(CLog::Blue, "pSI->operateType[%d] Parser operate_type=[%S]", pSI->BaseProperty, CParser::GetValueString(wLine, L"operate_type").c_str());

						}
						if(wLine.find(L"LLLLLLLLLLLmp_consume1"))
						{
	//						pSI->nConsumeMP1 = _wtoi(CParser::GetBypassValue(wLine, L"mp_consume1=").c_str());
						}
						if(wLine.find(L"LLLLLLLLLLLmp_consume2"))
						{
	//						pSI->nConsumeMP2 = _wtoi(CParser::GetBypassValue(wLine, L"mp_consume2=").c_str());
						}
						if(wLine.find(L"LLLLLLLLLLLhp_consume"))
						{
	//						pSI->nConsumeHP = _wtoi(CParser::GetBypassValue(wLine, L"hp_consume=").c_str());
						}
						if(wLine.find(L"LLLLLLLLLLLeffective_range"))
						{
	//						pSI->nEffectiveRange = _wtoi(CParser::GetBypassValue(wLine, L"effective_range=").c_str());
						}
						if(wLine.find(L"LLLLLLLLLLLskill_hit_time"))
						{
//							pSI->dSkillHitTime = Parser::ParseOptionDouble(wLine, L"skill_hit_time=");
						}
						if(wLine.find(L"LLLLLLLLLLLskill_cool_time"))
						{
//							pSI->dSkillCoolTime = Parser::ParseOptionDouble(wLine, L"skill_cool_time=");
						}
						if(wLine.find(L"LLLLLLLLLLLskill_hit_cancel_time"))
						{
//							pSI->dSkillHitCancelTime = Parser::ParseOptionDouble(wLine, L"skill_hit_cancel_time=");
						}
						if(wLine.find(L"LLLLLLLLLLLreuse_delay"))
						{
						//	pSI->dReuseDelay = Parser::ParseOptionDouble(wLine, L"reuse_delay=");
						}
						if(wLine.find(L"LLLLLLLLLLLlv_bonus_rate"))
						{
//							pSI->LevelBonusRate = Parser::ParseOptionDouble(wLine, L"lv_bonus_rate=");
						}
						if(wLine.find(L"LLLLLLLLLLLactivate_rate"))
						{
//							pSI->nActivateRate =  _wtoi(CParser::GetBypassValue(wLine, L"activate_rate=").c_str());
						}
						if(wLine.find(L"LLLLLLLLLLLbasic_property"))
						{
//							wstring wStr = CParser::GetValueString(wLine, L"basic_property");
//							if(wStr == L"str")			pSI->BaseProperty = CSkillInfo::PROP_STR;
//							else if(wStr == L"dex")		pSI->BaseProperty = CSkillInfo::PROP_DEX;
//							else if(wStr == L"con")		pSI->BaseProperty = CSkillInfo::PROP_CON;
//							else if(wStr == L"int")		pSI->BaseProperty = CSkillInfo::PROP_INT;
//							else if(wStr == L"men")		pSI->BaseProperty = CSkillInfo::PROP_MEN;
//							else if(wStr == L"wit")		pSI->BaseProperty = CSkillInfo::PROP_WIT;
//							else if(wStr == L"none")	pSI->BaseProperty = CSkillInfo::PROP_NONE;

//g_Log.Add(CLog::Blue, "pSI->BaseProperty[%d] Parser basic_property=[%S]", pSI->BaseProperty, CParser::GetValueString(wLine, L"basic_property").c_str());
						}
						if(wLine.find(L"LLLLLLLLLLLabnormal_time"))	//OK
						{
//							pSI->nAbnormalTime =  _wtoi(CParser::GetBypassValue(wLine, L"abnormal_time=").c_str());
						}
						if(wLine.find(L"LLLLLLLLLLLabnormal_lv"))
						{
//							pSI->nAbnormalLevel =  _wtoi(CParser::GetBypassValue(wLine, L"abnormal_lv=").c_str());
						}
						if(wLine.find(L"LLLLLLLLLLLabnormal_type"))
						{
							wstring wStr = CParser::GetValueString(wLine, L"abnormal_type");
//							if(wStr == L"none")							pSI->nAbnormalType = -1;
//							else if(wStr == L"pa_up")					pSI->nAbnormalType = 0;
//							else if(wStr == L"pa_up_special")			pSI->nAbnormalType = 1;
//							else if(wStr == L"pa_down")					pSI->nAbnormalType = 2;
//							else if(wStr == L"pd_up")					pSI->nAbnormalType = 3;
//							else if(wStr == L"pd_up_special")			pSI->nAbnormalType = 4;
//							else if(wStr == L"ma_up")					pSI->nAbnormalType = 5;
//							else if(wStr == L"md_up")					pSI->nAbnormalType = 6;
//							else if(wStr == L"md_up_attr")				pSI->nAbnormalType = 7;
//							else if(wStr == L"avoid_up")				pSI->nAbnormalType = 8;
//							else if(wStr == L"avoid_up_special")		pSI->nAbnormalType = 9;
//							else if(wStr == L"hit_up")					pSI->nAbnormalType = 10;
//							else if(wStr == L"hit_down")				pSI->nAbnormalType = 11;
//							else if(wStr == L"fatal_poison")			pSI->nAbnormalType = 12;
//							else if(wStr == L"fly_away")				pSI->nAbnormalType = 13;
//							else if(wStr == L"turn_stone")				pSI->nAbnormalType = 14;
//							else if(wStr == L"casting_time_down")		pSI->nAbnormalType = 15;
//							else if(wStr == L"attack_time_down")		pSI->nAbnormalType = 16;
//							else if(wStr == L"speed_up")				pSI->nAbnormalType = 17;
//							else if(wStr == L"possession")				pSI->nAbnormalType = 18;
//							else if(wStr == L"attack_time_up")			pSI->nAbnormalType = 19;
//							else if(wStr == L"speed_down")				pSI->nAbnormalType = 20;
//							else if(wStr == L"hp_regen_up")				pSI->nAbnormalType = 21;
//							else if(wStr == L"max_mp_up")				pSI->nAbnormalType = 22;
//							else if(wStr == L"antaras_debuff")			pSI->nAbnormalType = 23;
//							else if(wStr == L"critical_prob_up")		pSI->nAbnormalType = 24;
//							else if(wStr == L"cancel_prob_down")		pSI->nAbnormalType = 25;
//							if(wStr == L"bow_range_up")					pSI->nAbnormalType = 26;			//los bloques estaban demasiado anidados por eso quito el else
//							else if(wStr == L"max_breath_up")			pSI->nAbnormalType = 27;
//							else if(wStr == L"decrease_weight_penalty") pSI->nAbnormalType = 28;
//							else if(wStr == L"poison")					pSI->nAbnormalType = 29;
//							else if(wStr == L"bleeding")				pSI->nAbnormalType = 30;
//							else if(wStr == L"dot_attr")				pSI->nAbnormalType = 31;
//							else if(wStr == L"dot_mp")					pSI->nAbnormalType = 32;
//							else if(wStr == L"dmg_shield")				pSI->nAbnormalType = 33;
//							else if(wStr == L"ab_hawk_eye")				pSI->nAbnormalType = 34;
//							else if(wStr == L"resist_shock")			pSI->nAbnormalType = 35;
//							else if(wStr == L"paralyze")				pSI->nAbnormalType = 36;
//							else if(wStr == L"public_slot")				pSI->nAbnormalType = 37;
//							else if(wStr == L"silence")					pSI->nAbnormalType = 38;
//							else if(wStr == L"derangement")				pSI->nAbnormalType = 39;
//							else if(wStr == L"stun")					pSI->nAbnormalType = 40;
//							else if(wStr == L"resist_poison")			pSI->nAbnormalType = 41;
//							else if(wStr == L"resist_derangement")		pSI->nAbnormalType = 42;
//							else if(wStr == L"resist_spiritless")		pSI->nAbnormalType = 43;
//							else if(wStr == L"mp_regen_up")				pSI->nAbnormalType = 44;
//							else if(wStr == L"md_down")					pSI->nAbnormalType = 45;
//							else if(wStr == L"heal_effect_down")		pSI->nAbnormalType = 46;
//							else if(wStr == L"turn_passive")			pSI->nAbnormalType = 47;
//							else if(wStr == L"turn_flee")				pSI->nAbnormalType = 48;
//							else if(wStr == L"vampiric_attack")			pSI->nAbnormalType = 49;
//							else if(wStr == L"duelist_spirit")			pSI->nAbnormalType = 50;
//							else if(wStr == L"hp_recover")				pSI->nAbnormalType = 51;
//							else if(wStr == L"mp_recover")				pSI->nAbnormalType = 52;
//							else if(wStr == L"root")					pSI->nAbnormalType = 53;
//							else if(wStr == L"speed_up_special")		pSI->nAbnormalType = 54;
//							else if(wStr == L"majesty")					pSI->nAbnormalType = 55;
//							else if(wStr == L"pd_up_bow")				pSI->nAbnormalType = 56;
//							else if(wStr == L"attack_speed_up_bow")		pSI->nAbnormalType = 57;
//							else if(wStr == L"max_hp_up")				pSI->nAbnormalType = 58;
//							else if(wStr == L"holy_attack")				pSI->nAbnormalType = 59;
//							else if(wStr == L"sleep")					pSI->nAbnormalType = 60;
//							else if(wStr == L"berserker")				pSI->nAbnormalType = 61;
//							else if(wStr == L"pinch")					pSI->nAbnormalType = 62;
//							else if(wStr == L"life_force")				pSI->nAbnormalType = 63;
//							else if(wStr == L"song_of_earth")			pSI->nAbnormalType = 64;
//							else if(wStr == L"song_of_life")			pSI->nAbnormalType = 65;
//							else if(wStr == L"song_of_water")			pSI->nAbnormalType = 66;
//							else if(wStr == L"song_of_warding")			pSI->nAbnormalType = 67;
//							else if(wStr == L"song_of_wind")			pSI->nAbnormalType = 68;
//							else if(wStr == L"song_of_hunter")			pSI->nAbnormalType = 69;
//							if(wStr == L"song_of_invocation")			pSI->nAbnormalType = 70;			//los bloques estaban demasiado anidados por eso quito el else
//							else if(wStr == L"song_of_vitality")		pSI->nAbnormalType = 71;
//							else if(wStr == L"song_of_flame_guard")		pSI->nAbnormalType = 72;
//							else if(wStr == L"song_of_storm_guard")		pSI->nAbnormalType = 73;
//							else if(wStr == L"song_of_renewal")			pSI->nAbnormalType = 74;
//							else if(wStr == L"song_of_meditation")		pSI->nAbnormalType = 75;
//							else if(wStr == L"song_of_champion")		pSI->nAbnormalType = 76;
//							else if(wStr == L"song_of_vengeance")		pSI->nAbnormalType = 77;
//							else if(wStr == L"dance_of_warrior")		pSI->nAbnormalType = 78;
//							else if(wStr == L"dance_of_inspiration")	pSI->nAbnormalType = 79;
//							else if(wStr == L"dance_of_mystic")			pSI->nAbnormalType = 80;
//							else if(wStr == L"dance_of_fire")			pSI->nAbnormalType = 81;
//							else if(wStr == L"dance_of_fury")			pSI->nAbnormalType = 82;
//							else if(wStr == L"dance_of_concentration")	pSI->nAbnormalType = 83;
//							else if(wStr == L"dance_of_light")			pSI->nAbnormalType = 84;
//							else if(wStr == L"dance_of_vampire")		pSI->nAbnormalType = 85;
//							else if(wStr == L"dance_of_aqua_guard")		pSI->nAbnormalType = 86;
//							else if(wStr == L"dance_of_earth_guard")	pSI->nAbnormalType = 87;
//							else if(wStr == L"dance_of_siren")			pSI->nAbnormalType = 88;
//							else if(wStr == L"dance_of_shadow")			pSI->nAbnormalType = 89;
//							else if(wStr == L"dance_of_protection")		pSI->nAbnormalType = 90;
//							else if(wStr == L"detect_weakness")			pSI->nAbnormalType = 91;
//							else if(wStr == L"thrill_fight")			pSI->nAbnormalType = 92;
//							else if(wStr == L"resist_bleeding")			pSI->nAbnormalType = 93;
//							else if(wStr == L"critical_dmg_up")			pSI->nAbnormalType = 94;
//							else if(wStr == L"shield_prob_up")			pSI->nAbnormalType = 95;
//							else if(wStr == L"hp_regen_down")			pSI->nAbnormalType = 96;
//							else if(wStr == L"reuse_delay_up")			pSI->nAbnormalType = 97;
//							else if(wStr == L"pd_down")					pSI->nAbnormalType = 98;
//							else if(wStr == L"big_head")				pSI->nAbnormalType = 99;
//							if(wStr == L"snipe")						pSI->nAbnormalType = 100;			//los bloques estaban demasiado anidados por eso quito el else
//							else if(wStr == L"cheap_magic")				pSI->nAbnormalType = 101;
//							else if(wStr == L"magic_critical_up")		pSI->nAbnormalType = 102;
//							else if(wStr == L"shield_defence_up")		pSI->nAbnormalType = 103;
//							else if(wStr == L"rage_might")				pSI->nAbnormalType = 104;
//							else if(wStr == L"ultimate_buff")			pSI->nAbnormalType = 105;
//							else if(wStr == L"reduce_drop_penalty")		pSI->nAbnormalType = 106;
//							else if(wStr == L"heal_effect_up")			pSI->nAbnormalType = 107;
//							else if(wStr == L"ssq_town_curse")			pSI->nAbnormalType = 108;
//							else if(wStr == L"ssq_town_blessing")		pSI->nAbnormalType = 109;
//							else if(wStr == L"big_body")				pSI->nAbnormalType = 110;
//							else if(wStr == L"preserve_abnormal")		pSI->nAbnormalType = 111;
//							else if(wStr == L"spa_disease_a")			pSI->nAbnormalType = 112;
//							else if(wStr == L"spa_disease_b")			pSI->nAbnormalType = 113;
//							else if(wStr == L"spa_disease_c")			pSI->nAbnormalType = 114;
//							else if(wStr == L"spa_disease_d")			pSI->nAbnormalType = 115;
//							else if(wStr == L"avoid_down")				pSI->nAbnormalType = 116;
//							else if(wStr == L"multi_buff")				pSI->nAbnormalType = 117;
//							else if(wStr == L"dragon_breath")			pSI->nAbnormalType = 118;
//							else if(wStr == L"ultimate_debuff")			pSI->nAbnormalType = 119;
//							else if(wStr == L"buff_queen_of_cat")		pSI->nAbnormalType = 120;
//							else if(wStr == L"buff_unicorn_seraphim")	pSI->nAbnormalType = 121;
//							else if(wStr == L"debuff_nightshade")		pSI->nAbnormalType = 122;
//							else if(wStr == L"watcher_gaze")			pSI->nAbnormalType = 123;
//							else if(wStr == L"multi_debuff")			pSI->nAbnormalType = 124;
//							else if(wStr == L"reflect_abnormal")		pSI->nAbnormalType = 125;
//							else if(wStr == L"focus_dagger")			pSI->nAbnormalType = 126;
//							else if(wStr == L"max_hp_down")				pSI->nAbnormalType = 127;
//							else if(wStr == L"resist_holy_unholy")		pSI->nAbnormalType = 128;
//							else if(wStr == L"resist_debuff_dispel")	pSI->nAbnormalType = 129;
//							else if(wStr == L"touch_of_life")			pSI->nAbnormalType = 130;
//							else if(wStr == L"touch_of_death")			pSI->nAbnormalType = 131;
//							else if(wStr == L"silence_physical")		pSI->nAbnormalType = 132;
//							else if(wStr == L"silence_all")				pSI->nAbnormalType = 133;
//							else if(wStr == L"valakas_item")			pSI->nAbnormalType = 134;
//							else if(wStr == L"gara")					pSI->nAbnormalType = 135;
//							else if(wStr == L"resist_wind")				pSI->nAbnormalType = 136;
//							else if(wStr == L"resist_earth")			pSI->nAbnormalType = 137;
//							else if(wStr == L"resist_fire")				pSI->nAbnormalType = 138;
//							else if(wStr == L"resist_water")			pSI->nAbnormalType = 139;
//							else if(wStr == L"resist_holy")				pSI->nAbnormalType = 140;
//							else if(wStr == L"resist_unholy")			pSI->nAbnormalType = 141;
//							else if(wStr == L"surr_earth")				pSI->nAbnormalType = 142;
//							else if(wStr == L"surr_wind")				pSI->nAbnormalType = 143;
//							else if(wStr == L"surr_water")				pSI->nAbnormalType = 144;
//							else if(wStr == L"surr_fire")				pSI->nAbnormalType = 145;
//							else if(wStr == L"greater_buff")			pSI->nAbnormalType = 146;
//							else if(wStr == L"psycho_symphony")			pSI->nAbnormalType = 147;
//							else if(wStr == L"demonic_blade_dance")		pSI->nAbnormalType = 148;
//							else if(wStr == L"heroic_valor")			pSI->nAbnormalType = 149;
//							else if(wStr == L"heroic_grandeur")			pSI->nAbnormalType = 150;
//							else if(wStr == L"heroic_miracle")			pSI->nAbnormalType = 151;
//							else if(wStr == L"heroic_berserker")		pSI->nAbnormalType = 152;
//							else if(wStr == L"arcane_disruption")		pSI->nAbnormalType = 153;
//							else if(wStr == L"angelic_icon")			pSI->nAbnormalType = 154;
//							else if(wStr == L"rapid_fire")				pSI->nAbnormalType = 155;
//							else if(wStr == L"dead_eye")				pSI->nAbnormalType = 156;
//							else if(wStr == L"spirit_of_sagittarius")	pSI->nAbnormalType = 157;
//							else if(wStr == L"blessing_of_sagittarius") pSI->nAbnormalType = 158;
//							else if(wStr == L"infernal_form")			pSI->nAbnormalType = 159;
//							else if(wStr == L"betray")					pSI->nAbnormalType = 160;
//							else if(wStr == L"magical_backfire")		pSI->nAbnormalType = 161;
//							else if(wStr == L"clarity")					pSI->nAbnormalType = 162;
//							else if(wStr == L"meditation")				pSI->nAbnormalType = 163;
//							else if(wStr == L"bless_of_fire")			pSI->nAbnormalType = 164;
//							else if(wStr == L"bless_of_water")			pSI->nAbnormalType = 165;
//							if(wStr == L"bless_of_wind")				pSI->nAbnormalType = 166;			//los bloques estaban demasiado anidados por eso quito el else
//							else if(wStr == L"bless_of_earth")			pSI->nAbnormalType = 167;
//							else if(wStr == L"bless_of_darkness")		pSI->nAbnormalType = 168;
//							else if(wStr == L"bless_of_sacredness")		pSI->nAbnormalType = 169;
//							else if(wStr == L"self_resurrection")		pSI->nAbnormalType = 170;
//							else if(wStr == L"surr_holy")				pSI->nAbnormalType = 171;
//							else if(wStr == L"surr_unholy")				pSI->nAbnormalType = 172;
//							else if(wStr == L"spell_force")				pSI->nAbnormalType = 173;
//							else if(wStr == L"battle_force")			pSI->nAbnormalType = 174;
//							else if(wStr == L"invincibility")			pSI->nAbnormalType = 175;
//							else if(wStr == L"battle_symbol")			pSI->nAbnormalType = 176;
//							else if(wStr == L"augmentation")			pSI->nAbnormalType = 177;
//							else if(wStr == L"augmentation_trigger")	pSI->nAbnormalType = 178;
//							else if(wStr == L"clan_gate")				pSI->nAbnormalType = 179;
//							else if(wStr == L"offline_shop")			pSI->nAbnormalType = 180;
//							else if(wStr == L"hide_buff")				pSI->nAbnormalType = 181;
//							else if(wStr == L"hide_debuff")				pSI->nAbnormalType = 182;
//							else if(wStr == L"heart_of_paagrio")		pSI->nAbnormalType = 183;
//							else if(wStr == L"chant_of_life")			pSI->nAbnormalType = 184;
//							else if(wStr == L"shield_of_revenge")		pSI->nAbnormalType = 185;
//							else if(wStr == L"focus_attack")			pSI->nAbnormalType = 186;
//							else if(wStr == L"mirage")					pSI->nAbnormalType = 187;
//							else if(wStr == L"resurrection_special")	pSI->nAbnormalType = 188;
//							else if(wStr == L"team_abnormal")			pSI->nAbnormalType = 189;
//							else if(wStr == L"abnormal_invincibility")	pSI->nAbnormalType = 190;
						}
						if(wLine.find(L"LLLLLLLLLLLattribute"))
						{
							wstring wStr = CParser::GetValueString(wLine, L"attribute=");
//							if(wStr == L"attr_sword")					pSI->attributeType = CSkillInfo::W_SWORD;
//							else if(wStr == L"attr_blunt")				pSI->attributeType = CSkillInfo::W_BLUNT;
//							else if(wStr == L"attr_dagger")				pSI->attributeType = CSkillInfo::W_DAGGER;
//							else if(wStr == L"attr_pole")				pSI->attributeType = CSkillInfo::W_POLE;
//							else if(wStr == L"attr_fist")				pSI->attributeType = CSkillInfo::W_FIST;
//							else if(wStr == L"attr_bow")				pSI->attributeType = CSkillInfo::W_BOW;
//							else if(wStr == L"attr_etc")				pSI->attributeType = CSkillInfo::W_ETC;
//							else if(wStr == L"attr_earth")				pSI->attributeType = CSkillInfo::EARTH;
//							else if(wStr == L"attr_water")				pSI->attributeType = CSkillInfo::WATER;
//							else if(wStr == L"attr_wind")				pSI->attributeType = CSkillInfo::WIND;
//							else if(wStr == L"attr_fire")				pSI->attributeType = CSkillInfo::FIRE;
//							else if(wStr == L"attr_poison")				pSI->attributeType = CSkillInfo::POISON;
//							else if(wStr == L"attr_holy")				pSI->attributeType = CSkillInfo::HOLY;
//							else if(wStr == L"attr_hold")				pSI->attributeType = CSkillInfo::HOLD;
//							else if(wStr == L"attr_bleed")				pSI->attributeType = CSkillInfo::BLEED;
//							else if(wStr == L"attr_sleep")				pSI->attributeType = CSkillInfo::SLEEP;
//							else if(wStr == L"attr_shock")				pSI->attributeType = CSkillInfo::SHOCK;
//							else if(wStr == L"attr_derangement")		pSI->attributeType = CSkillInfo::DERANGEMENT;
//							else if(wStr == L"attr_unholy")				pSI->attributeType = CSkillInfo::UNHOLY;
//							else if(wStr == L"attr_bug_weakness")		pSI->attributeType = CSkillInfo::BUG_WEAKNESS;
//							else if(wStr == L"attr_animal_weakness")	pSI->attributeType = CSkillInfo::ANIMAL_WEAKNESS;
//							else if(wStr == L"attr_plant_weakness")		pSI->attributeType = CSkillInfo::PLANT_WEAKNESS;
//							else if(wStr == L"attr_beast_weakness")		pSI->attributeType = CSkillInfo::BEAST_WEAKNESS;
//							else if(wStr == L"attr_dragon_weakness")	pSI->attributeType = CSkillInfo::DRAGON_WEAKNESS;
//							else if(wStr == L"attr_paralyze")			pSI->attributeType = CSkillInfo::PARALYZE;
//							else if(wStr == L"attr_dual")				pSI->attributeType = CSkillInfo::W_DUAL;
//							else if(wStr == L"attr_dualfist")			pSI->attributeType = CSkillInfo::W_DUALFIST;
//							else if(wStr == L"attr_boss")				pSI->attributeType = CSkillInfo::BOSS;
//							else if(wStr == L"attr_death")				pSI->attributeType = CSkillInfo::DEATH;
//							else if(wStr == L"attr_valakas")			pSI->attributeType = CSkillInfo::VALAKAS;
//							else if(wStr == L"attr_none")				pSI->attributeType = CSkillInfo::NONE;

//g_Log.Add(CLog::Blue, "pSI->attributeType[%d] Parser abnormal_type=[%S]", pSI->attributeType, CParser::GetValueString(wLine, L"abnormal_type").c_str());
						}
						if(wLine.find(L"LLLLLLLLLLLeffect_point"))
						{
//							pSI->nEffectPoint =  _wtoi(CParser::GetBypassValue(wLine, L"effect_point=").c_str());
						}
						if(wLine.find(L"LLLLLLLLLLLdebuff"))
						{
//							pSI->nDebuff =  _wtoi(CParser::GetBypassValue(wLine, L"debuff=").c_str());
						}
						if(wLine.find(L"LLLLLLLLLLLnext_action"))
						{
//							wstring wStr = CParser::GetValueString(wLine, L"next_action");
//							if(wStr == L"none")				pSI->nNextAction = 0;
//							else if(wStr == L"stand")		pSI->nNextAction = 1;
//							else if(wStr == L"sit")			pSI->nNextAction = 2;	//nose hay que testear	//next_action	//stand- 1 attack- 4 none- 0 sit-2 fakeDeath- 2
//							else if(wStr == L"fakeDeath")	pSI->nNextAction = 2;	//nose hay que testear	//next_action	//stand- 1 attack- 4 none- 0 sit-2 fakeDeath- 2
//							else if(wStr == L"attack")		pSI->nNextAction = 4;

//g_Log.Add(CLog::Blue, "pSI->nNextAction[%d] Parser affect_scope=[%S]", pSI->nNextAction, CParser::GetValueString(wLine, L"next_action").c_str());
						}
						if(wLine.find(L"LLLLLLLLLLLtarget_type"))
						{
//							wstring wStr = CParser::GetValueString(wLine, L"target_type");
//							if(wStr == L"self")					pSI->targetType = CSkillInfo::TargetSelf;
//							else if(wStr == L"target")			pSI->targetType = CSkillInfo::TargetTarget;
//							else if(wStr == L"enemy")			pSI->targetType = CSkillInfo::TargetEnemy;
//							else if(wStr == L"enemy_only")		pSI->targetType = CSkillInfo::TargetEnemyOnly;
//							else if(wStr == L"item")			pSI->targetType = CSkillInfo::TargetItem;
//							else if(wStr == L"summon")			pSI->targetType = CSkillInfo::TargetSummon;
//							else if(wStr == L"holything")		pSI->targetType = CSkillInfo::TargetHolything;
//							else if(wStr == L"door_treasure")	pSI->targetType = CSkillInfo::TargetDoorTreasure;
//							else if(wStr == L"pc_body")			pSI->targetType = CSkillInfo::TargetPCBody;
//							else if(wStr == L"npc_body")		pSI->targetType = CSkillInfo::TargetNPCBody;

							//else if(wStr == L"none")		pSI->targetType = xxxxxxxxxxxx;
							//else if(wStr == L"others")		pSI->targetType = xxxxxxxxxxxx;
							//else if(wStr == L"wyvern_target")		pSI->targetType = xxxxxxxxxxxx;

//g_Log.Add(CLog::Blue, "pSI->targetType[%d] Parser target_type=[%S]", pSI->targetType, CParser::GetValueString(wLine, L"target_type").c_str());
						}
						if(wLine.find(L"LLLLLLLLLLLaffect_scope"))
						{

//							wstring wStr = CParser::GetValueString(wLine, L"affect_scope");
//							if(wStr == L"single")					pSI->AffectScope = CSkillInfo::AS_SINGLE;
//							else if(wStr == L"party")				pSI->AffectScope = CSkillInfo::AS_PARTY;
//							else if(wStr == L"range")				pSI->AffectScope = CSkillInfo::AS_RANGE;
//							else if(wStr == L"point_blank")			pSI->AffectScope = CSkillInfo::AS_POINT_BLANK;
//							else if(wStr == L"fan")					pSI->AffectScope = CSkillInfo::AS_FAN;
//							else if(wStr == L"pledge")				pSI->AffectScope = CSkillInfo::AS_PLEDGE;
//							else if(wStr == L"square")				pSI->AffectScope = CSkillInfo::AS_SQUARE;
//							else if(wStr == L"square_pb")			pSI->AffectScope = CSkillInfo::AS_SQUARE_PB;
//							else if(wStr == L"dead_pledge")			pSI->AffectScope = CSkillInfo::AS_DEAD_PLEDGE;
//							else if(wStr == L"wyvern_scope")		pSI->AffectScope = CSkillInfo::AS_WYVERN_SCOPE;
//							else if(wStr == L"balakas_scope")		pSI->AffectScope = CSkillInfo::AS_BALAKAS_SCOPE;
//							else if(wStr == L"none")				pSI->AffectScope = CSkillInfo::AS_NONE;

//g_Log.Add(CLog::Blue, "pSI->AffectScope[%d] Parser affect_scope=[%S]", pSI->AffectScope, CParser::GetValueString(wLine, L"affect_scope").c_str());

						}
						if(wLine.find(L"LLLLLLLLLLLdebuff"))
						{
//							pSI->nAffectRange =  _wtoi(CParser::GetBypassValue(wLine, L"affect_range=").c_str());
						}
						if(wLine.find(L"	effect") && 1 == 2)
						{
							///-----------------------------------------------------------------------------------------------------
							//effect={{p_physical_attack;{all};25;per};{p_physical_attack;{all};25;per}}

							if(skill_lv != 1)
								continue;
											
							wstring wStr = CParser::GetValueString(wLine, L"	effect");





//									for(vector<CSkillEffect*>::iterator Iter = pSI->m_vPumpEffect.begin();Iter!=pSI->m_vPumpEffect.end();Iter++)
//									{
//										if(CSkillEffect *pCond = (*Iter))
//										{
//											file << "skill " << skill_id << " skill_lv " << skill_lv << ":::: ";
//											for(int n=0;n<5;n++)
//											{
//												BYTE write = ((*(LPWORD)((INT32)pCond+n)));
//												file << (UINT)(BYTE)write << " ";
//											}
//											file << "\r\n";
//										}
//									}

							


							pSI->m_vPumpEffect.clear();
							pSI->m_vInstantEffects.clear();

							wStr = Utils::ReplaceStringW(wStr, L"{{", L"{", true);
							wStr = Utils::ReplaceStringW(wStr, L"}}", L"}", true);
							wStr = Utils::ReplaceStringW(wStr, L"};{", L"$", true);
							wStr = Utils::ReplaceStringW(wStr, L"{", L"", true);
							wStr = Utils::ReplaceStringW(wStr, L"}", L"", true);

							if(wStr.find(L"$"))
							{
								std::wstring temp;
								std::wstringstream wss(wStr);

								while(std::getline(wss, temp, L'$'))
								{
									//g_Log.Add(CLog::Error, "%S",temp.c_str());

									int contador = 0;
									std::wstring var1 = L"";
									std::wstring var2 = L"";
									std::wstring var3 = L"";
									std::wstring var4 = L"";
									std::wstring var5 = L"";
									std::wstring var6 = L"";
									std::wstring var7 = L"";
									std::wstring var8 = L"";
									std::wstring efecto;
									std::wstringstream wss2(temp);
									while(std::getline(wss2, efecto, L';'))
									{
										//g_Log.Add(CLog::Error, "%S",efecto.c_str());
										
										if (contador == 0) var1 = efecto;
										if (contador == 1) var2 = efecto;
										if (contador == 2) var3 = efecto;
										if (contador == 3) var4 = efecto;
										if (contador == 4) var5 = efecto;
										if (contador == 5) var6 = efecto;
										if (contador == 6) var7 = efecto;
										if (contador == 7) var8 = efecto;

										contador++;
									}
									//----------------------------------------------------------------
									if (var1 == L"p_physical_attack")		//OK (volver a probar)
									{
										CSkillEffect_p_physical_attack *pEffect = new CSkillEffect_p_physical_attack;
										if(var4 == L"per") var4 = L"0"; else var4 = L"1";

										std::wstring weapon;
										std::wstringstream wss2(var2);
										while(std::getline(wss2, weapon, L';'))
										{
											if(weapon == L"all" || weapon == L"none") pEffect->var1[0]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"sword") pEffect->var1[1]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"blunt") pEffect->var1[2]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"dagger") pEffect->var1[3]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"pole") pEffect->var1[4]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"fist") pEffect->var1[5]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"bow") pEffect->var1[6]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"etc") pEffect->var1[7]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"dual") pEffect->var1[8]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"dualfist") pEffect->var1[9]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"fishingrod") pEffect->var1[10]=1; else pEffect->var1[0]=0;
										}

										pEffect->var2 = _wtof(var3.c_str());
										pEffect->var3 = _wtoi(var4.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_hit")					//OK
									{
										CSkillEffect_p_hit *pEffect = new CSkillEffect_p_hit;
										if(var4 == L"per") var4 = L"0"; else var4 = L"1";

										pEffect->var2 = _wtof(var3.c_str());
										pEffect->var3 = _wtoi(var4.c_str());

										std::wstring weapon;
										std::wstringstream wss2(var2);
										while(std::getline(wss2, weapon, L';'))
										{
											if(weapon == L"all" || weapon == L"none") pEffect->var4[0]=1; else pEffect->var4[0]=0;
											if(weapon == L"all" || weapon == L"sword") pEffect->var4[1]=1; else pEffect->var4[0]=0;
											if(weapon == L"all" || weapon == L"blunt") pEffect->var4[2]=1; else pEffect->var4[0]=0;
											if(weapon == L"all" || weapon == L"dagger") pEffect->var4[3]=1; else pEffect->var4[0]=0;
											if(weapon == L"all" || weapon == L"pole") pEffect->var4[4]=1; else pEffect->var4[0]=0;
											if(weapon == L"all" || weapon == L"fist") pEffect->var4[5]=1; else pEffect->var4[0]=0;
											if(weapon == L"all" || weapon == L"bow") pEffect->var4[6]=1; else pEffect->var4[0]=0;
											if(weapon == L"all" || weapon == L"etc") pEffect->var4[7]=1; else pEffect->var4[0]=0;
											if(weapon == L"all" || weapon == L"dual") pEffect->var4[8]=1; else pEffect->var4[0]=0;
											if(weapon == L"all" || weapon == L"dualfist") pEffect->var4[9]=1; else pEffect->var4[0]=0;
											if(weapon == L"all" || weapon == L"fishingrod") pEffect->var4[10]=1; else pEffect->var4[0]=0;
										}

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_attack_range")					//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_attack_range *pEffect = new CSkillEffect_p_attack_range;
										if(var4 == L"per") var4 = L"0"; else var4 = L"1";

										pEffect->var2 = _wtof(var3.c_str());
										pEffect->var3 = _wtoi(var4.c_str());

										std::wstring weapon;
										std::wstringstream wss2(var2);
										while(std::getline(wss2, weapon, L';'))
										{
											if(weapon == L"all" || weapon == L"none") pEffect->var1[0]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"sword") pEffect->var1[1]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"blunt") pEffect->var1[2]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"dagger") pEffect->var1[3]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"pole") pEffect->var1[4]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"fist") pEffect->var1[5]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"bow") pEffect->var1[6]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"etc") pEffect->var1[7]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"dual") pEffect->var1[8]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"dualfist") pEffect->var1[9]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"fishingrod") pEffect->var1[10]=1; else pEffect->var1[0]=0;
										}

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_attack_speed_by_weapon")					//OK
									{
										CSkillEffect_p_attack_speed_by_weapon *pEffect = new CSkillEffect_p_attack_speed_by_weapon;
										if(var4 == L"per") var4 = L"0"; else var4 = L"1";

										pEffect->var2 = _wtof(var3.c_str());
										pEffect->var3 = _wtoi(var4.c_str());

										std::wstring weapon;
										std::wstringstream wss2(var2);
										while(std::getline(wss2, weapon, L';'))
										{
											if(weapon == L"all" || weapon == L"none") pEffect->var1[0]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"sword") pEffect->var1[1]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"blunt") pEffect->var1[2]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"dagger") pEffect->var1[3]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"pole") pEffect->var1[4]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"fist") pEffect->var1[5]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"bow") pEffect->var1[6]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"etc") pEffect->var1[7]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"dual") pEffect->var1[8]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"dualfist") pEffect->var1[9]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"fishingrod") pEffect->var1[10]=1; else pEffect->var1[0]=0;
										}

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_create_item")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_create_item *pEffect = new CSkillEffect_p_create_item;

										pEffect->var1 = _wtof(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_create_common_item")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_create_common_item *pEffect = new CSkillEffect_p_create_common_item;

										pEffect->var1 = _wtof(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_luck")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_luck *pEffect = new CSkillEffect_p_luck;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_attack_attribute")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_attack_attribute *pEffect = new CSkillEffect_p_attack_attribute;

										if(var2 == L"attr_sword")					pEffect->var1 = CSkillInfo::W_SWORD;
										else if(var2 == L"attr_blunt")				pEffect->var1 = CSkillInfo::W_BLUNT;
										else if(var2 == L"attr_dagger")				pEffect->var1= CSkillInfo::W_DAGGER;
										else if(var2 == L"attr_pole")				pEffect->var1 = CSkillInfo::W_POLE;
										else if(var2 == L"attr_fist")				pEffect->var1 = CSkillInfo::W_FIST;
										else if(var2 == L"attr_bow")				pEffect->var1 = CSkillInfo::W_BOW;
										else if(var2 == L"attr_etc")				pEffect->var1 = CSkillInfo::W_ETC;
										else if(var2 == L"attr_earth")				pEffect->var1 = CSkillInfo::EARTH;
										else if(var2 == L"attr_water")				pEffect->var1 = CSkillInfo::WATER;
										else if(var2 == L"attr_wind")				pEffect->var1 = CSkillInfo::WIND;
										else if(var2 == L"attr_fire")				pEffect->var1 = CSkillInfo::FIRE;
										else if(var2 == L"attr_poison")				pEffect->var1 = CSkillInfo::POISON;
										else if(var2 == L"attr_holy")				pEffect->var1 = CSkillInfo::HOLY;
										else if(var2 == L"attr_hold")				pEffect->var1 = CSkillInfo::HOLD;
										else if(var2 == L"attr_bleed")				pEffect->var1 = CSkillInfo::BLEED;
										else if(var2 == L"attr_sleep")				pEffect->var1 = CSkillInfo::SLEEP;
										else if(var2 == L"attr_shock")				pEffect->var1 = CSkillInfo::SHOCK;
										else if(var2 == L"attr_derangement")		pEffect->var1 = CSkillInfo::DERANGEMENT;
										else if(var2 == L"attr_unholy")				pEffect->var1 = CSkillInfo::UNHOLY;
										else if(var2 == L"attr_bug_weakness")		pEffect->var1 = CSkillInfo::BUG_WEAKNESS;
										else if(var2 == L"attr_animal_weakness")	pEffect->var1 = CSkillInfo::ANIMAL_WEAKNESS;
										else if(var2 == L"attr_plant_weakness")		pEffect->var1 = CSkillInfo::PLANT_WEAKNESS;
										else if(var2 == L"attr_beast_weakness")		pEffect->var1 = CSkillInfo::BEAST_WEAKNESS;
										else if(var2 == L"attr_dragon_weakness")	pEffect->var1 = CSkillInfo::DRAGON_WEAKNESS;
										else if(var2 == L"attr_paralyze")			pEffect->var1 = CSkillInfo::PARALYZE;
										else if(var2 == L"attr_dual")				pEffect->var1 = CSkillInfo::W_DUAL;
										else if(var2 == L"attr_dualfist")			pEffect->var1 = CSkillInfo::W_DUALFIST;
										else if(var2 == L"attr_boss")				pEffect->var1 = CSkillInfo::BOSS;
										else if(var2 == L"attr_death")				pEffect->var1 = CSkillInfo::DEATH;
										else if(var2 == L"attr_valakas")			pEffect->var1 = CSkillInfo::VALAKAS;
										else if(var2 == L"attr_none")				pEffect->var1 = CSkillInfo::NONE;
										else pEffect->var1 = CSkillInfo::NONE;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_defence_attribute")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_defence_attribute *pEffect = new CSkillEffect_p_defence_attribute;

										if(var2 == L"attr_sword")					pEffect->var1 = CSkillInfo::W_SWORD;
										else if(var2 == L"attr_blunt")				pEffect->var1 = CSkillInfo::W_BLUNT;
										else if(var2 == L"attr_dagger")				pEffect->var1= CSkillInfo::W_DAGGER;
										else if(var2 == L"attr_pole")				pEffect->var1 = CSkillInfo::W_POLE;
										else if(var2 == L"attr_fist")				pEffect->var1 = CSkillInfo::W_FIST;
										else if(var2 == L"attr_bow")				pEffect->var1 = CSkillInfo::W_BOW;
										else if(var2 == L"attr_etc")				pEffect->var1 = CSkillInfo::W_ETC;
										else if(var2 == L"attr_earth")				pEffect->var1 = CSkillInfo::EARTH;
										else if(var2 == L"attr_water")				pEffect->var1 = CSkillInfo::WATER;
										else if(var2 == L"attr_wind")				pEffect->var1 = CSkillInfo::WIND;
										else if(var2 == L"attr_fire")				pEffect->var1 = CSkillInfo::FIRE;
										else if(var2 == L"attr_poison")				pEffect->var1 = CSkillInfo::POISON;
										else if(var2 == L"attr_holy")				pEffect->var1 = CSkillInfo::HOLY;
										else if(var2 == L"attr_hold")				pEffect->var1 = CSkillInfo::HOLD;
										else if(var2 == L"attr_bleed")				pEffect->var1 = CSkillInfo::BLEED;
										else if(var2 == L"attr_sleep")				pEffect->var1 = CSkillInfo::SLEEP;
										else if(var2 == L"attr_shock")				pEffect->var1 = CSkillInfo::SHOCK;
										else if(var2 == L"attr_derangement")		pEffect->var1 = CSkillInfo::DERANGEMENT;
										else if(var2 == L"attr_unholy")				pEffect->var1 = CSkillInfo::UNHOLY;
										else if(var2 == L"attr_bug_weakness")		pEffect->var1 = CSkillInfo::BUG_WEAKNESS;
										else if(var2 == L"attr_animal_weakness")	pEffect->var1 = CSkillInfo::ANIMAL_WEAKNESS;
										else if(var2 == L"attr_plant_weakness")		pEffect->var1 = CSkillInfo::PLANT_WEAKNESS;
										else if(var2 == L"attr_beast_weakness")		pEffect->var1 = CSkillInfo::BEAST_WEAKNESS;
										else if(var2 == L"attr_dragon_weakness")	pEffect->var1 = CSkillInfo::DRAGON_WEAKNESS;
										else if(var2 == L"attr_paralyze")			pEffect->var1 = CSkillInfo::PARALYZE;
										else if(var2 == L"attr_dual")				pEffect->var1 = CSkillInfo::W_DUAL;
										else if(var2 == L"attr_dualfist")			pEffect->var1 = CSkillInfo::W_DUALFIST;
										else if(var2 == L"attr_boss")				pEffect->var1 = CSkillInfo::BOSS;
										else if(var2 == L"attr_death")				pEffect->var1 = CSkillInfo::DEATH;
										else if(var2 == L"attr_valakas")			pEffect->var1 = CSkillInfo::VALAKAS;
										else if(var2 == L"attr_none")				pEffect->var1 = CSkillInfo::NONE;
										else pEffect->var1 = CSkillInfo::NONE;

										pEffect->var2 = _wtof(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_block_move")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_block_move *pEffect = new CSkillEffect_p_block_move;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_block_act")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_block_act *pEffect = new CSkillEffect_p_block_act;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_block_controll")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_block_controll *pEffect = new CSkillEffect_p_block_controll;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_block_spell")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_block_spell *pEffect = new CSkillEffect_p_block_spell;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_fear")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_fear *pEffect = new CSkillEffect_p_fear;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_max_hp")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_max_hp *pEffect = new CSkillEffect_p_max_hp;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_max_mp")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_max_mp *pEffect = new CSkillEffect_p_max_mp;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_max_cp")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_max_cp *pEffect = new CSkillEffect_p_max_cp;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_critical_rate")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_critical_rate *pEffect = new CSkillEffect_p_critical_rate;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_critical_damage")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_critical_damage *pEffect = new CSkillEffect_p_critical_damage;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_reuse_delay")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_reuse_delay *pEffect = new CSkillEffect_p_reuse_delay;
										if(var4 == L"per") var4 = L"0"; else var4 = L"1";

										pEffect->var1 = _wtoi(var2.c_str());
										pEffect->var2 = _wtof(var3.c_str());
										pEffect->var3 = _wtoi(var4.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_reduce_cancel")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_reduce_cancel *pEffect = new CSkillEffect_p_reduce_cancel;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_shield_defence_rate")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_shield_defence_rate *pEffect = new CSkillEffect_p_shield_defence_rate;
										if(var4 == L"per") var4 = L"0"; else var4 = L"1";

										pEffect->var1 = _wtof(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_safe_fall_height")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_safe_fall_height *pEffect = new CSkillEffect_p_safe_fall_height;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_breath")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_breath *pEffect = new CSkillEffect_p_breath;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_damage_shield")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_damage_shield *pEffect = new CSkillEffect_p_damage_shield;

										pEffect->var1 = _wtof(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_passive")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_passive *pEffect = new CSkillEffect_p_passive;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_avoid_agro")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_avoid_agro *pEffect = new CSkillEffect_p_avoid_agro;

										pEffect->var1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_weight_limit")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_weight_limit *pEffect = new CSkillEffect_p_weight_limit;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_trade")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_trade *pEffect = new CSkillEffect_p_trade;

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());
										pEffect->var3 = _wtoi(var4.c_str());
										pEffect->var4 = _wtoi(var5.c_str());
										pEffect->var5 = _wtoi(var6.c_str());
										pEffect->var6 = _wtoi(var7.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_set_collected")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_set_collected *pEffect = new CSkillEffect_p_set_collected;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_cubic_mastery")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_cubic_mastery *pEffect = new CSkillEffect_p_cubic_mastery;

										pEffect->var1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_weight_penalty")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_weight_penalty *pEffect = new CSkillEffect_p_weight_penalty;

										pEffect->var1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_mana_charge")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_mana_charge *pEffect = new CSkillEffect_p_mana_charge;

										pEffect->var1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_transfer_damage_summon")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_transfer_damage_summon *pEffect = new CSkillEffect_p_transfer_damage_summon;

										pEffect->var1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_heal_effect")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_heal_effect *pEffect = new CSkillEffect_p_heal_effect;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_area_damage")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_area_damage *pEffect = new CSkillEffect_p_area_damage;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_hit_at_night")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_hit_at_night *pEffect = new CSkillEffect_p_hit_at_night;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_2h_sword_bonus")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_2h_sword_bonus *pEffect = new CSkillEffect_p_2h_sword_bonus;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";
										if(var5 == L"per") var5 = L"0"; else var5 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());
										pEffect->var3 = _wtof(var4.c_str());
										pEffect->var4 = _wtoi(var5.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_2h_blunt_bonus")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_2h_blunt_bonus *pEffect = new CSkillEffect_p_2h_blunt_bonus;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";
										if(var5 == L"per") var5 = L"0"; else var5 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());
										pEffect->var3 = _wtof(var4.c_str());
										pEffect->var4 = _wtoi(var5.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_vampiric_attack")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_vampiric_attack *pEffect = new CSkillEffect_p_vampiric_attack;

										pEffect->var1 = _wtof(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_critical_rate_by_hp1")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_critical_rate_by_hp1 *pEffect = new CSkillEffect_p_critical_rate_by_hp1;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_critical_rate_by_hp2")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_critical_rate_by_hp2 *pEffect = new CSkillEffect_p_critical_rate_by_hp2;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_physical_attack_by_hp1")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_physical_attack_by_hp1 *pEffect = new CSkillEffect_p_physical_attack_by_hp1;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_physical_attack_by_hp2")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_physical_attack_by_hp2 *pEffect = new CSkillEffect_p_physical_attack_by_hp2;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_physical_defence_by_hp1")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_physical_defence_by_hp1 *pEffect = new CSkillEffect_p_physical_defence_by_hp1;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_physical_defence_by_hp2")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_physical_defence_by_hp2 *pEffect = new CSkillEffect_p_physical_defence_by_hp2;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_avoid_rate_by_hp1")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_avoid_rate_by_hp1 *pEffect = new CSkillEffect_p_avoid_rate_by_hp1;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_avoid_rate_by_hp2")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_avoid_rate_by_hp2 *pEffect = new CSkillEffect_p_avoid_rate_by_hp2;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_attack_speed_by_hp1")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_attack_speed_by_hp1 *pEffect = new CSkillEffect_p_attack_speed_by_hp1;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_attack_speed_by_hp2")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_attack_speed_by_hp2 *pEffect = new CSkillEffect_p_attack_speed_by_hp2;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_fatal_blow_rate")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_fatal_blow_rate *pEffect = new CSkillEffect_p_fatal_blow_rate;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_critical_rate_position_bonus")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_critical_rate_position_bonus	*pEffect = new CSkillEffect_p_critical_rate_position_bonus;
										if(var4 == L"per") var4 = L"0"; else var4 = L"1";

										if(var2 == L"front") var2 = L"0";
										if(var2 == L"side") var2 = L"1";
										if(var2 == L"back") var2 = L"2";
										if(var2 == L"left") var2 = L"3";
										if(var2 == L"right") var2 = L"4";

										pEffect->var1 = _wtoi(var2.c_str());
										pEffect->var2 = _wtof(var3.c_str());
										pEffect->var3 = _wtoi(var4.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_showtime")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_showtime *pEffect = new CSkillEffect_p_showtime;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_sound")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_sound *pEffect = new CSkillEffect_p_sound;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_see_my_heart")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_see_my_heart *pEffect = new CSkillEffect_p_see_my_heart;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_reduce_drop_penalty")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_reduce_drop_penalty *pEffect = new CSkillEffect_p_reduce_drop_penalty;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_physical_shield_defence_angle_all")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_physical_shield_defence_angle_all *pEffect = new CSkillEffect_p_physical_shield_defence_angle_all;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_magic_mp_cost")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_magic_mp_cost  *pEffect = new CSkillEffect_p_magic_mp_cost;
										if(var4 == L"per") var4 = L"0"; else var4 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());
										pEffect->var3 = _wtoi(var4.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_magic_critical_rate")		//NO LO PROBE PERO PARECE PERFECTO NO LLEVA EL {all} no distinge armas ya por codigo....
									{
										CSkillEffect_p_magic_critical_rate  *pEffect = new CSkillEffect_p_magic_critical_rate;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_pvp_physical_attack_dmg_bonus")		//NO LO PROBE PERO PARECE PERFECTO NO LLEVA EL {all} no distinge armas ya por codigo....
									{
										CSkillEffect_p_pvp_physical_attack_dmg_bonus  *pEffect = new CSkillEffect_p_pvp_physical_attack_dmg_bonus;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtoi(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_pvp_physical_skill_dmg_bonus")		//NO LO PROBE PERO PARECE PERFECTO NO LLEVA EL {all} no distinge armas ya por codigo....
									{
										CSkillEffect_p_pvp_physical_skill_dmg_bonus  *pEffect = new CSkillEffect_p_pvp_physical_skill_dmg_bonus;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtoi(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_pvp_magical_skill_dmg_bonus")		//NO LO PROBE PERO PARECE PERFECTO NO LLEVA EL {all} no distinge armas ya por codigo....
									{
										CSkillEffect_p_pvp_magical_skill_dmg_bonus  *pEffect = new CSkillEffect_p_pvp_magical_skill_dmg_bonus;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtoi(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_physical_shield_defence")		//NO LO PROBE PERO PARECE PERFECTO NO LLEVA EL {all} no distinge armas ya por codigo....
									{
										CSkillEffect_p_physical_shield_defence  *pEffect = new CSkillEffect_p_physical_shield_defence;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtoi(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_physical_polarm_target_single")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_physical_polarm_target_single *pEffect = new CSkillEffect_p_physical_polarm_target_single;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_fishing_mastery")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_fishing_mastery *pEffect = new CSkillEffect_p_fishing_mastery;

										pEffect->var1 = _wtof(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_abnormal_rate_limit")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_abnormal_rate_limit *pEffect = new CSkillEffect_p_abnormal_rate_limit;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_abnormal_remove_by_hit")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_abnormal_remove_by_hit *pEffect = new CSkillEffect_p_abnormal_remove_by_hit;

										pEffect->var1 = _wtoi(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_abnormal_remove_by_dmg")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_abnormal_remove_by_dmg *pEffect = new CSkillEffect_p_abnormal_remove_by_dmg;

										pEffect->var1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_block_skill_physical")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_block_skill_physical *pEffect = new CSkillEffect_p_block_skill_physical;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_block_skill_special")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_block_skill_special *pEffect = new CSkillEffect_p_block_skill_special;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_block_buff")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_block_buff *pEffect = new CSkillEffect_p_block_buff;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_block_debuff")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_block_debuff *pEffect = new CSkillEffect_p_block_debuff;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_reflect_skill")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_reflect_skill *pEffect = new CSkillEffect_p_reflect_skill;

										pEffect->var1 = _wtoi(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_skill_critical")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_skill_critical *pEffect = new CSkillEffect_p_skill_critical;
	
										if(var2 == L"str") var2 = L"1";
										if(var2 == L"dex") var2 = L"2";
										if(var2 == L"con") var2 = L"3";
										if(var2 == L"int") var2 = L"4";
										if(var2 == L"men") var2 = L"5";
										if(var2 == L"wit") var2 = L"6";

										pEffect->var1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_skill_critical_probability")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_skill_critical_probability *pEffect = new CSkillEffect_p_skill_critical_probability;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtoi(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_critical_damage_position")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_critical_damage_position	*pEffect = new CSkillEffect_p_critical_damage_position;
										if(var4 == L"per") var4 = L"0"; else var4 = L"1";

										if(var2 == L"front") var2 = L"0";
										if(var2 == L"side") var2 = L"1";
										if(var2 == L"back") var2 = L"2";
										if(var2 == L"left") var2 = L"3";
										if(var2 == L"right") var2 = L"4";

										pEffect->var1 = _wtoi(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());
										pEffect->var3 = _wtoi(var4.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_preserve_abnormal")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_preserve_abnormal *pEffect = new CSkillEffect_p_preserve_abnormal;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_enlarge_storage")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_enlarge_storage *pEffect = new CSkillEffect_p_enlarge_storage;

										if(var2 == L"inventory_normal") var2 = L"0";
										if(var2 == L"storage_private") var2 = L"1";
										if(var2 == L"storage_clan") var2 = L"2";		//no se bien el nombre le puse storageclan pero figura como trade en ccreature y clan en TotalCheaker2015
										if(var2 == L"trade_sell") var2 = L"3";
										if(var2 == L"trade_buy") var2 = L"4";
										if(var2 == L"recipe_dwarven") var2 = L"5";
										if(var2 == L"recipe_common") var2 = L"6";

										pEffect->var1 = _wtoi(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_hit_number")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_hit_number *pEffect = new CSkillEffect_p_hit_number;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtoi(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_cub_physical_attack")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_cub_physical_attack *pEffect = new CSkillEffect_p_cub_physical_attack;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_cub_physical_defence")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_cub_physical_defence *pEffect = new CSkillEffect_p_cub_physical_defence;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_cub_attack_speed")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_cub_attack_speed *pEffect = new CSkillEffect_p_cub_attack_speed;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_cub_block_act")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_cub_block_act *pEffect = new CSkillEffect_p_cub_block_act;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_hp_regen")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_hp_regen *pEffect = new CSkillEffect_p_hp_regen;
										if(var4 == L"per") var4 = L"0"; else var4 = L"1";

										pEffect->var1 = _wtof(var3.c_str());
										pEffect->var2 = _wtoi(var4.c_str());

										std::wstring weapon;
										std::wstringstream wss2(var2);
										while(std::getline(wss2, weapon, L';'))
										{
											if(weapon == L"all" || weapon == L"armor_none") pEffect->var3[0]=1; else pEffect->var3[0]=0;
											if(weapon == L"all" || weapon == L"armor_light") pEffect->var3[1]=1; else pEffect->var3[1]=0;
											if(weapon == L"all" || weapon == L"armor_heavy") pEffect->var3[2]=1; else pEffect->var3[2]=0;
											if(weapon == L"all" || weapon == L"armor_magic") pEffect->var3[3]=1; else pEffect->var3[3]=0;
										}

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_mp_regen")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_mp_regen *pEffect = new CSkillEffect_p_mp_regen;
										if(var4 == L"per") var4 = L"0"; else var4 = L"1";

										pEffect->var1 = _wtof(var3.c_str());
										pEffect->var2 = _wtoi(var4.c_str());

										std::wstring weapon;
										std::wstringstream wss2(var2);
										while(std::getline(wss2, weapon, L';'))
										{
											if(weapon == L"all" || weapon == L"armor_none") pEffect->var3[0]=1; else pEffect->var3[0]=0;
											if(weapon == L"all" || weapon == L"armor_light") pEffect->var3[1]=1; else pEffect->var3[1]=0;
											if(weapon == L"all" || weapon == L"armor_heavy") pEffect->var3[2]=1; else pEffect->var3[2]=0;
											if(weapon == L"all" || weapon == L"armor_magic") pEffect->var3[3]=1; else pEffect->var3[3]=0;
										}

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_speed")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_speed *pEffect = new CSkillEffect_p_speed;
										if(var4 == L"per") var4 = L"0"; else var4 = L"1";

										pEffect->var1 = _wtof(var3.c_str());
										pEffect->var2 = _wtoi(var4.c_str());

										std::wstring weapon;
										std::wstringstream wss2(var2);
										while(std::getline(wss2, weapon, L';'))
										{
											if(weapon == L"all" || weapon == L"armor_none") pEffect->var3[0]=1; else pEffect->var3[0]=0;
											if(weapon == L"all" || weapon == L"armor_light") pEffect->var3[1]=1; else pEffect->var3[1]=0;
											if(weapon == L"all" || weapon == L"armor_heavy") pEffect->var3[2]=1; else pEffect->var3[2]=0;
											if(weapon == L"all" || weapon == L"armor_magic") pEffect->var3[3]=1; else pEffect->var3[3]=0;
										}

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_attack_speed")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_attack_speed *pEffect = new CSkillEffect_p_attack_speed;
										if(var4 == L"per") var4 = L"0"; else var4 = L"1";

										pEffect->var1 = _wtof(var3.c_str());
										pEffect->var2 = _wtoi(var4.c_str());

										std::wstring weapon;
										std::wstringstream wss2(var2);
										while(std::getline(wss2, weapon, L';'))
										{
											if(weapon == L"all" || weapon == L"armor_none") pEffect->var3[0]=1; else pEffect->var3[0]=0;
											if(weapon == L"all" || weapon == L"armor_light") pEffect->var3[1]=1; else pEffect->var3[1]=0;
											if(weapon == L"all" || weapon == L"armor_heavy") pEffect->var3[2]=1; else pEffect->var3[2]=0;
											if(weapon == L"all" || weapon == L"armor_magic") pEffect->var3[3]=1; else pEffect->var3[3]=0;
										}

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_magic_speed")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_magic_speed *pEffect = new CSkillEffect_p_magic_speed;
										if(var4 == L"per") var4 = L"0"; else var4 = L"1";

										pEffect->var1 = _wtof(var3.c_str());
										pEffect->var2 = _wtoi(var4.c_str());

										std::wstring weapon;
										std::wstringstream wss2(var2);
										while(std::getline(wss2, weapon, L';'))
										{
											if(weapon == L"all" || weapon == L"armor_none") pEffect->var3[0]=1; else pEffect->var3[0]=0;
											if(weapon == L"all" || weapon == L"armor_light") pEffect->var3[1]=1; else pEffect->var3[1]=0;
											if(weapon == L"all" || weapon == L"armor_heavy") pEffect->var3[2]=1; else pEffect->var3[2]=0;
											if(weapon == L"all" || weapon == L"armor_magic") pEffect->var3[3]=1; else pEffect->var3[3]=0;
										}

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_avoid")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_avoid *pEffect = new CSkillEffect_p_avoid;
										if(var4 == L"per") var4 = L"0"; else var4 = L"1";

										pEffect->var1 = _wtof(var3.c_str());
										pEffect->var2 = _wtoi(var4.c_str());

										std::wstring weapon;
										std::wstringstream wss2(var2);
										while(std::getline(wss2, weapon, L';'))
										{
											if(weapon == L"all" || weapon == L"armor_none") pEffect->var3[0]=1; else pEffect->var3[0]=0;
											if(weapon == L"all" || weapon == L"armor_light") pEffect->var3[1]=1; else pEffect->var3[1]=0;
											if(weapon == L"all" || weapon == L"armor_heavy") pEffect->var3[2]=1; else pEffect->var3[2]=0;
											if(weapon == L"all" || weapon == L"armor_magic") pEffect->var3[3]=1; else pEffect->var3[3]=0;
										}

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_magical_defence")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_magical_defence *pEffect = new CSkillEffect_p_magical_defence;
										if(var4 == L"per") var4 = L"0"; else var4 = L"1";

										pEffect->var1 = _wtof(var3.c_str());
										pEffect->var2 = _wtoi(var4.c_str());

										std::wstring weapon;
										std::wstringstream wss2(var2);
										while(std::getline(wss2, weapon, L';'))
										{
											if(weapon == L"all" || weapon == L"armor_none") pEffect->var3[0]=1; else pEffect->var3[0]=0;
											if(weapon == L"all" || weapon == L"armor_light") pEffect->var3[1]=1; else pEffect->var3[1]=0;
											if(weapon == L"all" || weapon == L"armor_heavy") pEffect->var3[2]=1; else pEffect->var3[2]=0;
											if(weapon == L"all" || weapon == L"armor_magic") pEffect->var3[3]=1; else pEffect->var3[3]=0;
										}

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_physical_armor_hit")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_physical_armor_hit *pEffect = new CSkillEffect_p_physical_armor_hit;
										if(var4 == L"per") var4 = L"0"; else var4 = L"1";

										pEffect->var1 = _wtof(var3.c_str());
										pEffect->var2 = _wtoi(var4.c_str());

										std::wstring weapon;
										std::wstringstream wss2(var2);
										while(std::getline(wss2, weapon, L';'))
										{
											if(weapon == L"all" || weapon == L"armor_none") pEffect->var3[0]=1; else pEffect->var3[0]=0;
											if(weapon == L"all" || weapon == L"armor_light") pEffect->var3[1]=1; else pEffect->var3[1]=0;
											if(weapon == L"all" || weapon == L"armor_heavy") pEffect->var3[2]=1; else pEffect->var3[2]=0;
											if(weapon == L"all" || weapon == L"armor_magic") pEffect->var3[3]=1; else pEffect->var3[3]=0;
										}

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_physical_defence")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_physical_defence *pEffect = new CSkillEffect_p_physical_defence;
										if(var4 == L"per") var4 = L"0"; else var4 = L"1";

										pEffect->var2 = _wtof(var3.c_str());
										pEffect->var3 = _wtoi(var4.c_str());

										std::wstring weapon;
										std::wstringstream wss2(var2);
										while(std::getline(wss2, weapon, L';'))
										{
											if(weapon == L"all" || weapon == L"armor_none") pEffect->var1[0]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"armor_light") pEffect->var1[1]=1; else pEffect->var1[1]=0;
											if(weapon == L"all" || weapon == L"armor_heavy") pEffect->var1[2]=1; else pEffect->var1[2]=0;
											if(weapon == L"all" || weapon == L"armor_magic") pEffect->var1[3]=1; else pEffect->var1[3]=0;
										}

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_magical_attack")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_magical_attack *pEffect = new CSkillEffect_p_magical_attack;
										if(var4 == L"per") var4 = L"0"; else var4 = L"1";

										pEffect->var2 = _wtof(var3.c_str());
										pEffect->var3 = _wtoi(var4.c_str());

										std::wstring weapon;
										std::wstringstream wss2(var2);
										while(std::getline(wss2, weapon, L';'))
										{
											if(weapon == L"all" || weapon == L"armor_none") pEffect->var1[0]=1; else pEffect->var1[0]=0;
											if(weapon == L"all" || weapon == L"armor_light") pEffect->var1[1]=1; else pEffect->var1[1]=0;
											if(weapon == L"all" || weapon == L"armor_heavy") pEffect->var1[2]=1; else pEffect->var1[2]=0;
											if(weapon == L"all" || weapon == L"armor_magic") pEffect->var1[3]=1; else pEffect->var1[3]=0;
										}

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_remove_equip_penalty")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_remove_equip_penalty *pEffect = new CSkillEffect_p_remove_equip_penalty;

										if(var2 == L"d") var2 = L"1";
										if(var2 == L"c") var2 = L"2";		//no se bien el nombre le puse storageclan pero figura como trade en ccreature y clan en TotalCheaker2015
										if(var2 == L"b") var2 = L"3";
										if(var2 == L"a") var2 = L"4";
										if(var2 == L"s") var2 = L"5";

										pEffect->var1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_crystallize")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_crystallize *pEffect = new CSkillEffect_p_crystallize;

										if(var2 == L"d") var2 = L"1";
										if(var2 == L"c") var2 = L"2";
										if(var2 == L"b") var2 = L"3";
										if(var2 == L"a") var2 = L"4";
										if(var2 == L"s") var2 = L"5";

										pEffect->var1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}

									if (var1 == L"p_hp_regen_by_move_mode")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_hp_regen_by_move_mode *pEffect = new CSkillEffect_p_hp_regen_by_move_mode;
										if(var4 == L"per") var4 = L"0"; else var4 = L"1";

										if(var2 == L"sit") var2 = L"0";
										if(var2 == L"stand") var2 = L"1";
										if(var2 == L"walk") var2 = L"2";
										if(var2 == L"run") var2 = L"3";

										pEffect->var1 = _wtof(var3.c_str());
										pEffect->var2 = _wtoi(var4.c_str());
										pEffect->var3 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_mp_regen_by_move_mode")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_mp_regen_by_move_mode *pEffect = new CSkillEffect_p_mp_regen_by_move_mode;
										if(var4 == L"per") var4 = L"0"; else var4 = L"1";

										if(var2 == L"sit") var2 = L"0";
										if(var2 == L"stand") var2 = L"1";
										if(var2 == L"walk") var2 = L"2";
										if(var2 == L"run") var2 = L"3";

										pEffect->var1 = _wtof(var3.c_str());
										pEffect->var2 = _wtoi(var4.c_str());
										pEffect->var3 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_avoid_by_move_mode")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_avoid_by_move_mode *pEffect = new CSkillEffect_p_avoid_by_move_mode;
										if(var4 == L"per") var4 = L"0"; else var4 = L"1";

										if(var2 == L"sit") var2 = L"0";
										if(var2 == L"stand") var2 = L"1";
										if(var2 == L"walk") var2 = L"2";
										if(var2 == L"run") var2 = L"3";

										pEffect->var1 = _wtof(var3.c_str());
										pEffect->var2 = _wtoi(var4.c_str());
										pEffect->var3 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}

									if (var1 == L"p_resist_dispel_by_category")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_resist_dispel_by_category *pEffect = new CSkillEffect_p_resist_dispel_by_category;
										if(var4 == L"per") var4 = L"0"; else var4 = L"1";


										if(var2 == L"slot_buff") var2 = L"0";
										else if(var2 == L"slot_debuff") var2 = L"1";
										else var2 = L"2";

										pEffect->var1 = _wtoi(var2.c_str());

										pEffect->var2 = _wtoi(var3.c_str());
										pEffect->var3 = _wtoi(var4.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"p_resist_abnormal_by_category")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_p_resist_abnormal_by_category *pEffect = new CSkillEffect_p_resist_abnormal_by_category;
										if(var4 == L"per") var4 = L"0"; else var4 = L"1";


										if(var2 == L"slot_buff") var2 = L"0";
										else if(var2 == L"slot_debuff") var2 = L"1";
										else var2 = L"2";

										pEffect->var1 = _wtoi(var2.c_str());

										pEffect->var2 = _wtoi(var3.c_str());
										pEffect->var3 = _wtoi(var4.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vPumpEffect, &pEffect_Final);	//PUSH MAP
									}



									//-----------------------------pSI->m_vInstantEffects---------------------------------


									if (var1 == L"i_p_attack")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_p_attack *pEffect = new CSkillEffect_i_p_attack;

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_p_attack_over_hit")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_p_attack_over_hit *pEffect = new CSkillEffect_i_p_attack_over_hit;

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_heal")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_heal *pEffect = new CSkillEffect_i_heal;

										pEffect->var1 = _wtof(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_hp_drain")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_hp_drain *pEffect = new CSkillEffect_i_hp_drain;

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtof(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_m_attack")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_m_attack *pEffect = new CSkillEffect_i_m_attack;

										pEffect->var1 = _wtof(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_enchant_armor")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_Enchant_Armor *pEffect = new CSkillEffect_i_Enchant_Armor;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_enchant_weapon")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_Enchant_Weapon *pEffect = new CSkillEffect_i_Enchant_Weapon;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_hp_per_max")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_hp_per_max *pEffect = new CSkillEffect_i_hp_per_max;

										pEffect->var1 = _wtof(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_mp_per_max")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_mp_per_max *pEffect = new CSkillEffect_i_mp_per_max;

										pEffect->var1 = _wtof(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_mp_by_level")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_mp_by_level *pEffect = new CSkillEffect_i_mp_by_level;

										pEffect->var1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_add_hate")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_add_hate *pEffect = new CSkillEffect_i_add_hate;

										pEffect->var1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_holything_possess")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_holything_possess *pEffect = new CSkillEffect_i_holything_possess;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_install_camp")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_install_camp *pEffect = new CSkillEffect_i_install_camp;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_unlock")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_unlock *pEffect = new CSkillEffect_i_unlock;

										pEffect->var1 = _wtoi(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());
										pEffect->var3 = _wtoi(var4.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_focus_energy")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_focus_energy *pEffect = new CSkillEffect_i_focus_energy;

										pEffect->var1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_soul_shot")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_soul_shot *pEffect = new CSkillEffect_i_soul_shot;

										pEffect->var1 = _wtof(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_spirit_shot")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_spirit_shot *pEffect = new CSkillEffect_i_spirit_shot;

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtof(var3.c_str());
										pEffect->var3 = _wtof(var4.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_summon_soul_shot")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_summon_soul_shot *pEffect = new CSkillEffect_i_summon_soul_shot;

										pEffect->var1 = _wtof(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_summon_spirit_shot")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_summon_spirit_shot *pEffect = new CSkillEffect_i_summon_spirit_shot;

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtof(var3.c_str());
										pEffect->var3 = _wtof(var4.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_consume_body")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_consume_body *pEffect = new CSkillEffect_i_consume_body;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_hp_by_level_self")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_hp_by_level_self *pEffect = new CSkillEffect_i_hp_by_level_self;

										pEffect->var1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_mp_by_level_self")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_mp_by_level_self *pEffect = new CSkillEffect_i_mp_by_level_self;

										pEffect->var1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_sweeper")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_sweeper *pEffect = new CSkillEffect_i_sweeper;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_harvesting")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_harvesting *pEffect = new CSkillEffect_i_harvesting;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_hp_self")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_hp_self *pEffect = new CSkillEffect_i_hp_self;

										pEffect->var1 = _wtof(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_death_link")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_death_link *pEffect = new CSkillEffect_i_death_link;

										pEffect->var1 = _wtof(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_dispel_all")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_dispel_all *pEffect = new CSkillEffect_i_dispel_all;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_summon_dd_cubic")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_summon_dd_cubic *pEffect = new CSkillEffect_i_summon_dd_cubic;
										
										pEffect->var1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_summon_drain_cubic")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_summon_drain_cubic *pEffect = new CSkillEffect_i_summon_drain_cubic;
										
										pEffect->var1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_summon_heal_cubic")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_summon_heal_cubic *pEffect = new CSkillEffect_i_summon_heal_cubic;
										
										pEffect->var1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_summon_poison_cubic")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_summon_poison_cubic *pEffect = new CSkillEffect_i_summon_poison_cubic;
										
										pEffect->var1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_summon_debuf_cubic")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_summon_debuf_cubic *pEffect = new CSkillEffect_i_summon_debuf_cubic;
										
										pEffect->var1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_summon_paralyze_cubic")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_summon_paralyze_cubic *pEffect = new CSkillEffect_i_summon_paralyze_cubic;
										pEffect->var1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_summon_water_dot_cubic")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_summon_water_dot_cubic *pEffect = new CSkillEffect_i_summon_water_dot_cubic;
										
										pEffect->var1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_summon_shock_cubic")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_summon_shock_cubic *pEffect = new CSkillEffect_i_summon_shock_cubic;
										
										pEffect->var1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_save_position")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_save_position *pEffect = new CSkillEffect_i_save_position;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_fly_away")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_fly_away *pEffect = new CSkillEffect_i_fly_away;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_register_siege_golem")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_register_siege_golem *pEffect = new CSkillEffect_i_register_siege_golem;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_remove_m_power")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_remove_m_power *pEffect = new CSkillEffect_i_remove_m_power;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_m_attack_over_hit")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_m_attack_over_hit *pEffect = new CSkillEffect_i_m_attack_over_hit;
										
										pEffect->var1 = _wtof(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_give_contribution")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_give_contribution *pEffect = new CSkillEffect_i_give_contribution;
										
										pEffect->var1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_change_face")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_change_face *pEffect = new CSkillEffect_i_change_face;
										
										pEffect->var1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_change_hair_style")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_change_hair_style *pEffect = new CSkillEffect_i_change_hair_style;
										
										pEffect->var1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_change_hair_color")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_change_hair_color *pEffect = new CSkillEffect_i_change_hair_color;
										
										pEffect->var1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_cub_m_attack")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_cub_m_attack *pEffect = new CSkillEffect_i_cub_m_attack;
										
										pEffect->var1 = _wtof(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_cub_hp_drain")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_cub_hp_drain *pEffect = new CSkillEffect_i_cub_hp_drain;
										
										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtof(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_cub_heal")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_cub_heal *pEffect = new CSkillEffect_i_cub_heal;
										
										pEffect->var1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_summon_pet")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_summon_pet *pEffect = new CSkillEffect_i_summon_pet;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_food_for_pet")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_food_for_pet *pEffect = new CSkillEffect_i_food_for_pet;

										pEffect->var1 = _wtoi(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());
										pEffect->var3 = _wtoi(var4.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_hp")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_hp *pEffect = new CSkillEffect_i_hp;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_mp")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_mp *pEffect = new CSkillEffect_i_mp;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_resurrection")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_resurrection *pEffect = new CSkillEffect_i_resurrection;

										pEffect->var1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_inform")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_inform *pEffect = new CSkillEffect_i_inform;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_cp")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_cp *pEffect = new CSkillEffect_i_cp;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtoi(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_sp")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_sp *pEffect = new CSkillEffect_i_sp;
										if(var3 == L"per") var3 = L"0"; else var3 = L"1";

										pEffect->var1 = _wtoi(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_physical_attack_hp_link")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_physical_attack_hp_link *pEffect = new CSkillEffect_i_physical_attack_hp_link;

										pEffect->var1 = _wtof(var2.c_str());
		
										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_m_attack_by_hp")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_m_attack_by_hp *pEffect = new CSkillEffect_i_m_attack_by_hp;

										pEffect->var1 = _wtof(var2.c_str());
		
										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_m_attack_by_dist")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_m_attack_by_dist *pEffect = new CSkillEffect_i_m_attack_by_dist;

										pEffect->var1 = _wtof(var2.c_str());
		
										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_fishing_cast")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_fishing_cast *pEffect = new CSkillEffect_i_fishing_cast;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_fishing_pumping")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_fishing_pumping *pEffect = new CSkillEffect_i_fishing_pumping;

										pEffect->var1 = _wtof(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_fishing_reeling")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_fishing_reeling *pEffect = new CSkillEffect_i_fishing_reeling;

										pEffect->var1 = _wtof(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_fishing_shot")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_fishing_shot *pEffect = new CSkillEffect_i_fishing_shot;

										pEffect->var1 = _wtof(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_open_dwarf_recipebook")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_open_dwarf_recipebook *pEffect = new CSkillEffect_i_open_dwarf_recipebook;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_open_common_recipebook")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_open_common_recipebook *pEffect = new CSkillEffect_i_open_common_recipebook;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_align_direction")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_align_direction *pEffect = new CSkillEffect_i_align_direction;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_death")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_death *pEffect = new CSkillEffect_i_death;

										pEffect->var1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_rebalance_hp")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_rebalance_hp *pEffect = new CSkillEffect_i_rebalance_hp;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_rebalance_mp")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_rebalance_mp *pEffect = new CSkillEffect_i_rebalance_mp;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_target_cancel")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_target_cancel *pEffect = new CSkillEffect_i_target_cancel;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_target_me")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_target_me *pEffect = new CSkillEffect_i_target_me;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_teleport")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_teleport *pEffect = new CSkillEffect_i_teleport;

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtof(var3.c_str());
										pEffect->var3 = _wtof(var4.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_install_camp_ex")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_install_camp_ex *pEffect = new CSkillEffect_i_install_camp_ex;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_fatal_blow")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_fatal_blow *pEffect = new CSkillEffect_i_fatal_blow;

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtof(var3.c_str());
										pEffect->var3 = _wtoi(var4.c_str());

										pEffect->var_a2 = 0;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"CSkillEffect_i_escape")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_escape *pEffect = new CSkillEffect_i_escape;

										if(var2 == L"village") var2 = L"0";
										if(var2 == L"agit") var2 = L"1";
										if(var2 == L"castle") var2 = L"2";

										pEffect->var1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_delete_hate")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_delete_hate *pEffect = new CSkillEffect_i_delete_hate;

										pEffect->var1 = _wtoi(var2.c_str());

										pEffect->var_a2 = 1;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_randomize_hate")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_randomize_hate *pEffect = new CSkillEffect_i_randomize_hate;

										pEffect->var1 = _wtoi(var2.c_str());

										pEffect->var_a2 = 2;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_confuse")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_confuse *pEffect = new CSkillEffect_i_confuse;

										pEffect->var1 = _wtoi(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										pEffect->var_a2 = 3;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_run_away")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_run_away *pEffect = new CSkillEffect_i_run_away;

										pEffect->var1 = _wtoi(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());

										pEffect->var_a2 = 4;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_spoil")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_spoil *pEffect = new CSkillEffect_i_spoil;

										pEffect->var_a2 = 5;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_sowing")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_sowing *pEffect = new CSkillEffect_i_sowing;

										pEffect->var_a2 = 5;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_delete_hate_of_me")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_delete_hate_of_me *pEffect = new CSkillEffect_i_delete_hate_of_me;

										pEffect->var1 = _wtoi(var2.c_str());

										pEffect->var_a2 = 8;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_transmit_m_power")		//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_transmit_m_power *pEffect = new CSkillEffect_i_transmit_m_power;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_backstab")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_backstab *pEffect = new CSkillEffect_i_backstab;

										pEffect->var_a2 = 6;

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var2 = _wtof(var3.c_str());
										pEffect->var3 = _wtof(var4.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_distrus")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_distrust *pEffect = new CSkillEffect_i_distrust;

										pEffect->var_a2 = 7;

										pEffect->var1 = _wtoi(var2.c_str());
										pEffect->var2 = _wtoi(var3.c_str());
	
										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_dispel_by_category")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_dispel_by_category *pEffect = new CSkillEffect_i_dispel_by_category;

										if(var2 == L"slot_buff") var2 = L"0";
										else if(var2 == L"slot_debuff") var2 = L"1";
										else var2 = L"2";

										pEffect->var1 = _wtoi(var2.c_str());

										pEffect->var2 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}
									if (var1 == L"i_energy_attack")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_i_energy_attack *pEffect = new CSkillEffect_i_energy_attack;

										pEffect->var1 = _wtof(var2.c_str());

										pEffect->var2 = _wtoi(var3.c_str());

										pSI->nIsEnergyAttack = 1;

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										typedef void (*f)(vector<CSkillEffect *>*, CSkillEffect**);
										f(0x7A1D60)(&pSI->m_vInstantEffects, &pEffect_Final);	//PUSH MAP
									}

									//-----------------------------pSI->m_pConsumeEffect---------------------------------

									if (var1 == L"t_hp")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_t_hp *pEffect = new CSkillEffect_t_hp;

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var_a1 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										pSI->m_pConsumeEffect = pEffect_Final;
									}
									if (var1 == L"t_cub_hp")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_t_cub_hp *pEffect = new CSkillEffect_t_cub_hp;

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var_a1 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										pSI->m_pConsumeEffect = pEffect_Final;
									}
									if (var1 == L"t_mp")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_t_mp *pEffect = new CSkillEffect_t_mp;

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var_a1 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										pSI->m_pConsumeEffect = pEffect_Final;
									}
									if (var1 == L"t_hp_fatal")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_t_hp_fatal *pEffect = new CSkillEffect_t_hp_fatal;

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var_a1 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										pSI->m_pConsumeEffect = pEffect_Final;
									}



									//-----------------------------pSI->m_TickEffects---------------------------------

									if (var1 == L"c_mp")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_c_mp *pEffect = new CSkillEffect_c_mp;

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var_a1 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										pSI->m_TickEffects = pEffect_Final;
									}
									if (var1 == L"c_hp")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_c_hp *pEffect = new CSkillEffect_c_hp;

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var_a1 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										pSI->m_TickEffects = pEffect_Final;
									}
									if (var1 == L"c_rest")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_c_rest *pEffect = new CSkillEffect_c_rest;

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var_a1 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										pSI->m_TickEffects = pEffect_Final;
									}
									if (var1 == L"c_chameleon_rest")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_c_chameleon_rest *pEffect = new CSkillEffect_c_chameleon_rest;

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var_a1 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										pSI->m_TickEffects = pEffect_Final;
									}
									if (var1 == L"c_mp_by_level")				//NO LO PROBE PERO PARECE PERFECTO
									{
										CSkillEffect_c_mp_by_level *pEffect = new CSkillEffect_c_mp_by_level;

										pEffect->var1 = _wtof(var2.c_str());
										pEffect->var_a1 = _wtoi(var3.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										pSI->m_TickEffects = pEffect_Final;
									}
									if (var1 == L"c_fake_death")				// OK TESTEADO
									{
										CSkillEffect_c_fake_death *pEffect = new CSkillEffect_c_fake_death;

										pEffect->var1 = _wtof(var3.c_str());
										pEffect->var_a1 = _wtoi(var2.c_str());

										CSkillEffect *pEffect_Final = (CSkillEffect *)pEffect;
										pSI->m_TickEffects = pEffect_Final;
									}
								


								//CSkillEffect_p_physical_defence_by_material (NO TENGO INFORMACION SUFICIENTE)
								//CSkillEffect_p_physical_attack_by_material (NO TENGO INFORMACION SUFICIENTE)

								//CSkillEffect_i_dispel_by_slot (LO VOY A HACER AL FINAL IGUAL NO SE UTILIZA

								//CSkillEffect_p_block_getdamage  (NO TENGO INFORMACION SUFICIENTE) tengo que descompilar un poco mas


									//----------------------------------------------------------------



								}

							}

				//			g_Log.Add(CLog::Error, "[%S]",wStr.c_str());
							///-----------------------------------------------------------------------------------------------------
						}
					}
				}
			}
		}
	}


//file.close();

//	if (ret)
//		g_Log.Add(CLog::Blue, "[%s] Loaded skillId[%d]", __FUNCTION__, skillId);
//	else
//		g_Log.Add(CLog::Blue, "[%s] No se pudo encontrar skillId[%d]", __FUNCTION__, skillId);

	unguard;
	return ret;
}



									//	ShowMessage("size", "CSkillInfo Size %p", sizeof(CSkillEffect_p_hit));
//										g_Log.Add(CLog::Error, "%S",var1.c_str());
//										g_Log.Add(CLog::Error, "%S",var2.c_str());
//										g_Log.Add(CLog::Error, "%S",var3.c_str());
//										g_Log.Add(CLog::Error, "%S",var4.c_str());



							//			g_Log.Add(CLog::Blue, "OFFSET [%x]", pSI->m_vPumpEffect[0]);

							//			g_Log.Add(CLog::Blue, "INT32 [%d]", (*(LPWORD)((INT32)pSI->m_vPumpEffect[0]+24)));		// INT *(v886 + 4) = v1086;



					//--------------------------------------------


			//						if( (*(LPDWORD)pSI->vCSkillEffectList1[n]) == 0x00ADA958)	// CSkillEffect_p_cubic_mastery		//vCSkillEffectList1
			//						{
			//							g_Log.Add(CLog::Blue, "OFFSET [%d]", (int)pSI->vCSkillEffectList1[n]);
			//							g_Log.Add(CLog::Blue, "INT32 [%d]", (*(LPWORD)((INT32)pSI->vCSkillEffectList1[n]+16)));		// INT *(v886 + 4) = v1086;
			//						}