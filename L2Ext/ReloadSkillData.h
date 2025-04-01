#pragma once
#include "SkillEffect.h"
#include "DBSocket.h"
#include "winsock.h"


class ReloadSkillData
{

public:
	static bool ReloadSkills(int skillId);
};



static const DWORD  VT_I_P_ATTACK   							=	0x00AD7AD8;	// I_P_ATTACK
static const DWORD  VT_I_P_ATTACK_OVER_HIT   					=	0x00AD7B38;	// I_P_ATTACK_OVER_HIT
static const DWORD  VT_I_FATAL_BLOW   							=	0x00AD7B98;	// I_FATAL_BLOW
static const DWORD  VT_I_HEAL   								=	0x00AD7BF8;	// I_HEAL
static const DWORD  VT_I_HP_DRAIN   							=	0x00AD7C58;	// I_HP_DRAIN
static const DWORD  VT_I_M_ATTACK   							=	0x00AD7CB8;	// I_M_ATTACK
static const DWORD  VT_I_M_ATTACK_BY_HP   						=	0x00AD7D18;	// I_M_ATTACK_BY_HP
static const DWORD  VT_I_M_ATTACK_BY_DIST   					=	0x00AD7D78;	// I_M_ATTACK_BY_DIST
static const DWORD  VT_I_ESCAPE   								=	0x00AD7DD8;	// I_ESCAPE
static const DWORD  VT_I_HP   									=	0x00AD7E38;	// I_HP
static const DWORD  VT_I_HP_SELF   								=	0x00AD7E98;	// I_HP_SELF
static const DWORD  VT_I_MP   									=	0x00AD7EF8;	// I_MP
static const DWORD  VT_I_INFORM   								=	0x00AD7F58;	// I_INFORM
static const DWORD  VT_I_RESURRECTION							=	0x00AD7FB8;	// I_RESURRECTION
static const DWORD  VT_I_ENCHANT_WEAPON   						=	0x00AD8018;	// I_ENCHANT_WEAPON
static const DWORD  VT_I_ENCHANT_ARMOR   						=	0x00AD8078;	// I_ENCHANT_ARMOR
static const DWORD  VT_I_HP_PER_MAX   							=	0x00AD80D8;	// I_HP_PER_MAX
static const DWORD  VT_I_MP_PER_MAX   							=	0x00AD8138;	// I_MP_PER_MAX
static const DWORD  VT_I_MP_BY_LEVEL   							=	0x00AD8198;	// I_MP_BY_LEVEL
static const DWORD  VT_I_ADD_HATE   							=	0x00AD81F8;	// I_ADD_HATE
static const DWORD  VT_I_HOLYTHING_POSSESS   					=	0x00AD8258;	// I_HOLYTHING_POSSESS
static const DWORD  VT_I_INSTALL_CAMP   						=	0x00AD82B8;	// I_INSTALL_CAMP
static const DWORD  VT_I_UNLOCK   								=	0x00AD8318;	// I_UNLOCK
static const DWORD  VT_I_DELETE_HATE   							=	0x00AD8378;	// I_DELETE_HATE
static const DWORD  VT_I_RANDOMIZE_HATE   						=	0x00AD83D8;	// I_RANDOMIZE_HATE
static const DWORD  VT_I_FOCUS_ENERGY   						=	0x00AD8438;	// I_FOCUS_ENERGY
static const DWORD  VT_I_ENERGY_ATTACK   						=	0x00AD8498;	// I_ENERGY_ATTACK
static const DWORD  VT_I_SOUL_SHOT   							=	0x00AD84F8;	// I_SOUL_SHOT
static const DWORD  VT_I_SPIRIT_SHOT   							=	0x00AD8558;	// I_SPIRIT_SHOT
static const DWORD  VT_I_SUMMON_SOUL_SHOT   					=	0x00AD85B8;	// I_SUMMON_SOUL_SHOT
static const DWORD  VT_I_SUMMON_SPIRIT_SHOT   					=	0x00AD8618;	// I_SUMMON_SPIRIT_SHOT
static const DWORD  VT_I_CONFUSE   								=	0x00AD8678;	// I_CONFUSE
static const DWORD  VT_I_RUN_AWAY   							=	0x00AD86D8;	// I_RUN_AWAY
static const DWORD  VT_I_CONSUME_BODY   						=	0x00AD8738;	// I_CONSUME_BODY
static const DWORD  VT_I_HP_BY_LEVEL_SELF   					=	0x00AD8798;	// I_HP_BY_LEVEL_SELF
static const DWORD  VT_I_MP_BY_LEVEL_SELF   					=	0x00AD87F8;	// I_MP_BY_LEVEL_SELF
static const DWORD  VT_I_SPOIL   								=	0x00AD8858;	// I_SPOIL
static const DWORD  VT_I_SWEEPER   								=	0x00AD88B8;	// I_SWEEPER
static const DWORD  VT_I_SOWING   								=	0x00AD8918;	// I_SOWING
static const DWORD  VT_I_HARVESTING   							=	0x00AD8978;	// I_HARVESTING
static const DWORD  VT_I_BACKSTAB   							=	0x00AD89D8;	// I_BACKSTAB
static const DWORD  VT_I_DISTRUST   							=	0x00AD8A38;	// I_DISTRUST
static const DWORD  VT_I_DELETE_HATE_OF_ME   					=	0x00AD8A98;	// I_DELETE_HATE_OF_ME
static const DWORD  VT_I_DEATH_LINK   							=	0x00AD8AF8;	// I_DEATH_LINK
static const DWORD  VT_I_DISPEL_ALL   							=	0x00AD8B58;	// I_DISPEL_ALL
static const DWORD  VT_I_SUMMON_DD_CUBIC   						=	0x00AD8BB8;	// I_SUMMON_DD_CUBIC
static const DWORD  VT_I_SUMMON_DRAIN_CUBIC   					=	0x00AD8C18;	// I_SUMMON_DRAIN_CUBIC
static const DWORD  VT_I_SUMMON_HEAL_CUBIC   					=	0x00AD8C78;	// I_SUMMON_HEAL_CUBIC
static const DWORD  VT_I_SUMMON_POISON_CUBIC   					=	0x00AD8CD8;	// I_SUMMON_POISON_CUBIC
static const DWORD  VT_I_SUMMON_DEBUF_CUBIC   					=	0x00AD8D38;	// I_SUMMON_DEBUF_CUBIC
static const DWORD  VT_I_SUMMON_PARALYZE_CUBIC   				=	0x00AD8D98;	// I_SUMMON_PARALYZE_CUBIC
static const DWORD  VT_I_SUMMON_WATER_DOT_CUBIC   				=	0x00AD8DF8;	// I_SUMMON_WATER_DOT_CUBIC
static const DWORD  VT_I_SUMMON_SHOCK_CUBIC   					=	0x00AD8E58;	// I_SUMMON_SHOCK_CUBIC
static const DWORD  VT_I_CUB_M_ATTACK   						=	0x00AD8EB8;	// I_CUB_M_ATTACK
static const DWORD  VT_I_CUB_HP_DRAIN   						=	0x00AD8F18;	// I_CUB_HP_DRAIN
static const DWORD  VT_I_CUB_HEAL   							=	0x00AD8F78;	// I_CUB_HEAL
static const DWORD  VT_I_SAVE_POSITION   						=	0x00AD8FD8;	// I_SAVE_POSITION
static const DWORD  VT_I_FLY_AWAY   							=	0x00AD9038;	// I_FLY_AWAY
static const DWORD  VT_I_REGISTER_SIEGE_GOLEM   				=	0x00AD9098;	// I_REGISTER_SIEGE_GOLEM
static const DWORD  VT_I_TRANSMIT_M_POWER   					=	0x00AD90F8;	// I_TRANSMIT_M_POWER
static const DWORD  VT_I_REMOVE_M_POWER   						=	0x00AD9158;	// I_REMOVE_M_POWER
static const DWORD  VT_I_M_ATTACK_OVER_HIT   					=	0x00AD91B8;	// I_M_ATTACK_OVER_HIT
static const DWORD  VT_I_RESTORATION_RANDOM   					=	0x00AD9218;	// I_RESTORATION_RANDOM
static const DWORD  VT_I_GIVE_CONTRIBUTION   					=	0x00AD9278;	// I_GIVE_CONTRIBUTION
static const DWORD  VT_I_CHANGE_FACE   							=	0x00AD92D8;	// I_CHANGE_FACE
static const DWORD  VT_I_CHANGE_HAIR_STYLE   					=	0x00AD9338;	// I_CHANGE_HAIR_STYLE
static const DWORD  VT_I_CHANGE_HAIR_COLOR   					=	0x00AD9398;	// I_CHANGE_HAIR_COLOR
static const DWORD  VT_I_CP   									=	0x00AD93F8;	// I_CP
static const DWORD  VT_I_SP   									=	0x00AD9458;	// I_SP
static const DWORD  VT_I_PHYSICAL_ATTACK_HP_LINK   				=	0x00AD94B8;	// I_PHYSICAL_ATTACK_HP_LINK
static const DWORD  VT_I_DISPEL_BY_CATEGORY   					=	0x00AD9518;	// I_DISPEL_BY_CATEGORY
static const DWORD  VT_I_ALIGN_DIRECTION   						=	0x00AD9578;	// I_ALIGN_DIRECTION
static const DWORD  VT_I_DEATH   								=	0x00AD95D8;	// I_DEATH
static const DWORD  VT_I_REBALANCE_HP   						=	0x00AD9638;	// I_REBALANCE_HP
static const DWORD  VT_I_REBALANCE_MP   						=	0x00AD9698;	// I_REBALANCE_MP
static const DWORD  VT_I_TARGET_CANCEL   						=	0x00AD96F8;	// I_TARGET_CANCEL
static const DWORD  VT_I_TARGET_ME   							=	0x00AD9758;	// I_TARGET_ME
static const DWORD  VT_I_INSTALL_CAMP_EX   						=	0x00AD97B8;	// I_INSTALL_CAMP_EX
static const DWORD  VT_P_PHYSICAL_ATTACK   						=	0x00AD9818;	// P_PHYSICAL_ATTACK
static const DWORD  VT_P_PHYSICAL_DEFENCE   					=	0x00AD9878;	// P_PHYSICAL_DEFENCE						//BIEN
static const DWORD  VT_P_PHYSICAL_ATTACK_BY_MATERIAL  	 		=	0x00AD98D8;	// P_PHYSICAL_ATTACK_BY_MATERIAL
static const DWORD  VT_P_PHYSICAL_DEFENCE_BY_MATERIAL  			=	0x00AD9938;	// P_PHYSICAL_DEFENCE_BY_MATERIAL
static const DWORD  VT_P_MAGICAL_DEFENCE   						=	0x00AD9998;	// P_MAGICAL_DEFENCE
static const DWORD  VT_P_ATTACK_ATTRIBUTE   					=	0x00AD99F8;	// P_ATTACK_ATTRIBUTE
static const DWORD  VT_P_DEFENCE_ATTRIBUTE   					=	0x00AD9A58;	// P_DEFENCE_ATTRIBUTE
static const DWORD  VT_P_HP_REGEN   							=	0x00AD9AB8;	// P_HP_REGEN
static const DWORD  VT_P_MP_REGEN   							=	0x00AD9B18;	// P_MP_REGEN
static const DWORD  VT_P_SPEED   								=	0x00AD9B78;	// P_SPEED
static const DWORD  VT_P_ATTACK_SPEED   						=	0x00AD9BD8;	// P_ATTACK_SPEED
static const DWORD  VT_P_MAGIC_SPEED   							=	0x00AD9C38;	// P_MAGIC_SPEED
static const DWORD  VT_P_REMOVE_EQUIP_PENALTY   				=	0x00AD9C98;	// P_REMOVE_EQUIP_PENALTY
static const DWORD  VT_P_CRYSTALLIZE   							=	0x00AD9CF8;	// P_CRYSTALLIZE
static const DWORD  VT_P_LUCK   								=	0x00AD9D58;	// P_LUCK
static const DWORD  VT_P_CREATE_ITEM   							=	0x00AD9DB8;	// P_CREATE_ITEM
static const DWORD  VT_P_CREATE_COMMON_ITEM   					=	0x00AD9E18;	// P_CREATE_COMMON_ITEM
static const DWORD  VT_P_AVOID   								=	0x00AD9E78;	// P_AVOID
static const DWORD  VT_P_BLOCK_ACT   							=	0x00AD9ED8;	// P_BLOCK_ACT
static const DWORD  VT_P_BLOCK_MOVE   							=	0x00AD9F38;	// P_BLOCK_MOVE
static const DWORD  VT_P_BLOCK_CONTROLL   						=	0x00AD9F98;	// P_BLOCK_CONTROLL
static const DWORD  VT_P_BLOCK_SPELL   							=	0x00AD9FF8;	// P_BLOCK_SPELL
static const DWORD  VT_P_FEAR   								=	0x00ADA058;	// P_FEAR
static const DWORD  VT_P_MAX_HP   								=	0x00ADA0B8;	// P_MAX_HP
static const DWORD  VT_P_MAX_MP   								=	0x00ADA118;	// P_MAX_MP
static const DWORD  VT_P_MAX_CP   								=	0x00ADA178;	// P_MAX_CP
static const DWORD  VT_P_HIT   									=	0x00ADA1D8;	// P_HIT
static const DWORD  VT_P_MAGICAL_ATTACK   						=	0x00ADA238;	// P_MAGICAL_ATTACK
static const DWORD  VT_P_ATTACK_RANGE   						=	0x00ADA298;	// P_ATTACK_RANGE
static const DWORD  VT_P_CRITICAL_RATE   						=	0x00ADA2F8;	// P_CRITICAL_RATE
static const DWORD  VT_P_CRITICAL_DAMAGE   						=	0x00ADA358;	// P_CRITICAL_DAMAGE
static const DWORD  VT_P_AVOID_BY_MOVE_MODE   					=	0x00ADA3B8;	// P_AVOID_BY_MOVE_MODE
static const DWORD  VT_P_REUSE_DELAY   							=	0x00ADA418;	// P_REUSE_DELAY
static const DWORD  VT_P_REDUCE_CANCEL   						=	0x00ADA478;	// P_REDUCE_CANCEL
static const DWORD  VT_P_ATTACK_SPEED_BY_WEAPON   				=	0x00ADA4D8;	// P_ATTACK_SPEED_BY_WEAPON
static const DWORD  VT_P_SHIELD_DEFENCE_RATE   					=	0x00ADA538;	// P_SHIELD_DEFENCE_RATE
static const DWORD  VT_P_HP_REGEN_BY_MOVE_MODE   				=	0x00ADA598;	// P_HP_REGEN_BY_MOVE_MODE
static const DWORD  VT_P_MP_REGEN_BY_MOVE_MODE   				=	0x00ADA5F8;	// P_MP_REGEN_BY_MOVE_MODE
static const DWORD  VT_P_SAFE_FALL_HEIGHT   					=	0x00ADA658;	// P_SAFE_FALL_HEIGHT
static const DWORD  VT_P_BREATH   								=	0x00ADA6B8;	// P_BREATH
static const DWORD  VT_P_DAMAGE_SHIELD   						=	0x00ADA718;	// P_DAMAGE_SHIELD
static const DWORD  VT_P_PASSIVE   								=	0x00ADA778;	// P_PASSIVE
static const DWORD  VT_P_AVOID_AGRO   							=	0x00ADA7D8;	// P_AVOID_AGRO
static const DWORD  VT_P_WEIGHT_LIMIT   						=	0x00ADA838;	// P_WEIGHT_LIMIT
static const DWORD  VT_P_TRADE   								=	0x00ADA898;	// P_TRADE
static const DWORD  VT_P_SET_COLLECTED   						=	0x00ADA8F8;	// P_SET_COLLECTED
static const DWORD  VT_P_CUBIC_MASTERY   						=	0x00ADA958;	// P_CUBIC_MASTERY
static const DWORD  VT_P_WEIGHT_PENALTY   						=	0x00ADA9B8;	// P_WEIGHT_PENALTY
static const DWORD  VT_P_MANA_CHARGE   							=	0x00ADAA18;	// P_MANA_CHARGE
static const DWORD  VT_P_TRANSFER_DAMAGE_SUMMON   				=	0x00ADAA78;	// P_TRANSFER_DAMAGE_SUMMON
static const DWORD  VT_P_HEAL_EFFECT   							=	0x00ADAAD8;	// P_HEAL_EFFECT
static const DWORD  VT_P_AREA_DAMAGE   							=	0x00ADAB38;	// P_AREA_DAMAGE
static const DWORD  VT_P_HIT_AT_NIGHT   						=	0x00ADAB98;	// P_HIT_AT_NIGHT
static const DWORD  VT_P_2H_SWORD_BONUS   						=	0x00ADABF8;	// P_2H_SWORD_BONUS
static const DWORD  VT_P_2H_BLUNT_BONUS   						=	0x00ADAC58;	// P_2H_BLUNT_BONUS
static const DWORD  VT_P_VAMPIRIC_ATTACK   						=	0x00ADACB8;	// P_VAMPIRIC_ATTACK
static const DWORD  VT_P_CRITICAL_RATE_BY_HP1   				=	0x00ADAD18;	// P_CRITICAL_RATE_BY_HP1
static const DWORD  VT_P_CRITICAL_RATE_BY_HP2   				=	0x00ADAD78;	// P_CRITICAL_RATE_BY_HP2
static const DWORD  VT_P_PHYSICAL_ATTACK_BY_HP1   				=	0x00ADADD8;	// P_PHYSICAL_ATTACK_BY_HP1
static const DWORD  VT_P_PHYSICAL_ATTACK_BY_HP2   				=	0x00ADAE38;	// P_PHYSICAL_ATTACK_BY_HP2
static const DWORD  VT_P_PHYSICAL_DEFENCE_BY_HP1   				=	0x00ADAE98;	// P_PHYSICAL_DEFENCE_BY_HP1
static const DWORD  VT_P_PHYSICAL_DEFENCE_BY_HP2   				=	0x00ADAEF8;	// P_PHYSICAL_DEFENCE_BY_HP2
static const DWORD  VT_P_AVOID_RATE_BY_HP1   					=	0x00ADAF58;	// P_AVOID_RATE_BY_HP1
static const DWORD  VT_P_AVOID_RATE_BY_HP2   					=	0x00ADAFB8;	// P_AVOID_RATE_BY_HP2
static const DWORD  VT_P_ATTACK_SPEED_BY_HP1   					=	0x00ADB018;	// P_ATTACK_SPEED_BY_HP1
static const DWORD  VT_P_ATTACK_SPEED_BY_HP2   					=	0x00ADB078;	// P_ATTACK_SPEED_BY_HP2
static const DWORD  VT_P_FATAL_BLOW_RATE   						=	0x00ADB0D8;	// P_FATAL_BLOW_RATE
static const DWORD  VT_P_CRITICAL_RATE_POSITION_BONUS  			=	0x00ADB138;	// P_CRITICAL_RATE_POSITION_BONUS
static const DWORD  VT_P_SHOWTIME   							=	0x00ADB198;	// P_SHOWTIME
static const DWORD  VT_P_SOUND   								=	0x00ADB1F8;	// P_SOUND
static const DWORD  VT_P_SEE_MY_HEART   						=	0x00ADB258;	// P_SEE_MY_HEART
static const DWORD  VT_P_CUB_PHYSICAL_ATTACK   					=	0x00ADB2B8;	// P_CUB_PHYSICAL_ATTACK
static const DWORD  VT_P_CUB_PHYSICAL_DEFENCE   				=	0x00ADB318;	// P_CUB_PHYSICAL_DEFENCE
static const DWORD  VT_P_CUB_ATTACK_SPEED   					=	0x00ADB378;	// P_CUB_ATTACK_SPEED
static const DWORD  VT_P_CUB_BLOCK_ACT   						=	0x00ADB3D8;	// P_CUB_BLOCK_ACT
static const DWORD  VT_P_REDUCE_DROP_PENALTY   					=	0x00ADB438;	// P_REDUCE_DROP_PENALTY
static const DWORD  VT_P_PHYSICAL_SHIELD_DEFENCE_ANGLE_ALL  	= 	0x00ADB498;	// P_PHYSICAL_SHIELD_DEFENCE_ANGLE_ALL
static const DWORD  VT_P_MAGIC_MP_COST   						=	0x00ADB4F8;	// P_MAGIC_MP_COST
static const DWORD  VT_P_MAGIC_CRITICAL_RATE   					=	0x00ADB558;	// P_MAGIC_CRITICAL_RATE
static const DWORD  VT_P_PHYSICAL_ARMOR_HIT   					=	0x00ADB5B8;	// P_PHYSICAL_ARMOR_HIT
static const DWORD  VT_P_PVP_PHYSICAL_ATTACK_DMG_BONUS  	 	=	0x00ADB618;	// P_PVP_PHYSICAL_ATTACK_DMG_BONUS
static const DWORD  VT_P_PVP_PHYSICAL_SKILL_DMG_BONUS  		 	=	0x00ADB678;	// P_PVP_PHYSICAL_SKILL_DMG_BONUS
static const DWORD  VT_P_PVP_MAGICAL_SKILL_DMG_BONUS  		 	=	0x00ADB6D8;	// P_PVP_MAGICAL_SKILL_DMG_BONUS
static const DWORD  VT_P_PHYSICAL_SHIELD_DEFENCE   				=	0x00ADB738;	// P_PHYSICAL_SHIELD_DEFENCE
static const DWORD  VT_P_PHYSICAL_POLARM_TARGET_SINGLE  	 	=	0x00ADB798;	// P_PHYSICAL_POLARM_TARGET_SINGLE
static const DWORD  VT_P_ABNORMAL_RATE_LIMIT   					=	0x00ADB7F8;	// P_ABNORMAL_RATE_LIMIT
static const DWORD  VT_P_ABNORMAL_REMOVE_BY_HIT   				=	0x00ADB858;	// P_ABNORMAL_REMOVE_BY_HIT
static const DWORD  VT_P_ABNORMAL_REMOVE_BY_DMG   				=	0x00ADB8B8;	// P_ABNORMAL_REMOVE_BY_DMG
static const DWORD  VT_P_BLOCK_SKILL_PHYSICAL   				=	0x00ADB918;	// P_BLOCK_SKILL_PHYSICAL
static const DWORD  VT_P_BLOCK_SKILL_SPECIAL   					=	0x00ADB978;	// P_BLOCK_SKILL_SPECIAL
static const DWORD  VT_P_BLOCK_BUFF   							=	0x00ADB9D8;	// P_BLOCK_BUFF
static const DWORD  VT_P_BLOCK_DEBUFF   						=	0x00ADBA38;	// P_BLOCK_DEBUFF
static const DWORD  VT_P_REFLECT_SKILL   						=	0x00ADBA98;	// P_REFLECT_SKILL
static const DWORD  VT_P_SKILL_CRITICAL   						=	0x00ADBAF8;	// P_SKILL_CRITICAL
static const DWORD  VT_P_SKILL_CRITICAL_PROBABILITY   			=	0x00ADBB58;	// P_SKILL_CRITICAL_PROBABILITY
static const DWORD  VT_P_CRITICAL_DAMAGE_POSITION   			=	0x00ADBBB8;	// P_CRITICAL_DAMAGE_POSITION
static const DWORD  VT_P_RESIST_DISPEL_BY_CATEGORY   			=	0x00ADBC18;	// P_RESIST_DISPEL_BY_CATEGORY
static const DWORD  VT_P_RESIST_ABNORMAL_BY_CATEGORY  	 		=	0x00ADBC78;	// P_RESIST_ABNORMAL_BY_CATEGORY
static const DWORD  VT_P_PRESERVE_ABNORMAL   					=	0x00ADBCD8;	// P_PRESERVE_ABNORMAL
static const DWORD  VT_P_ENLARGE_STORAGE   						=	0x00ADBD38;	// P_ENLARGE_STORAGE
static const DWORD  VT_P_HIT_NUMBER   							=	0x00ADBD98;	// P_HIT_NUMBER
static const DWORD  VT_T_HP   									=	0x00ADBDF8;	// T_HP
static const DWORD  VT_T_HP_FATAL   							=	0x00ADBE58;	// T_HP_FATAL
static const DWORD  VT_T_CUB_HP   								=	0x00ADBEB8;	// T_CUB_HP
static const DWORD  VT_T_MP   									=	0x00ADBF18;	// T_MP
static const DWORD  VT_C_MP   									=	0x00ADBF78;	// C_MP
static const DWORD  VT_C_HP   									=	0x00ADBFD8;	// C_HP
static const DWORD  VT_C_REST   								=	0x00ADC038;	// C_REST
static const DWORD  VT_C_CHAMELEON_REST   						=	0x00ADC098;	// C_CHAMELEON_REST
static const DWORD  VT_C_MP_BY_LEVEL   							=	0x00ADC0F8;	// C_MP_BY_LEVEL
static const DWORD  VT_C_FAKE_DEATH   							=	0x00ADC158;	// C_FAKE_DEATH
static const DWORD  VT_P_FISHING_MASTERY   						=	0x00ADC4E8;	// P_FISHING_MASTERY
static const DWORD  VT_I_SUMMON_PET		  						=	0x00ADC1E8;	// I_SUMMON_PET
static const DWORD  VT_I_FOOD_FOR_PET	  						=	0x00ADC248;	// I_FOOD_FOR_PET
static const DWORD  VT_I_FISHING_CAST	  						=	0x00ADC368;	// I_FISHING_CAST
static const DWORD  VT_I_FISHING_PUMPING  						=	0x00ADC3C8;	// I_FISHING_PUMPING
static const DWORD  VT_I_FISHING_REELING	  					=	0x00ADC428;	// I_FISHING_REELING
static const DWORD  VT_I_FISHING_SHOT	  						=	0x00ADC488;	// I_FISHING_SHOT
static const DWORD  VT_I_OPEN_DWARF_RECIPEBOOK	  				=	0x00ADC2A8;	// I_OPEN_DWARF_RECIPEBOOK
static const DWORD  VT_I_OPEN_COMMON_RECIPEBOOK	  				=	0x00ADC308;	// I_OPEN_COMMON_RECIPEBOOK
static const DWORD  VT_I_TELEPORT				  				=	0x00AE22E8;	// I_TELEPORT




class CSkillEffect_i_p_attack	//OK
{
	/*000*/	CSkillEffect_i_p_attack *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_p_attack() { pInstance = (CSkillEffect_i_p_attack*)0x00AD7AD8; };
	double var1;
	int var2;
};


class CSkillEffect_i_p_attack_over_hit	//OK
{
	/*000*/	CSkillEffect_i_p_attack_over_hit *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_p_attack_over_hit() { pInstance = (CSkillEffect_i_p_attack_over_hit*)0x00AD7B38; };
	double var1;
	int var2;
};


class CSkillEffect_i_fatal_blow	//OK
{
	/*000*/	CSkillEffect_i_fatal_blow *pInstance;

public:
	int var_a1;
	int var_a2;
	CSkillEffect_i_fatal_blow() { pInstance = (CSkillEffect_i_fatal_blow*)0x00AD7B98; };
	double var1;
	double var2;
	int var3;
};


class CSkillEffect_i_heal	//OK
{
	/*000*/	CSkillEffect_i_heal *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_heal() { pInstance = (CSkillEffect_i_heal*)0x00AD7BF8; };
	double var1;
};

class CSkillEffect_i_hp_drain	//OK
{
	/*000*/	CSkillEffect_i_hp_drain *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_hp_drain() { pInstance = (CSkillEffect_i_hp_drain*)0x00AD7C58; };
	double var1;
	double var2;

};

class CSkillEffect_i_m_attack	//OK
{
	/*000*/	CSkillEffect_i_m_attack *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_m_attack() { pInstance = (CSkillEffect_i_m_attack*)0x00AD7CB8; };
	double var1;

};

class CSkillEffect_i_escape	//OK
{
	/*000*/	CSkillEffect_i_escape *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_escape() { pInstance = (CSkillEffect_i_escape*)0x00AD7DD8; };
	int var1;

};


class CSkillEffect_i_Enchant_Armor	//OK
{
	/*000*/	CSkillEffect_i_Enchant_Armor *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_Enchant_Armor() { pInstance = (CSkillEffect_i_Enchant_Armor*)0x00AD8078; };

};

class CSkillEffect_i_Enchant_Weapon	//OK
{
	/*000*/	CSkillEffect_i_Enchant_Weapon *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_Enchant_Weapon() { pInstance = (CSkillEffect_i_Enchant_Weapon*)0x00AD8018; };

};

class CSkillEffect_i_hp_per_max	//OK
{
	/*000*/	CSkillEffect_i_hp_per_max *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_hp_per_max() { pInstance = (CSkillEffect_i_hp_per_max*)0x00AD80D8; };
	double var1;

};

class CSkillEffect_i_mp_per_max	//OK
{
	/*000*/	CSkillEffect_i_mp_per_max *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_mp_per_max() { pInstance = (CSkillEffect_i_mp_per_max*)0x00AD8138; };
	double var1;

};

class CSkillEffect_i_mp_by_level	//OK
{
	/*000*/	CSkillEffect_i_mp_by_level *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_mp_by_level() { pInstance = (CSkillEffect_i_mp_by_level*)0x00AD8198; };
	int var1;

};

class CSkillEffect_i_add_hate	//OK
{
	/*000*/	CSkillEffect_i_add_hate *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_add_hate() { pInstance = (CSkillEffect_i_add_hate*)0x00AD81F8; };
	int var1;

};

class CSkillEffect_i_holything_possess	//OK
{
	/*000*/	CSkillEffect_i_holything_possess *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_holything_possess() { pInstance = (CSkillEffect_i_holything_possess*)0x00AD8258; };

};

class CSkillEffect_i_install_camp	//OK
{
	/*000*/	CSkillEffect_i_install_camp *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_install_camp() { pInstance = (CSkillEffect_i_install_camp*)0x00AD82B8; };

};

class CSkillEffect_i_unlock	//OK
{
	/*000*/	CSkillEffect_i_unlock *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_unlock() { pInstance = (CSkillEffect_i_unlock*)0x00AD8318; };
	int var1;
	int var2;
	int var3;

};





class CSkillEffect_i_delete_hate	//OK
{
	/*000*/	CSkillEffect_i_delete_hate *pInstance;

public:
	int var_a1;
	int var_a2;
	CSkillEffect_i_delete_hate() { pInstance = (CSkillEffect_i_delete_hate*)0x00AD8378; };
	int var1;

};


class CSkillEffect_i_randomize_hate	//OK
{
	/*000*/	CSkillEffect_i_randomize_hate *pInstance;

public:
	int var_a1;
	int var_a2;
	CSkillEffect_i_randomize_hate() { pInstance = (CSkillEffect_i_randomize_hate*)0x00AD83D8; };
	int var1;

};


class CSkillEffect_i_focus_energy	//OK
{
	/*000*/	CSkillEffect_i_focus_energy *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_focus_energy() { pInstance = (CSkillEffect_i_focus_energy*)0x00AD8438; };
	int var1;
};


class CSkillEffect_i_energy_attack	//OK
{
	/*000*/	CSkillEffect_i_energy_attack *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_energy_attack() { pInstance = (CSkillEffect_i_energy_attack*)0x00AD8498; };
	double var1;
	int var2;
};


class CSkillEffect_i_soul_shot	//OK
{
	/*000*/	CSkillEffect_i_soul_shot *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_soul_shot() { pInstance = (CSkillEffect_i_soul_shot*)0x00AD84F8; };
	double var1;
};

class CSkillEffect_i_spirit_shot	//OK
{
	/*000*/	CSkillEffect_i_spirit_shot *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_spirit_shot() { pInstance = (CSkillEffect_i_spirit_shot*)0x00AD8558; };
	double var1;
	double var2;
	double var3;
};

class CSkillEffect_i_summon_soul_shot	//OK
{
	/*000*/	CSkillEffect_i_summon_soul_shot *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_summon_soul_shot() { pInstance = (CSkillEffect_i_summon_soul_shot*)0x00AD85B8; };
	double var1;

};

class CSkillEffect_i_summon_spirit_shot	//OK
{
	/*000*/	CSkillEffect_i_summon_spirit_shot *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_summon_spirit_shot() { pInstance = (CSkillEffect_i_summon_spirit_shot*)0x00AD8618; };
	double var1;
	double var2;
	double var3;
};



class CSkillEffect_i_confuse	//OK
{
	/*000*/	CSkillEffect_i_confuse *pInstance;

public:
	int var_a1;
	int var_a2;
	CSkillEffect_i_confuse() { pInstance = (CSkillEffect_i_confuse*)0x00AD8678; };
	int var1;
	int var2;
};



class CSkillEffect_i_run_away	//OK
{
	/*000*/	CSkillEffect_i_run_away *pInstance;

public:
	int var_a1;
	int var_a2;
	CSkillEffect_i_run_away() { pInstance = (CSkillEffect_i_run_away*)0x00AD8678; };
	int var1;
	int var2;
};


class CSkillEffect_i_consume_body	//OK
{
	/*000*/	CSkillEffect_i_consume_body *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_consume_body() { pInstance = (CSkillEffect_i_consume_body*)0x00AD8738; };
};

class CSkillEffect_i_hp_by_level_self	//OK
{
	/*000*/	CSkillEffect_i_hp_by_level_self *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_hp_by_level_self() { pInstance = (CSkillEffect_i_hp_by_level_self*)0x00AD8798; };
	int var1;

};

class CSkillEffect_i_mp_by_level_self	//OK
{
	/*000*/	CSkillEffect_i_mp_by_level_self *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_mp_by_level_self() { pInstance = (CSkillEffect_i_mp_by_level_self*)0x00AD87F8; };
	int var1;

};




class CSkillEffect_i_spoil	//OK
{
	/*000*/	CSkillEffect_i_spoil *pInstance;

public:
	int var_a1;
	int var_a2;
	CSkillEffect_i_spoil() { pInstance = (CSkillEffect_i_spoil*)0x00AD8858; };

};


class CSkillEffect_i_sweeper	//OK
{
	/*000*/	CSkillEffect_i_sweeper *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_sweeper() { pInstance = (CSkillEffect_i_sweeper*)0x00AD88B8; };

};

class CSkillEffect_i_sowing	//OK
{
	/*000*/	CSkillEffect_i_sowing *pInstance;

public:
	int var_a1;
	int var_a2;
	CSkillEffect_i_sowing() { pInstance = (CSkillEffect_i_sowing*)0x00AD8918; };

};



class CSkillEffect_i_harvesting	//OK
{
	/*000*/	CSkillEffect_i_harvesting *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_harvesting() { pInstance = (CSkillEffect_i_harvesting*)0x00AD8978; };

};



class CSkillEffect_i_hp_self	//OK
{
	/*000*/	CSkillEffect_i_hp_self *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_hp_self() { pInstance = (CSkillEffect_i_hp_self*)0x00AD7E98; };
	double var1;
};



class CSkillEffect_i_backstab	//OK
{
	/*000*/	CSkillEffect_i_backstab *pInstance;


public:
	CSkillEffect_i_backstab() { pInstance = (CSkillEffect_i_backstab*)0x00AD89D8; };
	/*008*/ int var_a1;
	/*008*/ int var_a2;
	double var1;
	double var2;
	int var3;
};

class CSkillEffect_i_distrust	//OK
{
	/*000*/	CSkillEffect_i_distrust *pInstance;
public:
	CSkillEffect_i_distrust() { pInstance = (CSkillEffect_i_distrust*)0x00AD8A38; };
	/*008*/ int var_a1;
	/*008*/ int var_a2;
	int var1;
	int var2;

};

class CSkillEffect_i_delete_hate_of_me	//OK
{
	/*000*/	CSkillEffect_i_delete_hate_of_me *pInstance;
public:
	CSkillEffect_i_delete_hate_of_me() { pInstance = (CSkillEffect_i_delete_hate_of_me*)0x00AD8A98; };
	/*008*/ int var_a1;
	/*008*/ int var_a2;
	int var1;


};


class CSkillEffect_i_death_link	//OK
{
	/*000*/	CSkillEffect_i_death_link *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_death_link() { pInstance = (CSkillEffect_i_death_link*)0x00AD8AF8; };
	double var1;
};


class CSkillEffect_i_dispel_all	//OK
{
	/*000*/	CSkillEffect_i_dispel_all *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_dispel_all() { pInstance = (CSkillEffect_i_dispel_all*)0x00AD8B58; };
};

class CSkillEffect_i_summon_dd_cubic	//OK
{
	/*000*/	CSkillEffect_i_summon_dd_cubic *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_summon_dd_cubic() { pInstance = (CSkillEffect_i_summon_dd_cubic*)0x00AD8BB8; };
	int var1;
};


class CSkillEffect_i_summon_drain_cubic	//OK
{
	/*000*/	CSkillEffect_i_summon_drain_cubic *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_summon_drain_cubic() { pInstance = (CSkillEffect_i_summon_drain_cubic*)0x00AD8C18; };
	int var1;
};

class CSkillEffect_i_summon_heal_cubic	//OK
{
	/*000*/	CSkillEffect_i_summon_heal_cubic *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_summon_heal_cubic() { pInstance = (CSkillEffect_i_summon_heal_cubic*)0x00AD8C78; };
	int var1;
};

class CSkillEffect_i_summon_poison_cubic	//OK
{
	/*000*/	CSkillEffect_i_summon_poison_cubic *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_summon_poison_cubic() { pInstance = (CSkillEffect_i_summon_poison_cubic*)0x00AD8CD8; };
	int var1;
};

class CSkillEffect_i_summon_debuf_cubic	//OK
{
	/*000*/	CSkillEffect_i_summon_debuf_cubic *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_summon_debuf_cubic() { pInstance = (CSkillEffect_i_summon_debuf_cubic*)0x00AD8D38; };
	int var1;
};

class CSkillEffect_i_summon_paralyze_cubic	//OK
{
	/*000*/	CSkillEffect_i_summon_paralyze_cubic *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_summon_paralyze_cubic() { pInstance = (CSkillEffect_i_summon_paralyze_cubic*)0x00AD8D98; };
	int var1;
};

class CSkillEffect_i_summon_water_dot_cubic	//OK
{
	/*000*/	CSkillEffect_i_summon_water_dot_cubic *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_summon_water_dot_cubic() { pInstance = (CSkillEffect_i_summon_water_dot_cubic*)0x00AD8DF8; };
	int var1;
};

class CSkillEffect_i_summon_shock_cubic	//OK
{
	/*000*/	CSkillEffect_i_summon_shock_cubic *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_summon_shock_cubic() { pInstance = (CSkillEffect_i_summon_shock_cubic*)0x00AD8E58; };
	int var1;
};

class CSkillEffect_i_save_position	//OK
{
	/*000*/	CSkillEffect_i_save_position *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_save_position() { pInstance = (CSkillEffect_i_save_position*)0x00AD8FD8; };
};

class CSkillEffect_i_fly_away	//OK
{
	/*000*/	CSkillEffect_i_fly_away *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_fly_away() { pInstance = (CSkillEffect_i_fly_away*)0x00AD9038; };
};


class CSkillEffect_i_register_siege_golem	//OK
{
	/*000*/	CSkillEffect_i_register_siege_golem *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_register_siege_golem() { pInstance = (CSkillEffect_i_register_siege_golem*)0x00AD9098; };
};

class CSkillEffect_i_transmit_m_power	//OK
{
	/*000*/	CSkillEffect_i_transmit_m_power *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_transmit_m_power() { pInstance = (CSkillEffect_i_transmit_m_power*)0x00AD90F8; };
};

class CSkillEffect_i_remove_m_power	//OK
{
	/*000*/	CSkillEffect_i_remove_m_power *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_remove_m_power() { pInstance = (CSkillEffect_i_remove_m_power*)0x00AD9158; };
};

class CSkillEffect_i_m_attack_over_hit	//OK
{
	/*000*/	CSkillEffect_i_m_attack_over_hit *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_m_attack_over_hit() { pInstance = (CSkillEffect_i_m_attack_over_hit*)0x00AD91B8; };
	double var1;
};


class CSkillEffect_i_restoration_random : public CSkillEffect
{
public:
	int var1;
	int var2;
	
};

class CSkillEffect_i_give_contribution	//OK
{
	/*000*/	CSkillEffect_i_give_contribution *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_give_contribution() { pInstance = (CSkillEffect_i_give_contribution*)0x00AD9278; };
	int var1;
};

class CSkillEffect_i_change_face	//OK
{
	/*000*/	CSkillEffect_i_change_face *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_change_face() { pInstance = (CSkillEffect_i_change_face*)0x00AD92D8; };
	int var1;
};

class CSkillEffect_i_change_hair_style	//OK
{
	/*000*/	CSkillEffect_i_change_hair_style *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_change_hair_style() { pInstance = (CSkillEffect_i_change_hair_style*)0x00AD9338; };
	int var1;
};

class CSkillEffect_i_change_hair_color	//OK
{
	/*000*/	CSkillEffect_i_change_hair_color *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_change_hair_color() { pInstance = (CSkillEffect_i_change_hair_color*)0x00AD9398; };
	int var1;
};

class CSkillEffect_i_cub_m_attack	//OK
{
	/*000*/	CSkillEffect_i_cub_m_attack *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_cub_m_attack() { pInstance = (CSkillEffect_i_cub_m_attack*)0x00AD8EB8; };
	double var1;
};

class CSkillEffect_i_cub_hp_drain	//OK
{
	/*000*/	CSkillEffect_i_cub_hp_drain *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_cub_hp_drain() { pInstance = (CSkillEffect_i_cub_hp_drain*)0x00AD8F18; };
	double var1;
	double var2;

};

class CSkillEffect_i_cub_heal	//OK
{
	/*000*/	CSkillEffect_i_cub_heal *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_cub_heal() { pInstance = (CSkillEffect_i_cub_heal*)0x00AD8F78; };
	int var1;

};



class CSkillEffect_t_hp	//OK
{
	/*000*/	CSkillEffect_t_hp *pInstance;

public:
	int var_a1;
	int var_a2;

	CSkillEffect_t_hp() { pInstance = (CSkillEffect_t_hp*)0x00ADBDF8; };
	int var1;
};


class CSkillEffect_t_cub_hp	//OK
{
	/*000*/	CSkillEffect_t_cub_hp *pInstance;

public:
	int var_a1;
	int var_a2;

	CSkillEffect_t_cub_hp() { pInstance = (CSkillEffect_t_cub_hp*)0x00ADBEB8; };
	int var1;
};

class CSkillEffect_t_mp	//OK
{
	/*000*/	CSkillEffect_t_mp *pInstance;

public:
	int var_a1;
	int var_a2;

	CSkillEffect_t_mp() { pInstance = (CSkillEffect_t_mp*)0x00ADBF18; };
	int var1;
};

class CSkillEffect_t_hp_fatal	//OK
{
	/*000*/	CSkillEffect_t_hp_fatal *pInstance;

public:
	int var_a1;
	int var_a2;

	CSkillEffect_t_hp_fatal() { pInstance = (CSkillEffect_t_hp_fatal*)0x00ADBE58; };
	int var1;
};


class CSkillEffect_p_physical_attack	//0x30			OK			48 en decimal
{
	/*000*/	CSkillEffect_p_physical_attack *pPointer;
	/*000*/ LPVOID pUnkn001;

public:
	CSkillEffect_p_physical_attack() { pPointer = (CSkillEffect_p_physical_attack*)0x00AD9818; };

  BYTE var1[10];
  double var2;
  int var3;

	int final; // NO USAR
};



class CSkillEffect_p_physical_defence
{
	/*000*/	CSkillEffect_p_physical_defence *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_physical_defence() { pPointer = (CSkillEffect_p_physical_defence*)0x00AD9878; };
	BYTE var1[4];
	double var2;
	int var3;
 
	
};


class CSkillEffect_p_hp_regen
{
	/*000*/	CSkillEffect_p_hp_regen *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_hp_regen() { pPointer = (CSkillEffect_p_hp_regen*)0x00AD9AB8; };
	double var1;
	int var2;
	BYTE var3[4]; 
	
};

class CSkillEffect_p_mp_regen
{
	/*000*/	CSkillEffect_p_mp_regen *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_mp_regen() { pPointer = (CSkillEffect_p_mp_regen*)0x00AD9B18; };
	double var1;
	int var2;
	BYTE var3[4]; 
	
};





class CSkillEffect_p_speed
{
	/*000*/	CSkillEffect_p_speed *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_speed() { pPointer = (CSkillEffect_p_speed*)0x00AD9B78; };
	double var1;
	int var2;
	BYTE var3[4]; 
	
};

class CSkillEffect_p_create_item
{
	/*000*/	CSkillEffect_p_create_item *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_create_item() { pPointer = (CSkillEffect_p_create_item*)0x00AD9DB8; };
	/*028*/	int var1;
	int final; // NO USAR
};

class CSkillEffect_p_create_common_item
{
	/*000*/	CSkillEffect_p_create_common_item *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_create_common_item() { pPointer = (CSkillEffect_p_create_common_item*)0x00AD9E18; };
	/*028*/	int var1;
	int final; // NO USAR
};


class CSkillEffect_p_attack_speed
{
	/*000*/	CSkillEffect_p_attack_speed *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_attack_speed() { pPointer = (CSkillEffect_p_attack_speed*)0x00AD9BD8; };
	double var1;
	int var2;
	BYTE var3[4]; 
	
};

class CSkillEffect_p_magic_speed
{
	/*000*/	CSkillEffect_p_magic_speed *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_magic_speed() { pPointer = (CSkillEffect_p_magic_speed*)0x00AD9C38; };
	double var1;
	int var2;
	BYTE var3[4]; 
	
};

class CSkillEffect_p_remove_equip_penalty
{
	/*000*/	CSkillEffect_p_remove_equip_penalty *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_remove_equip_penalty() { pPointer = (CSkillEffect_p_remove_equip_penalty*)0x00AD9C98; };
	int var1;
	
};


class CSkillEffect_p_crystallize
{
	/*000*/	CSkillEffect_p_crystallize *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_crystallize() { pPointer = (CSkillEffect_p_crystallize*)0x00AD9CF8; };
	int var1;
	
};


class CSkillEffect_p_avoid
{
	/*000*/	CSkillEffect_p_avoid *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_avoid() { pPointer = (CSkillEffect_p_avoid*)0x00AD9E78; };
	double var1;
	int var2;
	BYTE var3[4]; 
	
};


class CSkillEffect_p_luck
{
	/*000*/	CSkillEffect_p_luck *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_luck() { pPointer = (CSkillEffect_p_luck*)0x00AD9D58; };
	
};


class CSkillEffect_p_magical_defence
{
	/*000*/	CSkillEffect_p_magical_defence *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_magical_defence() { pPointer = (CSkillEffect_p_magical_defence*)0x00AD9998; };
	double var1;
	int var2;
	BYTE var3[4]; 
	
};


class CSkillEffect_p_physical_attack_by_material : public CSkillEffect
{
public:
	int var1;
	int var2;
	
};

class CSkillEffect_p_physical_defence_by_material : public CSkillEffect
{
public:
	int var1;
	int var2;
	
};

class CSkillEffect_p_attack_attribute
{
	/*000*/	CSkillEffect_p_attack_attribute *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_attack_attribute() { pPointer = (CSkillEffect_p_attack_attribute*)0x00AD99F8; };
	/*010*/	int var1;
	int final; // NO USAR
};


class CSkillEffect_p_defence_attribute
{
	/*000*/	CSkillEffect_p_defence_attribute *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_defence_attribute() { pPointer = (CSkillEffect_p_defence_attribute*)0x00AD9A58; };
	/*010*/	int var1;
	/*018*/	double var2;
	int final; // NO USAR
};

class CSkillEffect_p_block_move
{
	/*000*/	CSkillEffect_p_block_move *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_block_move() { pPointer = (CSkillEffect_p_block_move*)0x00AD9F38; };
	
};


class CSkillEffect_p_block_act
{
	/*000*/	CSkillEffect_p_block_act *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_block_act() { pPointer = (CSkillEffect_p_block_act*)0x00AD9ED8; };
	
};

class CSkillEffect_p_block_controll
{
	/*000*/	CSkillEffect_p_block_controll *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_block_controll() { pPointer = (CSkillEffect_p_block_controll*)0x00AD9F98; };
	
};

class CSkillEffect_p_block_spell
{
	/*000*/	CSkillEffect_p_block_spell *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_block_spell() { pPointer = (CSkillEffect_p_block_spell*)0x00AD9FF8; };
	
};

class CSkillEffect_p_fear
{
	/*000*/	CSkillEffect_p_fear *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_fear() { pPointer = (CSkillEffect_p_fear*)0x00ADA058; };
	
};

class CSkillEffect_p_max_hp
{
	/*000*/	CSkillEffect_p_max_hp *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_max_hp() { pPointer = (CSkillEffect_p_max_hp*)0x00ADA0B8; };
	/*010*/	double var1;
	/*018*/	int var2;

	int final; // NO USAR
};


class CSkillEffect_p_max_mp
{
	/*000*/	CSkillEffect_p_max_mp *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_max_mp() { pPointer = (CSkillEffect_p_max_mp*)0x00ADA118; };
	/*010*/	double var1;
	/*018*/	int var2;

	int final; // NO USAR
};

class CSkillEffect_p_max_cp
{
	/*000*/	CSkillEffect_p_max_cp *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_max_cp() { pPointer = (CSkillEffect_p_max_cp*)0x00ADA178; };
	/*010*/	double var1;
	/*018*/	int var2;

	int final; // NO USAR
};


class CSkillEffect_p_hit	//0x28		40 en decimal
{
	/*000*/	CSkillEffect_p_hit *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_hit() { pPointer = (CSkillEffect_p_hit*)0x00ADA1D8; };
	/*010*/	double var2; 
	/*018*/	int var3;
	/*020*/	BYTE var4[10]; 
	int final; // NO USAR

};

class CSkillEffect_p_magical_attack	//0x28		40 en decimal
{
	/*000*/	CSkillEffect_p_magical_attack *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_magical_attack() { pPointer = (CSkillEffect_p_magical_attack*)0x00ADA238; };
	/*020*/	BYTE var1[10]; 
	/*010*/	double var2; 
	/*018*/	int var3;
};


class CSkillEffect_p_attack_range
{
	/*000*/	CSkillEffect_p_attack_range *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_attack_range() { pPointer = (CSkillEffect_p_attack_range*)0x00ADA298; };
	/*010*/	BYTE var1[10]; 
	/*020*/	double var2; 
	/*028*/	int var3;
	int final; // NO USAR
};

class CSkillEffect_p_critical_rate
{
	/*000*/	CSkillEffect_p_critical_rate *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_critical_rate() { pPointer = (CSkillEffect_p_critical_rate*)0x00ADA2F8; };
	/*010*/	double var1;
	/*018*/	int var2;

	int final; // NO USAR
};

class CSkillEffect_p_critical_damage
{
	/*000*/	CSkillEffect_p_critical_damage *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_critical_damage() { pPointer = (CSkillEffect_p_critical_damage*)0x00ADA358; };
	/*010*/	double var1;
	/*018*/	int var2;

	int final; // NO USAR
};


class CSkillEffect_p_reuse_delay
{
	/*000*/	CSkillEffect_p_reuse_delay *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_reuse_delay() { pPointer = (CSkillEffect_p_reuse_delay*)0x00ADA418; };
	/*018*/	int var1;
	/*010*/	double var2;
	/*018*/	int var3;
	int final; // NO USAR
};

class CSkillEffect_p_reduce_cancel
{
	/*000*/	CSkillEffect_p_reduce_cancel *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_reduce_cancel() { pPointer = (CSkillEffect_p_reduce_cancel*)0x00ADA478; };
	/*010*/	double var1;
	/*018*/	int var2;
	int final; // NO USAR
};


class CSkillEffect_p_attack_speed_by_weapon
{
	/*000*/	CSkillEffect_p_attack_speed_by_weapon *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_attack_speed_by_weapon() { pPointer = (CSkillEffect_p_attack_speed_by_weapon*)0x00ADA4D8; };
	/*010*/	BYTE var1[10]; 
	/*020*/	double var2; 
	/*028*/	int var3;
	int final; // NO USAR
};

class CSkillEffect_p_shield_defence_rate
{
	/*000*/	CSkillEffect_p_shield_defence_rate *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_shield_defence_rate() { pPointer = (CSkillEffect_p_shield_defence_rate*)0x00ADA538; };
	/*010*/	double var1; 
	int final; // NO USAR
};


class CSkillEffect_p_hp_regen_by_move_mode
{
	/*000*/	CSkillEffect_p_hp_regen_by_move_mode *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_hp_regen_by_move_mode() { pPointer = (CSkillEffect_p_hp_regen_by_move_mode*)0x00ADA598; };
	/*010*/	double var1; 
	int var2;
	int var3;

};

class CSkillEffect_p_mp_regen_by_move_mode
{
	/*000*/	CSkillEffect_p_mp_regen_by_move_mode *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_mp_regen_by_move_mode() { pPointer = (CSkillEffect_p_mp_regen_by_move_mode*)0x00ADA5F8; };
	/*010*/	double var1; 
	int var2;
	int var3;

};

class CSkillEffect_p_avoid_by_move_mode
{
	/*000*/	CSkillEffect_p_avoid_by_move_mode *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_avoid_by_move_mode() { pPointer = (CSkillEffect_p_avoid_by_move_mode*)0x00ADA3B8; };
	/*010*/	double var1; 
	int var2;
	int var3;

};


class CSkillEffect_p_safe_fall_height
{
	/*000*/	CSkillEffect_p_safe_fall_height *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_safe_fall_height() { pPointer = (CSkillEffect_p_safe_fall_height*)0x00ADA658; };
	/*010*/	double var1; 
	int var2;
	int final; // NO USAR
};


class CSkillEffect_p_breath
{
	/*000*/	CSkillEffect_p_breath *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_breath() { pPointer = (CSkillEffect_p_breath*)0x00ADA6B8; };
	/*010*/	double var1; 
	int var2;
	int final; // NO USAR
};



class CSkillEffect_p_damage_shield
{
	/*000*/	CSkillEffect_p_damage_shield *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_damage_shield() { pPointer = (CSkillEffect_p_damage_shield*)0x00ADA718; };
	/*010*/	double var1; 
	int final; // NO USAR
};

class CSkillEffect_p_passive
{
	/*000*/	CSkillEffect_p_passive *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_passive() { pPointer = (CSkillEffect_p_passive*)0x00ADA778; };
	
};

class CSkillEffect_p_avoid_agro
{
	/*000*/	CSkillEffect_p_avoid_agro *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_avoid_agro() { pPointer = (CSkillEffect_p_avoid_agro*)0x00ADA7D8; };
	/*010*/	int var1; 
	int final; // NO USAR
};


class CSkillEffect_p_weight_limit
{
	/*000*/	CSkillEffect_p_weight_limit *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_weight_limit() { pPointer = (CSkillEffect_p_weight_limit*)0x00ADA838; };
	/*010*/	double var1; 
	/*018*/	int var2; 
	int final; // NO USAR
};


class CSkillEffect_p_trade
{
	/*000*/	CSkillEffect_p_trade *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_trade() { pPointer = (CSkillEffect_p_trade*)0x00ADA898; };
	/*010*/	double var1; 
	/*010*/	double var2; 
	/*010*/	double var3; 
	/*010*/	double var4; 
	/*010*/	double var5; 
	/*010*/	double var6; 

	int final; // NO USAR
};


class CSkillEffect_p_set_collected	//OK
{
	/*000*/	CSkillEffect_p_set_collected *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_set_collected() { pInstance = (CSkillEffect_p_set_collected*)0x00ADA8F8; };
	int var1;
};

class CSkillEffect_p_cubic_mastery	//OK
{
	/*000*/	CSkillEffect_p_cubic_mastery *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_cubic_mastery() { pInstance = (CSkillEffect_p_cubic_mastery*)0x00ADA958; };
	int var1;
};


class CSkillEffect_p_weight_penalty	//OK
{
	/*000*/	CSkillEffect_p_weight_penalty *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_weight_penalty() { pInstance = (CSkillEffect_p_weight_penalty*)0x00ADA9B8; };
	int var1;
};

class CSkillEffect_p_mana_charge	//OK
{
	/*000*/	CSkillEffect_p_mana_charge *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_mana_charge() { pInstance = (CSkillEffect_p_mana_charge*)0x00ADAA18; };
	int var1;
};

class CSkillEffect_p_transfer_damage_summon	//OK
{
	/*000*/	CSkillEffect_p_transfer_damage_summon *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_transfer_damage_summon() { pInstance = (CSkillEffect_p_transfer_damage_summon*)0x00ADAA78; };
	int var1;
};


class CSkillEffect_p_heal_effect	//OK
{
	/*000*/	CSkillEffect_p_heal_effect *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_heal_effect() { pInstance = (CSkillEffect_p_heal_effect*)0x00ADAAD8; };
	double var1;
	int var2;
};

class CSkillEffect_p_area_damage	//OK
{
	/*000*/	CSkillEffect_p_area_damage *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_area_damage() { pInstance = (CSkillEffect_p_area_damage*)0x00ADAB38; };
	double var1;
	int var2;
};

class CSkillEffect_p_hit_at_night	//OK
{
	/*000*/	CSkillEffect_p_hit_at_night *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_hit_at_night() { pInstance = (CSkillEffect_p_hit_at_night*)0x00ADAB98; };
	double var1;
	int var2;
};

class CSkillEffect_p_2h_sword_bonus	//OK
{
	/*000*/	CSkillEffect_p_2h_sword_bonus *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_2h_sword_bonus() { pInstance = (CSkillEffect_p_2h_sword_bonus*)0x00ADABF8; };
	double var1;
	int var2;
	double var3;
	int var4;
};

class CSkillEffect_p_2h_blunt_bonus	//OK
{
	/*000*/	CSkillEffect_p_2h_blunt_bonus *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_2h_blunt_bonus() { pInstance = (CSkillEffect_p_2h_blunt_bonus*)0x00ADAC58; };
	double var1;
	int var2;
	double var3;
	int var4;
};

class CSkillEffect_p_vampiric_attack	//OK
{
	/*000*/	CSkillEffect_p_vampiric_attack *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_vampiric_attack() { pInstance = (CSkillEffect_p_vampiric_attack*)0x00ADACB8; };
	double var1;

};

class CSkillEffect_p_critical_rate_by_hp1	//OK
{
	/*000*/	CSkillEffect_p_critical_rate_by_hp1 *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_critical_rate_by_hp1() { pInstance = (CSkillEffect_p_critical_rate_by_hp1*)0x00ADAD18; };
	double var1;
	int var2;
};

class CSkillEffect_p_critical_rate_by_hp2	//OK
{
	/*000*/	CSkillEffect_p_critical_rate_by_hp2 *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_critical_rate_by_hp2() { pInstance = (CSkillEffect_p_critical_rate_by_hp2*)0x00ADAD78; };
	double var1;
	int var2;
};

class CSkillEffect_p_physical_attack_by_hp1	//OK
{
	/*000*/	CSkillEffect_p_physical_attack_by_hp1 *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_physical_attack_by_hp1() { pInstance = (CSkillEffect_p_physical_attack_by_hp1*)0x00ADADD8; };
	double var1;
	int var2;
};

class CSkillEffect_p_physical_attack_by_hp2	//OK
{
	/*000*/	CSkillEffect_p_physical_attack_by_hp2 *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_physical_attack_by_hp2() { pInstance = (CSkillEffect_p_physical_attack_by_hp2*)0x00ADAE38; };
	double var1;
	int var2;
};

class CSkillEffect_p_physical_defence_by_hp1	//OK
{
	/*000*/	CSkillEffect_p_physical_defence_by_hp1 *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_physical_defence_by_hp1() { pInstance = (CSkillEffect_p_physical_defence_by_hp1*)0x00ADAE98; };
	double var1;
	int var2;
};

class CSkillEffect_p_physical_defence_by_hp2	//OK
{
	/*000*/	CSkillEffect_p_physical_defence_by_hp2 *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_physical_defence_by_hp2() { pInstance = (CSkillEffect_p_physical_defence_by_hp2*)0x00ADAEF8; };
	double var1;
	int var2;
};

class CSkillEffect_p_avoid_rate_by_hp1	//OK
{
	/*000*/	CSkillEffect_p_avoid_rate_by_hp1 *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_avoid_rate_by_hp1() { pInstance = (CSkillEffect_p_avoid_rate_by_hp1*)0x00ADAF58; };
	double var1;
	int var2;
};

class CSkillEffect_p_avoid_rate_by_hp2	//OK
{
	/*000*/	CSkillEffect_p_avoid_rate_by_hp2 *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_avoid_rate_by_hp2() { pInstance = (CSkillEffect_p_avoid_rate_by_hp2*)0x00ADAFB8; };
	double var1;
	int var2;
};

class CSkillEffect_p_attack_speed_by_hp1	//OK
{
	/*000*/	CSkillEffect_p_attack_speed_by_hp1 *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_attack_speed_by_hp1() { pInstance = (CSkillEffect_p_attack_speed_by_hp1*)0x00ADB018; };
	double var1;
	int var2;
};

class CSkillEffect_p_attack_speed_by_hp2	//OK
{
	/*000*/	CSkillEffect_p_attack_speed_by_hp2 *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_attack_speed_by_hp2() { pInstance = (CSkillEffect_p_attack_speed_by_hp2*)0x00ADB078; };
	double var1;
	int var2;
};

class CSkillEffect_p_fatal_blow_rate	//OK
{
	/*000*/	CSkillEffect_p_fatal_blow_rate *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_fatal_blow_rate() { pInstance = (CSkillEffect_p_fatal_blow_rate*)0x00ADB0D8; };
	double var1;
	int var2;
};

class CSkillEffect_p_critical_rate_position_bonus	//OK
{
	/*000*/	CSkillEffect_p_critical_rate_position_bonus *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_critical_rate_position_bonus() { pInstance = (CSkillEffect_p_critical_rate_position_bonus*)0x00ADB138; };
	int var1;
	double var2;
	int var3;
};

class CSkillEffect_p_showtime	//OK
{
	/*000*/	CSkillEffect_p_showtime *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_showtime() { pInstance = (CSkillEffect_p_showtime*)0x00ADB198; };
};

class CSkillEffect_p_sound	//OK
{
	/*000*/	CSkillEffect_p_sound *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_sound() { pInstance = (CSkillEffect_p_sound*)0x00ADB1F8; };
};

class CSkillEffect_p_see_my_heart	//OK
{
	/*000*/	CSkillEffect_p_see_my_heart *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_see_my_heart() { pInstance = (CSkillEffect_p_see_my_heart*)0x00ADB258; };
};

class CSkillEffect_p_reduce_drop_penalty	//OK
{
	/*000*/	CSkillEffect_p_reduce_drop_penalty *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_reduce_drop_penalty() { pInstance = (CSkillEffect_p_reduce_drop_penalty*)0x00ADB438; };
};

class CSkillEffect_p_physical_shield_defence_angle_all	//OK
{
	/*000*/	CSkillEffect_p_physical_shield_defence_angle_all *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_physical_shield_defence_angle_all() { pInstance = (CSkillEffect_p_physical_shield_defence_angle_all*)0x00ADB498; };
};

class CSkillEffect_p_magic_mp_cost	//OK
{
	/*000*/	CSkillEffect_p_magic_mp_cost *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_magic_mp_cost() { pInstance = (CSkillEffect_p_magic_mp_cost*)0x00ADB4F8; };
	double var1;
	int var2;
	int var3;
};

class CSkillEffect_p_magic_critical_rate	//OK
{
	/*000*/	CSkillEffect_p_magic_critical_rate *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_magic_critical_rate() { pInstance = (CSkillEffect_p_magic_critical_rate*)0x00ADB558; };
	double var1;
	int var2;
};

class CSkillEffect_p_pvp_physical_attack_dmg_bonus	//OK
{
	/*000*/	CSkillEffect_p_pvp_physical_attack_dmg_bonus *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_pvp_physical_attack_dmg_bonus() { pInstance = (CSkillEffect_p_pvp_physical_attack_dmg_bonus*)0x00ADB618; };
	int var1;
	int var2;
};

class CSkillEffect_p_pvp_physical_skill_dmg_bonus	//OK
{
	/*000*/	CSkillEffect_p_pvp_physical_skill_dmg_bonus *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_pvp_physical_skill_dmg_bonus() { pInstance = (CSkillEffect_p_pvp_physical_skill_dmg_bonus*)0x00ADB678; };
	int var1;
	int var2;
};

class CSkillEffect_p_pvp_magical_skill_dmg_bonus	//OK
{
	/*000*/	CSkillEffect_p_pvp_magical_skill_dmg_bonus *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_pvp_magical_skill_dmg_bonus() { pInstance = (CSkillEffect_p_pvp_magical_skill_dmg_bonus*)0x00ADB6D8; };
	int var1;
	int var2;
};



class CSkillEffect_p_physical_armor_hit
{
	/*000*/	CSkillEffect_p_physical_armor_hit *pPointer;
	/*008*/ LPVOID pUnkn001;
public:
	CSkillEffect_p_physical_armor_hit() { pPointer = (CSkillEffect_p_physical_armor_hit*)0x00ADB5B8; };
	double var1;
	int var2;
	BYTE var3[4]; 
	
};


class CSkillEffect_p_physical_shield_defence	//OK
{
	/*000*/	CSkillEffect_p_physical_shield_defence *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_physical_shield_defence() { pInstance = (CSkillEffect_p_physical_shield_defence*)0x00ADB738; };
	int var1;
	int var2;
};

class CSkillEffect_p_physical_polarm_target_single	//OK
{
	/*000*/	CSkillEffect_p_physical_polarm_target_single *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_physical_polarm_target_single() { pInstance = (CSkillEffect_p_physical_polarm_target_single*)0x00ADB798; };
};

class CSkillEffect_p_fishing_mastery	//OK
{
	/*000*/	CSkillEffect_p_fishing_mastery *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_fishing_mastery() { pInstance = (CSkillEffect_p_fishing_mastery*)0x00ADC4E8; };
	double var1;
};

class CSkillEffect_p_abnormal_rate_limit	//OK
{
	/*000*/	CSkillEffect_p_abnormal_rate_limit *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_abnormal_rate_limit() { pInstance = (CSkillEffect_p_abnormal_rate_limit*)0x00ADB7F8; };
};

class CSkillEffect_p_abnormal_remove_by_hit	//OK
{
	/*000*/	CSkillEffect_p_abnormal_remove_by_hit *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_abnormal_remove_by_hit() { pInstance = (CSkillEffect_p_abnormal_remove_by_hit*)0x00ADB858; };
	int var1;
	int var2;
};

class CSkillEffect_p_abnormal_remove_by_dmg	//OK
{
	/*000*/	CSkillEffect_p_abnormal_remove_by_dmg *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_abnormal_remove_by_dmg() { pInstance = (CSkillEffect_p_abnormal_remove_by_dmg*)0x00ADB8B8; };
	int var1;
};

class CSkillEffect_p_block_skill_physical	//OK
{
	/*000*/	CSkillEffect_p_block_skill_physical *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_block_skill_physical() { pInstance = (CSkillEffect_p_block_skill_physical*)0x00ADB918; };
};

class CSkillEffect_p_block_skill_special	//OK
{
	/*000*/	CSkillEffect_p_block_skill_special *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_block_skill_special() { pInstance = (CSkillEffect_p_block_skill_special*)0x00ADB978; };
};

class CSkillEffect_p_block_buff	//OK
{
	/*000*/	CSkillEffect_p_block_buff *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_block_buff() { pInstance = (CSkillEffect_p_block_buff*)0x00ADB9D8; };
};

class CSkillEffect_p_block_debuff	//OK
{
	/*000*/	CSkillEffect_p_block_debuff *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_block_debuff() { pInstance = (CSkillEffect_p_block_debuff*)0x00ADBA38; };
};

class CSkillEffect_p_reflect_skill	//OK
{
	/*000*/	CSkillEffect_p_reflect_skill *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_reflect_skill() { pInstance = (CSkillEffect_p_reflect_skill*)0x00ADBA98; };
	int var1;
	int var2;
};

class CSkillEffect_p_skill_critical	//OK
{
	/*000*/	CSkillEffect_p_skill_critical *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_skill_critical() { pInstance = (CSkillEffect_p_skill_critical*)0x00ADBAF8; };
	int var1;
};

class CSkillEffect_p_skill_critical_probability	//OK
{
	/*000*/	CSkillEffect_p_skill_critical_probability *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_skill_critical_probability() { pInstance = (CSkillEffect_p_skill_critical_probability*)0x00ADBB58; };
	int var1;
	int var2;
};

class CSkillEffect_p_critical_damage_position	//OK
{
	/*000*/	CSkillEffect_p_critical_damage_position *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_critical_damage_position() { pInstance = (CSkillEffect_p_critical_damage_position*)0x00ADBBB8; };
	int var1;
	int var2;
	int var3;
};

class CSkillEffect_p_resist_dispel_by_category	//OK
{
	/*000*/	CSkillEffect_p_resist_dispel_by_category *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_resist_dispel_by_category() { pInstance = (CSkillEffect_p_resist_dispel_by_category*)0x00ADBC18; };
	int var1;
	int var2;
	int var3;
};

class CSkillEffect_p_resist_abnormal_by_category	//OK
{
	/*000*/	CSkillEffect_p_resist_abnormal_by_category *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_resist_abnormal_by_category() { pInstance = (CSkillEffect_p_resist_abnormal_by_category*)0x00ADBC78; };
	int var1;
	int var2;
	int var3;
};

class CSkillEffect_p_preserve_abnormal	//OK
{
	/*000*/	CSkillEffect_p_preserve_abnormal *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_preserve_abnormal() { pInstance = (CSkillEffect_p_preserve_abnormal*)0x00ADBCD8; };
};

class CSkillEffect_p_enlarge_storage	//OK
{
	/*000*/	CSkillEffect_p_enlarge_storage *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_enlarge_storage() { pInstance = (CSkillEffect_p_enlarge_storage*)0x00ADBD38; };
	int var1;
	int var2;
};

class CSkillEffect_p_hit_number	//OK
{
	/*000*/	CSkillEffect_p_hit_number *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_hit_number() { pInstance = (CSkillEffect_p_hit_number*)0x00ADBD98; };
	int var1;
	int var2;
};

class CSkillEffect_p_cub_physical_attack	//OK
{
	/*000*/	CSkillEffect_p_cub_physical_attack *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_cub_physical_attack() { pInstance = (CSkillEffect_p_cub_physical_attack*)0x00ADB2B8; };
	double var1;
	int var2;
};

class CSkillEffect_p_cub_physical_defence	//OK
{
	/*000*/	CSkillEffect_p_cub_physical_defence *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_cub_physical_defence() { pInstance = (CSkillEffect_p_cub_physical_defence*)0x00ADB318; };
	double var1;
	int var2;
};

class CSkillEffect_p_cub_attack_speed	//OK
{
	/*000*/	CSkillEffect_p_cub_attack_speed *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_cub_attack_speed() { pInstance = (CSkillEffect_p_cub_attack_speed*)0x00ADB378; };
	double var1;
	int var2;
};

class CSkillEffect_p_cub_block_act	//OK
{
	/*000*/	CSkillEffect_p_cub_block_act *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_p_cub_block_act() { pInstance = (CSkillEffect_p_cub_block_act*)0x00ADB3D8; };
};





class CSkillEffect_c_mp	//OK
{
	/*000*/	CSkillEffect_c_mp *pInstance;

public:
	int var_a1;
	int var_a2;

	CSkillEffect_c_mp() { pInstance = (CSkillEffect_c_mp*)0x00ADBF78; };
	int var1;
};

class CSkillEffect_c_hp	//OK
{
	/*000*/	CSkillEffect_c_hp *pInstance;

public:
	int var_a1;
	int var_a2;

	CSkillEffect_c_hp() { pInstance = (CSkillEffect_c_hp*)0x00ADBFD8; };
	int var1;
};

class CSkillEffect_c_rest	//OK
{
	/*000*/	CSkillEffect_c_rest *pInstance;

public:
	int var_a1;
	int var_a2;

	CSkillEffect_c_rest() { pInstance = (CSkillEffect_c_rest*)0x00ADC038; };
	int var1;
};


class CSkillEffect_c_chameleon_rest	//OK
{
	/*000*/	CSkillEffect_c_chameleon_rest *pInstance;

public:
	int var_a1;
	int var_a2;

	CSkillEffect_c_chameleon_rest() { pInstance = (CSkillEffect_c_chameleon_rest*)0x00ADC098; };
	int var1;
};

class CSkillEffect_c_mp_by_level	//OK
{
	/*000*/	CSkillEffect_c_mp_by_level *pInstance;

public:
	int var_a1;
	int var_a2;

	CSkillEffect_c_mp_by_level() { pInstance = (CSkillEffect_c_mp_by_level*)0x00ADC0F8; };
	int var1;
};

class CSkillEffect_c_fake_death	//OK
{
	/*000*/	CSkillEffect_c_fake_death *pInstance;

public:
	int var_a1;
	int var_a2;

	CSkillEffect_c_fake_death() { pInstance = (CSkillEffect_c_fake_death*)0x00ADC158; };
	int var1;
};





class CSkillEffect_i_summon_pet	//OK
{
	/*000*/	CSkillEffect_i_summon_pet *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_summon_pet() { pInstance = (CSkillEffect_i_summon_pet*)0x00ADC1E8; };
};

class CSkillEffect_i_food_for_pet	//OK
{
	/*000*/	CSkillEffect_i_food_for_pet *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_food_for_pet() { pInstance = (CSkillEffect_i_food_for_pet*)0x00ADC248; };
	int var1;
	int var2;
	int var3;
};

class CSkillEffect_i_hp	//OK
{
	/*000*/	CSkillEffect_i_hp *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_hp() { pInstance = (CSkillEffect_i_hp*)0x00AD7E38; };
	double var1;
	int var2;
};

class CSkillEffect_i_mp	//OK
{
	/*000*/	CSkillEffect_i_mp *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_mp() { pInstance = (CSkillEffect_i_mp*)0x00AD7EF8; };
	double var1;
	int var2;
};

class CSkillEffect_i_resurrection	//OK
{
	/*000*/	CSkillEffect_i_resurrection *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_resurrection() { pInstance = (CSkillEffect_i_resurrection*)0x00AD7FB8; };
	int var1;
};

class CSkillEffect_i_inform	//OK
{
	/*000*/	CSkillEffect_i_inform *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_inform() { pInstance = (CSkillEffect_i_inform*)0x00AD7F58; };
};


class CSkillEffect_i_cp	//OK
{
	/*000*/	CSkillEffect_i_cp *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_cp() { pInstance = (CSkillEffect_i_cp*)0x00AD93F8; };
	int var1;
	int var2;
};

class CSkillEffect_i_sp	//OK
{
	/*000*/	CSkillEffect_i_sp *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_sp() { pInstance = (CSkillEffect_i_sp*)0x00AD9458; };
	int var1;
	int var2;
};


class CSkillEffect_i_physical_attack_hp_link	//OK
{
	/*000*/	CSkillEffect_i_physical_attack_hp_link *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_physical_attack_hp_link() { pInstance = (CSkillEffect_i_physical_attack_hp_link*)0x00AD94B8; };
	double var1;
};

class CSkillEffect_i_m_attack_by_hp	//OK
{
	/*000*/	CSkillEffect_i_m_attack_by_hp *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_m_attack_by_hp() { pInstance = (CSkillEffect_i_m_attack_by_hp*)0x00AD7D18; };
	double var1;
};

class CSkillEffect_i_m_attack_by_dist	//OK
{
	/*000*/	CSkillEffect_i_m_attack_by_dist *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_m_attack_by_dist() { pInstance = (CSkillEffect_i_m_attack_by_dist*)0x00AD7D78; };
	double var1;
};

class CSkillEffect_i_fishing_cast	//OK
{
	/*000*/	CSkillEffect_i_fishing_cast *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_fishing_cast() { pInstance = (CSkillEffect_i_fishing_cast*)0x00ADC368; };
};


class CSkillEffect_i_fishing_pumping	//OK
{
	/*000*/	CSkillEffect_i_fishing_pumping *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_fishing_pumping() { pInstance = (CSkillEffect_i_fishing_pumping*)0x00ADC3C8; };
	double var1;
};

class CSkillEffect_i_fishing_reeling	//OK
{
	/*000*/	CSkillEffect_i_fishing_reeling *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_fishing_reeling() { pInstance = (CSkillEffect_i_fishing_reeling*)0x00ADC428; };
	double var1;
};

class CSkillEffect_i_fishing_shot	//OK
{
	/*000*/	CSkillEffect_i_fishing_shot *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_fishing_shot() { pInstance = (CSkillEffect_i_fishing_shot*)0x00ADC488; };
	double var1;
};

class CSkillEffect_i_open_dwarf_recipebook	//OK
{
	/*000*/	CSkillEffect_i_open_dwarf_recipebook *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_open_dwarf_recipebook() { pInstance = (CSkillEffect_i_open_dwarf_recipebook*)0x00ADC2A8; };
};

class CSkillEffect_i_open_common_recipebook	//OK
{
	/*000*/	CSkillEffect_i_open_common_recipebook *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_open_common_recipebook() { pInstance = (CSkillEffect_i_open_common_recipebook*)0x00ADC308; };
};

class CSkillEffect_i_dispel_by_category	//OK
{
	/*000*/	CSkillEffect_i_dispel_by_category *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_dispel_by_category() { pInstance = (CSkillEffect_i_dispel_by_category*)0x00AD9518; };
	int var1;
	int var2;
};

class CSkillEffect_i_align_direction	//OK
{
	/*000*/	CSkillEffect_i_align_direction *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_align_direction() { pInstance = (CSkillEffect_i_align_direction*)0x00AD9578; };
};


class CSkillEffect_i_death	//OK
{
	/*000*/	CSkillEffect_i_death *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_death() { pInstance = (CSkillEffect_i_death*)0x00AD95D8; };
	int var1;
};

class CSkillEffect_i_rebalance_hp	//OK
{
	/*000*/	CSkillEffect_i_rebalance_hp *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_rebalance_hp() { pInstance = (CSkillEffect_i_rebalance_hp*)0x00AD9638; };
	int var1;
};

class CSkillEffect_i_rebalance_mp	//OK
{
	/*000*/	CSkillEffect_i_rebalance_mp *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_rebalance_mp() { pInstance = (CSkillEffect_i_rebalance_mp*)0x00AD9698; };
	int var1;
};

class CSkillEffect_i_target_cancel	//OK
{
	/*000*/	CSkillEffect_i_target_cancel *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_target_cancel() { pInstance = (CSkillEffect_i_target_cancel*)0x00AD96F8; };
};

class CSkillEffect_i_target_me	//OK
{
	/*000*/	CSkillEffect_i_target_me *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_target_me() { pInstance = (CSkillEffect_i_target_me*)0x00AD9758; };
};

class CSkillEffect_i_teleport	//OK
{
	/*000*/	CSkillEffect_i_teleport *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_teleport() { pInstance = (CSkillEffect_i_teleport*)0x00AE22E8; };
	double var1;
	double var2;
	double var3;
};

class CSkillEffect_i_install_camp_ex	//OK
{
	/*000*/	CSkillEffect_i_install_camp_ex *pInstance;
	/*008*/ LPVOID pUnkn008;

public:
	CSkillEffect_i_install_camp_ex() { pInstance = (CSkillEffect_i_install_camp_ex*)0x00AD97B8; };
};
