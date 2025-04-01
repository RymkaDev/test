#ifndef TVT_H
#define TVT_H
#include "TvTMatch.h"

namespace TvT
{
	class CTvT : public CThreadSafe
	{
	private:
		BOOL m_enabled;
		list<TvT::TvTInfo*> m_tvtInfo;
		
		TvT::CMatch* m_lpEvent;

		void LoadINI();
	public:

		BOOL m_SumarPvPReward;

		CTvT();
		~CTvT();
		void Init();
		void TimerExpired();
		void OnExit(User *pUser);
		void Register(User *pUser, int team);
		void Unregister(User *pUser);
		void OnDie(User *pUser, CCreature *pKiller);
		void OnNpcSpawn(CNPC *pNpc);	//NotUsed
		void TimerExpired(User *pUser);
		bool CanUse(CItem *pItem);
		void ValidateItems(User *pUser);
		bool IsSkillBlocked(INT32 skillId);
		inline int GetSkillId() { return m_lpEvent->m_lpInfo->korean_skillid; };
		void ApplyProtectionSkill(User *pUser);
		void RemoveProtectionSkill(User *pUser);
		void GiveBuffsToPlayer(User *pUser);
		void CheckPlayerLogin(User *pUser);
		bool PickPlayersForMatchKorean();
		void NPCAction(User *pUser);
		void NPCActionBlueFlag(User *pUser);
		void NPCActionRedFlag(User *pUser);
		void ShowHtml(User *pUser, const WCHAR* filename);

		void IniciarEventoManual(User* pUser, int Id);
		void FinalizarEventoManual(bool ValidateWinner);

		bool IsCtfNpcFlag(User*pUser, UINT nTargetObjId);
		void IsCtfEventMoveBackGround(User* pUser, UINT nTargetObjId);
		bool CtfUseWeapon(User*pUser, CItem* pItem);
		void IsNpcDestroyTheBaseDIE(UINT nObjId);
		bool IsNpcDestroyTheBaseTeam(User* pUser, UINT nObjId);
		void NpcDestroyTheBaseSetHP(CNPC* pNPC);

		void FortressTeleports();
		void FortressApplySkill(User *pUser);
		void FortressRemoveSkill(User *pUser);
		void FortressCastCrystal(User* pUser, UINT nTargetObjId, INT32 nSkillId);
		int FortressGetSkill();
		int FortressGetNpcObject();
	};
};

extern TvT::CTvT g_TvT;

#endif
