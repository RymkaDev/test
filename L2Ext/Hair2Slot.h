#pragma once


enum ESlotType : char {
	ST_UNDERWEAR = 0,
	ST_REAR = 1,
	ST_LEAR = 2,
	ST_NECK = 3,
	ST_RFINGER = 4,
	ST_LFINGER = 5,
	ST_HEAD = 6,
	ST_RHAND = 7,
	ST_LHAND = 8,
	ST_GLOVES = 9,
	ST_CHEST = 10,
	ST_LEGS = 11,
	ST_FEET = 12,
	ST_BACK = 13,
	ST_RLHAND = 14,
	ST_ONEPIECE = 15,
	ST_HAIR = 16,
	ST_ALLDRESS = 17,
	ST_HAIR2 = 18,
	ST_HAIRALL = 19,
	ST_Max = 20
};

//#define EXT_USER_PUBLIC_METHOD_DECL\
//	char ExtUnequipItem(ESlotType nSlotType);\
//	char UnequipItem(CItem* pItem);\

inline void ExtThreadSafe(CItem* item) {
	typedef void (*f)(CItem* pItem, const char*, int);
	f(0xA07CF8L)(item, "ExtThreadSafe", 0);
}

class Hair2Slot {
public:
	static void Initialize();

	static void PostInit();
	
	static bool UnequipItemPacket(CUserSocket*, const unsigned char*);

	static bool UnequipItem(::User* pUser, int nSlotIndex);

	static bool UnequipItem(::User* pUser, CItem* pItem);

	static bool LoadSelectedCharacterPacket(void*, const unsigned char*);

	static void GetDataBaseEquipID(::User*, int&, int&, int&);

	static void GetUserPaperDollID(::User*, int&, int&, int& , int&);
	
	static void GetItemIDCharInfo(::User*, int&, int&, int&);

	static void Hair2Slot::HookCreatePet(void* table, ::User* pUser, void* pet);

	class User {
	public:

		static char UnequipItem(::User* pUser, CItem* pItem);

		static int EquipItem(::User* pUser, CItem* pItem, int nSlotIndex);

		//
		static int UnequipItem2(::User* pUser, CItem*);
		
		static int UnequipItem2(::User* pUser, int nSlotType);

		static bool EquipItem2(::User*, CItem*, int);
	};

	class CCreature {
	public:

		static int UseItem(::CCreature*, CItem* pItem, bool nForce);

		static int EquipItem(::User* pUser, CItem* pItem, int nSlotIndex);

		static int IsEquiped(::CCreature*, int, int);

		//NOTE this argument as User hook call in User::EquipItem method
		static int EquipItem2(::User*, CItem*, int);

		static int UnequipItem(::CCreature*, CItem* pItem);

		//
		static inline void ValidateAllOnWeapon(::CCreature* pCreature) {
			typedef char (*f)(::CCreature*);
			f(0x516FE0)(pCreature);
		}

		static inline void ValidateAllOnArmors(::CCreature* pCreature) {
			typedef char (*f)(::CCreature*);
			f(0x5172A0)(pCreature);
		}

		static inline void ValidateAttachedSkills(::CCreature* pCreature) {
			typedef char (*f)(::CCreature*);
			f(0x5173F0)(pCreature);
		}

		static inline void ValidateAllOnSIM(::CCreature* pCreature) {
			typedef char (*f)(::CCreature*);
			f(0x4FFDC0)(pCreature);
		}
	};

	class CInventory {
	public:
		static inline char LockItemIndex(::CInventory& inventory, int nItemIndex) {
			typedef char (*f)(::CInventory*, int);
			return f(0x6119D0)(&inventory, nItemIndex);
		}
	};


};