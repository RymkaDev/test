#include "CachedExt.h"
#pragma comment(lib, "Ws2_32.lib")

void Debug()
{
	g_Log.Add(CLog::Error, "[%s] HERE1", __FUNCTION__);
}

DWORD _DECRYPT_ASM_CALL = 0x00463330;
DWORD _CLOG_ASM_CALL = 0x00447150;
DWORD _MemMove1_ASM_CALL = 0x004DA0A0;
DWORD _MemMove2_ASM_CALL = 0x004D8A20;
DWORD _VAssemble = 0x0043E150;
DWORD _CIOBufferAlloc = 0x0043E730;
DWORD _CriticalSectionLock = 0x004422F0;
DWORD _CIOSocket__Write_C1 = 0x0043FC00;
DWORD _CIOBuffer__Alloc_C1 = 0x0043E730l;
DWORD _InternalSocketAssemble = 0x004D9178;

void __declspec(naked) ReallocateIOBuffer1_IN()
{
	__asm
	{
		lea     eax, [edx+eax+2040h]
		lea     ecx, [esi+38h]
		push    ecx             ; lpOverlapped
		lea     edx, [esp+1Ch]
		push    edx             ; lpFlags
		mov     edx, [esi+14h]
		mov     [esp+2Ch], eax
		lea     eax, [esp+24h]
		push    eax             ; lpNumberOfBytesRecvd
		mov		eax, 43F99Bh
		jmp     eax
	}
}

void __declspec(naked) ReallocateIOBuffer2_IN()
{
	__asm
	{
		movzx   eax, byte ptr [edi+ebp+2041h]
		movzx   ebp, byte ptr [edi+ebp+2040h]
		shl     eax, 8
		lea     eax, [eax+ebp-2]
		test    eax, eax
		
		mov     [esi+0F4h], eax
		jle     004672ACh
		cmp     eax, 4000h
		jge     004672ACh

		mov		eax, 467091h ;mby here crash?
		jmp     eax
	}
}


void __declspec(naked) ReallocateIOBuffer3_IN()
{
	__asm
	{
		lea     ebx, [edi+ebp+2040h]
		push    ebx
		
		call    _DECRYPT_ASM_CALL
		mov     eax, [esi+0F4h]
		cdq
		add     esp, 10h
		add     [esi+100h], eax
		adc     [esi+104h], edx
		cmp     dword ptr [esi+0B0h], 56CE48h
		jnz     467134h

		lea     edx, [eax+edi+2040h]
		lea     ecx, [edx+ebp]
		movzx   edx, byte ptr [ecx-1]
		movzx   ecx, byte ptr [ecx-2]
		shl     edx, 8
		lea     ecx, [edx+ecx-2]
		cmp     ecx, eax
		jnz     4672D6h

		mov		eax, 467134h
		jmp     eax

	}
}

void __declspec(naked) ReallocateIOBuffer4_IN()
{
	__asm
	{
		lea     edi, [ecx+eax+2040h]

		mov		ebx, 4401A0h
		jmp     ebx
	}
}


void __declspec(naked) ReallocateIOBuffer5_IN()
{
	__asm
	{
		movzx   eax, byte ptr [ebx+ebp+2041h]
		movzx   edi, byte ptr [ebx+ebp+2040h]
		shl     eax, 8
		lea     eax, [eax+edi-2]
		mov     [esi+0F4h], eax
		movzx   eax, byte ptr [ebx+ebp+2041h]
		movzx   edi, byte ptr [ebx+ebp+2040h]
		shl     eax, 8
		lea     eax, [eax+edi-2]
		test    eax, eax
		mov     [esi+0F4h], eax
		jle     44DF5Ch
		cmp     eax, 4000h
		jge     44DF5Ch

		mov		ebp, 44DDE8h
		jmp     ebp
	}
}


void __declspec(naked) ReallocateIOBuffer6_IN()
{
	__asm
	{
		movzx   eax, byte ptr [edi+ebp+2040h]
		push    edx
		push    eax
		mov		eax, 4672E0h
		jmp     eax
	}
}

void __declspec(naked) ReallocateIOBuffer7_IN()
{
	__asm
	{
		lea     ebx, [ebx+ebp+2040h]
		push    ebx
		call    _DECRYPT_ASM_CALL
		mov     eax, [esi+0F4h]
		cdq
		add     esp, 10h
		add     [esi+100h], eax
		adc     [esi+104h], edx
		cmp     byte ptr [ebx], 0Bh
		jnb     44DF7Ch

		mov		ecx, 44DE64h
		jmp		ecx
	}
}

void __declspec(naked) ReallocateIOBuffer8_IN()
{
	__asm
	{
		movzx   eax, byte ptr [edx+edi+2041h]
		movzx   edi, byte ptr [edx+edi+2040h]
		shl     eax, 8
		lea     eax, [eax+edi-2]
		test    eax, eax
		mov     [esi+7Ch], eax
		jle     447DB7h
		
		mov		ecx, 447C8Eh
		jmp     ecx
	}
}

void __declspec(naked) ReallocateIOBuffer9_IN()
{
	__asm
	{
		cmp     byte ptr [edx+edi+2040h], 3
		jnb     447E35h

		mov		ecx, 447CC8h
		jmp		ecx
	}
}

void __declspec(naked) ReallocateIOBuffer10_IN()
{
	__asm
	{
		movzx   edx, byte ptr [ecx+edi+2040h]

		mov		eax, 447D4Dh
		jmp		eax
	}
}

void __declspec(naked) ReallocateIOBuffer11_IN()
{
	__asm
	{
		movzx   eax, byte ptr [edx+edi+2040h]
		push    eax
		push    516C8Ch
		push    2
		push    8FF138h
		call    _CLOG_ASM_CALL

		mov		eax, 447E4Ch
		jmp		eax
	}
}

void __declspec(naked) ReallocateIOBuffer12_IN()
{
	__asm
	{
		lea     ebp, [eax+2040h]
		jle     43D9C4h

		mov		eax, 43D980h
		jmp		eax
	}
}

void __declspec(naked) ReallocateIOBuffer13_IN()
{
	__asm
	{
		movzx   eax, byte ptr [ebx+ebp+2041h]
		movzx   edi, byte ptr [ebx+ebp+2040h]
		shl     eax, 8
		lea     eax, [eax+edi-2]
		mov     [esi+0F4h], eax
		movzx   eax, byte ptr [ebx+ebp+2041h]
		movzx   edi, byte ptr [ebx+ebp+2040h]
		shl     eax, 8
		lea     eax, [eax+edi-2]
		test    eax, eax
		mov     [esi+0F4h], eax
		jle     40708Ch

		mov		edi, 406F0Dh
		jmp		edi
	}
}

void __declspec(naked) ReallocateIOBuffer14_IN()
{
	__asm
	{
		mov     eax, [esi+0F4h]
		mov     ecx, [esi+104h]
		mov     edx, [esi+100h]
		push    eax
		push    ecx
		push    edx
		lea     ebx, [ebx+ebp+2040h]
		push    ebx

		mov		ecx, 406F70h
		jmp		ecx
	}
}

void __declspec(naked) ReallocateIOBuffer1_OUT()
{
	__asm
	{
		add     edi, 2040h
		push    ecx
		mov     [esp+34h], edi
		call    ds:WSASend
		test    eax, eax
		jz      43FE4Ah
		
		mov		edx, 43FD81h
		jmp		edx
	}
}

void __declspec(naked) ReallocateIOBuffer2_OUT()
{
	__asm
	{
		push    esi
		call    _CIOBuffer__Alloc_C1
		mov     ecx, [esp+2Ch]
		mov     esi, eax
		lea     eax, [esp+30h]
		push    eax
		push    ecx
		lea     edx, [esi+2042h]
		push    3FFEh
		push    edx
		call    _VAssemble
		mov     ebx, eax

		mov     eax, 467441h
		jmp		eax
	}
}

void __declspec(naked) ReallocateIOBuffer3_OUT()
{
	__asm
	{
		mov     ecx, edi
		mov     [esi+2040h], bl
		mov     [esi+2041h], dl
		call    _CriticalSectionLock
		push    esi             
		mov     ecx, ebp       
		mov     [esi+2010h], ebx
		call    _CIOSocket__Write_C1

		mov     eax, 4674BDh
		jmp		eax

	}
}

void __declspec(naked) ReallocateIOBuffer4_OUT()
{
	__asm
	{
		add     eax, 2040h
		mov     [esp+18h], edx
		mov     [esp+1Ch], eax

		mov     eax, 43FB32h
		jmp		eax

	}
}

void __declspec(naked) ReallocateIOBuffer5_OUT()
{
	__asm
	{
		lea     edx, [esi+2042h]
		push    1FFEh
		push    edx
		call    _VAssemble
		mov     ebx, eax

		mov     eax, 44E0B1h
		jmp		eax
	}
}

void __declspec(naked) ReallocateIOBuffer6_OUT()
{
	__asm
	{
		mov     ecx, edi
		mov     [esi+2040h], bl
		mov     [esi+2041h], dl
		call    _CriticalSectionLock
		push    esi
		mov     ecx, ebp
		mov     [esi+2010h], ebx
		call    _CIOSocket__Write_C1

		mov     eax, 44E12Dh
		jmp		eax
	}
}

void __declspec(naked) ReallocateIOBuffer7_OUT()
{
	__asm
	{
		lea     edx, [esi+2042h]
		push    1FFEh
		push    edx
		call    _VAssemble
		mov     ebx, eax

		mov     eax, 44E232h
		jmp		eax
	}
}

void __declspec(naked) ReallocateIOBuffer8_OUT()
{
	__asm
	{
		mov     [esi+2040h], bl
		mov     [esi+2041h], dl

		mov     eax, 44E269h
		jmp		eax
	}
}

void __declspec(naked) ReallocateIOBuffer9_OUT()
{
	__asm
	{
		lea     edx, [esi+2042h]
		push    3FFEh
		push    edx
		call    _VAssemble
		mov     ebx, eax

		mov     eax, 44802Bh
		jmp		eax
	}
}

void __declspec(naked) ReallocateIOBuffer10_OUT()
{
	__asm
	{
		mov     [esi+2040h], bl
		mov     [esi+2041h], dl

		mov     eax, 448062h
		jmp		eax
	}
}

void __declspec(naked) ReallocateIOBuffer11_OUT()
{
	__asm
	{
		lea     edi, [esi+2040h]
		push    4000h
		push    edi
		call    _InternalSocketAssemble
		add     esp, 2040h
		test    eax, eax
		jle     43D464h

		mov     eax, 43D44Ah
		jmp		eax
	}
}

void __declspec(naked) ReallocateIOBuffer12_OUT()
{
	__asm
	{
		push    esi
		call    _CIOBuffer__Alloc_C1
		mov     ecx, [esp+2Ch]
		mov     esi, eax
		lea     eax, [esp+30h]
		push    eax
		push    ecx
		lea     edx, [esi+2042h]
		push    3FFEh
		push    edx
		call    _VAssemble
		mov     ebx, eax

		mov     eax, 4071E1h
		jmp		eax
	}
}

void __declspec(naked) ReallocateIOBuffer13_OUT()
{
	__asm
	{
		mov     ecx, edi
		mov     [esi+2040h], bl
		mov     [esi+2041h], dl
		call    _CriticalSectionLock
		push    esi
		mov     ecx, ebp
		mov     [esi+2010h], ebx
		call    _CIOSocket__Write_C1

		mov     eax, 40725Dh
		jmp		eax
	}
}

void __declspec(naked) MemMove2_ASM_OUT()
{
	__asm
	{
		push    edx
		lea     edx, [edi+2040h]
		push    edx
		lea     eax, [ecx+eax+2040h]
		push    eax
		call    _MemMove2_ASM_CALL

		mov		eax, 43FE08h
		jmp		eax
	}
}

///////////////////////////////////////////////////////////////////////////////////////////

void __declspec(naked) MemMove1_ASM_IN()
{
	__asm
	{
		mov     eax, [esi+60h]
		mov     ecx, [eax+2010h]
		lea     edx, [ecx+eax+2040h]
		push    ebx
		push    edx
		add     eax, 2040h
		push    eax
		call    _MemMove1_ASM_CALL

		mov		eax, 43F932h
		jmp		eax
	}
}

void __declspec(naked) MemMove2_ASM_IN()
{
	__asm
	{
		mov     eax, [esi+60h]
		mov     ecx, [eax+2010h]
		lea     edx, [ecx+eax+2040h]
		push    ebx
		push    edx
		lea     eax, [ebp+2040h]
		push    eax
		call    _MemMove2_ASM_CALL

		mov		eax, 43F8E2h
		jmp		eax
	}
}

void CIOBufferExt::Init()
{
	//.text:00421F78                 imul    eax, 2040h
	CachedExt::WriteMemoryDWORD(0x421F7A, sizeof(CIOBuffer));
	//.text:00421F84                 call    malloc_C1
	CachedExt::SetHook(0xE8, 0x421F84, (DWORD)CIOBufferExt::Malloc, 0);
	//WriteInstruction(0x421F84, (INT32)&CIOBufferExt::Malloc, 0, ASM_CALL);
	//.text:00421FBD                 add     ecx, 2040h
	CachedExt::WriteMemoryDWORD(0x421FBF, sizeof(CIOBuffer));


//Outgoing packets
//CIOSocket::_Write
	WriteInstruction(0x43FD6B, (INT32)&ReallocateIOBuffer1_OUT, 0, 0xE9);
	WriteInstruction(0x43FDF9, (INT32)&MemMove2_ASM_OUT, 0, 0xE9);
	CachedExt::WriteMemoryDWORD(0x43FDF3, 0x4000);

//CIOSocket::WriteCallBack
	WriteInstruction(0x43FB27, (INT32)&ReallocateIOBuffer4_OUT, 0, 0xE9);

//CSocket::Send
	WriteInstruction(0x46741F, (INT32)&ReallocateIOBuffer2_OUT, 0, 0xE9);
	WriteInstruction(0x4674A2, (INT32)&ReallocateIOBuffer3_OUT, 0, 0xE9);

//CNpcDbSocket::Send - 8190 max buffer for npc socket
	WriteInstruction(0x44E0A1, (INT32)&ReallocateIOBuffer5_OUT, 0, 0xE9);
	WriteInstruction(0x44E114, (INT32)&ReallocateIOBuffer6_OUT, 0, 0xE9);

//CNpcDbSocket::SendBuffer - 8190 max buffer for npc socket
	WriteInstruction(0x44E222, (INT32)&ReallocateIOBuffer7_OUT, 0, 0xE9);
	WriteInstruction(0x44E263, (INT32)&ReallocateIOBuffer8_OUT, 0, 0xE9);

//CLogSocket::Send
	WriteInstruction(0x44801B, (INT32)&ReallocateIOBuffer9_OUT, 0, 0xE9);
	WriteInstruction(0x44805C, (INT32)&ReallocateIOBuffer10_OUT, 0, 0xE9);	
	
//CIntSocket::Send
	WriteInstruction(0x43D435, (INT32)&ReallocateIOBuffer11_OUT, 0, 0xE9);	
	CachedExt::WriteMemoryDWORD(0x43D455, 0x4000);

//CAdminSocket::Send - NOT TESTED
	WriteInstruction(0x4071BF, (INT32)&ReallocateIOBuffer12_OUT, 0, 0xE9);
	WriteInstruction(0x407242, (INT32)&ReallocateIOBuffer13_OUT, 0, 0xE9);		//nuevo (407242) anterior, error 40725D era a donde devuelve...
	
//Incomming packets IOBuffer
//CIOSocket::Read
	WriteInstruction(0x43F8CA, (INT32)&MemMove2_ASM_IN, 0, 0xE9);
	WriteInstruction(0x43F91A, (INT32)&MemMove1_ASM_IN, 0, 0xE9);
	CachedExt::WriteMemoryDWORD(0x43F96C, 0x4000);
	WriteInstruction(0x43F982, (INT32)&ReallocateIOBuffer1_IN, 0, 0xE9);

//void CSocket::OnRead
	WriteInstruction(0x467067, (INT32)&ReallocateIOBuffer2_IN, 0, 0xE9);
	WriteInstruction(0x4670E4, (INT32)&ReallocateIOBuffer3_IN, 0, 0xE9);
	WriteInstruction(0x4672D9, (INT32)&ReallocateIOBuffer6_IN, 0, 0xE9); //Packet Log Function

//CPacket Fix
	WriteInstruction(0x44019C, (INT32)&ReallocateIOBuffer4_IN, 0, 0xE9);

//NpcSocket::OnRead
	WriteInstruction(0x44DDA7, (INT32)&ReallocateIOBuffer5_IN, 0, 0xE9);
	WriteInstruction(0x44DE3B, (INT32)&ReallocateIOBuffer7_IN, 0, 0xE9);

//void CLogSocket::OnRead - BUGGED
	WriteInstruction(0x447C72, (INT32)&ReallocateIOBuffer8_IN, 0, 0xE9);
	CachedExt::WriteMemoryDWORD(0x447C8F, 0x4000);
	WriteInstruction(0x447CBD, (INT32)&ReallocateIOBuffer9_IN, 0, 0xE9);
	WriteInstruction(0x447D48, (INT32)&ReallocateIOBuffer10_IN, 0, 0xE9);
	WriteInstruction(0x447E35, (INT32)&ReallocateIOBuffer11_IN, 0, 0xE9);
	
//CIntSocket::OnRead
	WriteInstruction(0x43D97B, (INT32)&ReallocateIOBuffer12_IN, 0, 0xE9);
	
//CAdminSocket::OnRead - NOT TESTED
	WriteInstruction(0x406ED7, (INT32)&ReallocateIOBuffer13_IN, 0, 0xE9);
	CachedExt::WriteMemoryDWORD(0x406F0E, 0x4000);
	WriteInstruction(0x406F56, (INT32)&ReallocateIOBuffer14_IN, 0, 0xE9);		//al poner esta me crashea cacehd

}

LPVOID CIOBufferExt::Malloc(UINT32 size)
{
	typedef LPVOID (*f)(UINT32);
	LPVOID pRet = f(0x4D8EB2L)( size );
	int tries = 15;
	while(pRet == NULL && tries > 0)
	{
		tries--;
		if(pRet == NULL)
			g_Log.Add(CLog::Error, "[%s] Cannot allocate memory for IOBuffer [%d] size. - trying [%d]", __FUNCTION__, size, (15-tries));

		Sleep(50);
		pRet = f(0x4D8EB2L)( size );
	}

	return pRet;
}
