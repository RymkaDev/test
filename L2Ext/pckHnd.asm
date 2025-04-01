include windows.inc

.data
	RETURNADDR1_RECEIVE									QWORD 8771DAh
	RETURNADDR1_NOTRECEIVE								QWORD 877335h

	EXTERN												ReceiveData_Wrapper:PROC

	
FUNC_BEGIN ReadPackets_Hook
	
		XPUSHAD_ALL_NO_RAX
		
			movzx	r9d, byte ptr [rbx+r13]			; Packet ID
			movzx	r8d, word ptr [rbx+r13-02h]		; Packet Size
			lea		rdx, [rbx+r13+01h]				; Decrypted Packet Buffer
			mov		rcx, rsi						; CSocket *pSocket
			call	ReceiveData_Wrapper				; DepmaX64 Incomming Packet Handler
			
		XPOPAD_ALL_NO_RAX
		
		test	al, al								; Receive Packet (Yes/No?)
		jz		NotReceivePacket
		
		ReceivePacket:								; Passing Packets
		
			movzx   eax, byte ptr [rbx+r13]
			jmp		RETURNADDR1_RECEIVE
			
		NotReceivePacket:							; Filtering Packets
		
			jmp		RETURNADDR1_NOTRECEIVE
	
FUNC_END ReadPackets_Hook

.code

end