#pragma once


class CThreadSafe
{
	CRITICAL_SECTION lock;
public:
	CThreadSafe() { InitializeCriticalSection(&lock); };
	virtual ~CThreadSafe() { DeleteCriticalSection(&lock);};
	__forceinline void Lock() { EnterCriticalSection(&lock); };
	__forceinline void Unlock() { LeaveCriticalSection(&lock); };
};

class CThreadSafe2
{
	CRITICAL_SECTION lock;
public:
	CThreadSafe2() { InitializeCriticalSection(&lock); };
	virtual ~CThreadSafe2() { DeleteCriticalSection(&lock);};
	__forceinline void Lock() { EnterCriticalSection(&lock); };
	__forceinline void Unlock() { LeaveCriticalSection(&lock); };
};