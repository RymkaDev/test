#ifndef _HOOK_H
#define _HOOK_H


//namespace xtender {

class Hook
{
private: 
	wstring dll;
	string func;
	LPVOID addr;
	LPVOID fAddr;
	bool hooked;

	bool flushCache;

	BYTE saved[5];
	BYTE jump[5];

public:
	Hook(wstring const & dll, string const & func, LPVOID addr, bool allowRecalculate = false);
	Hook(wstring const & dll, string const & funcName, LPVOID func, LPVOID addr);
	~Hook();

	bool Apply();
	bool Cancel();

	bool IsApply() const {
		return hooked;
	}

	LPVOID GetFunctionAddress() const {
		return fAddr;
	}

	void SetFlushCache(bool flushCache) {
		this->flushCache = flushCache;
	}

	bool IsFlushCache() const {
		return flushCache;
	}

	BYTE* GetSaved() {
		return saved;
	}

private:
	bool WriteProcMem(LPVOID fAddr, PBYTE raw, SIZE_T size, bool flushCache);
};

//}

#endif