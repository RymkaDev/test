// SPLASH.h: interface for the SPLASH class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_SPLASH_H__41182F11_BB6F_11D6_B0F5_00B0D01AD687__INCLUDED_)
#define AFX_SPLASH_H__41182F11_BB6F_11D6_B0F5_00B0D01AD687__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000


class CSplash  
{
private:
	UINT TimerID;
	HWND hParentWindow;
	HWND hSplashWnd;

public:
	void Hide();
	void Show();
	void Init(HWND hWnd,HINSTANCE hInst,int resid);
    BOOL SHOWING;
	CSplash();
	virtual ~CSplash();


    
};

extern CSplash g_SplashScreen;

#endif // !defined(AFX_SPLASH_H__41182F11_BB6F_11D6_B0F5_00B0D01AD687__INCLUDED_)
