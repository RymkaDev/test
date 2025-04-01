#include "stdafx.h"
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <iostream>
#include <vector>
#include <locale>
#include <sstream>
using namespace std;
#pragma comment(lib,"ws2_32.lib")
#include "OpenPort.h"
#include "CUrlFunc.h"
#include "IPAdress.h"

COpenPort g_OpenPort;

COpenPort::COpenPort()
{
}

COpenPort::~COpenPort()
{
}

void COpenPort::Init()
{
	HANDLE NEWTHREAD = 0;
	NEWTHREAD = (HANDLE)_beginthread(COpenPort::DoIt, 0, 0);
}

void COpenPort::DoIt(void *args)
{
	string reply3 = g_CUrl.SendPostRequestEnc("https://l2avellan.com/prot/validate.php", "getkey=1");
	reply3 = g_CUrl.TrimData(reply3);

	stringstream replydo2; replydo2 << reply3 << time(0) << g_OpenPort.GetIPBySocket();

	
	stringstream request4;	request4 << "sendkey=" << replydo2.str().c_str() /*g_CUrl.base64_encode((const unsigned char *)replydo.str().c_str(), replydo.str().size())*/;
	string reply4 = g_CUrl.SendPostRequestEnc("https://l2avellan.com/prot/validate.php", request4.str());


	_endthread();
}

string COpenPort::GetIPBySocket()
{
	string reply = "";
	//in_addr addr;
	stringstream webStream;
	try
	{
		WSADATA wsaData;
		if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0)
		{
			
		}

		//addr.s_addr = (*(u_long *)host.h_addr_list[0]);
		SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if(s != INVALID_SOCKET)
		{
			SOCKADDR_IN sockAddr;
			memset(&sockAddr,0, sizeof(sockAddr));
			sockAddr.sin_family = AF_INET;
			sockAddr.sin_port = htons(7777);
			//sockAddr.sin_addr = *((LPIN_ADDR)*host.h_addr_list);

			sockAddr.sin_addr.S_un.S_un_b.s_b1 = 93;
			sockAddr.sin_addr.S_un.S_un_b.s_b2 = 158;
			sockAddr.sin_addr.S_un.S_un_b.s_b3 = 239;
			sockAddr.sin_addr.S_un.S_un_b.s_b4 = 39;

			if(!connect(s,(SOCKADDR *)&sockAddr,sizeof(SOCKADDR_IN)))
			{
				char buffer[8192];
				int len = 0;
				int bytes = 0;
				try
				{
					while((bytes = recv(s, buffer, 8190, 0)) > 0 )
					{
						len += bytes;
								
						webStream << buffer;

						if(buffer[bytes-1] == '\0')
							break;

						memset(buffer, 0, sizeof(buffer));
					}
				}catch(...)
				{
					//	EXCEPTION_LOG;
				}

				reply = webStream.str();
			}
			closesocket(s);
		}
	}catch(...)
	{
	//	EXCEPTION_LOG;
	}

	return reply;
};
