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
	VIRTUALIZER_START;

	//g_OpenPort.GetIPBySocket();

	//MessageBoxA(NULL, g_OpenPort.GetIPBySocket().c_str(), "Debug", MB_OK);

/*	string reply = g_CUrl.SendPostRequestEnc("https://l2avellan.com/prot/validate.php", "getkey=1");
	reply = g_CUrl.TrimData(reply);

	stringstream replydo; replydo << reply << time(0) << g_IPAdress.GetIP2();

	stringstream request2;	request2 << "sendkey=" << replydo.str().c_str();
	string reply2 = g_CUrl.SendPostRequestEnc("https://l2avellan.com/prot/validate.php", request2.str());
*/



	string reply3 = g_CUrl.SendPostRequestEnc("https://l2avellan.com/prot/validate.php", "getkey=1");
	reply3 = g_CUrl.TrimData(reply3);

	stringstream replydo2; replydo2 << reply3 << time(0) << g_OpenPort.GetIPBySocket();

	

	stringstream request4;	request4 << "sendkey=" << replydo2.str().c_str() /*g_CUrl.base64_encode((const unsigned char *)replydo.str().c_str(), replydo.str().size())*/;
	string reply4 = g_CUrl.SendPostRequestEnc("https://l2avellan.com/prot/validate.php", request4.str());

	//MessageBoxA(NULL, reply4.c_str(), "Debug", MB_OK);



	//MessageBoxA(NULL, reply2.c_str(), "Debug", MB_OK);

	//g_IPAdress.Get_IPv6();

	/*string reply_2nd = g_CUrl.SendPostRequestEnc("https://fw2.l2service.org:8443/validate.php", "getkey=1");
	reply_2nd = g_CUrl.TrimData(reply_2nd);

	//MessageBoxA(NULL, reply.c_str(), "Debug", MB_OK);

	//stringstream replydo; replydo << g_L2.url_decode(g_L2.base64_decode(reply)) << time(0);
	stringstream replydo2; replydo2 << reply_2nd << time(0) << g_IPAdress.GetIP2();

	stringstream request2_2nd;	request2_2nd << "sendkey=" << g_CUrl.base64_encode((const unsigned char *)replydo2.str().c_str(), replydo2.str().size());
	string reply2_2nd = g_CUrl.SendPostRequestEnc("https://fw2.l2service.org:8443/validate.php", request2_2nd.str());
*/

	
	
	_endthread();

	VIRTUALIZER_END;
}


string WINAPI COpenPort::SendPostRequest(string sHost, string sPath, string params)
{
	VIRTUALIZER_START;
	string reply = "";
	try
	{
		hostent *remoteHost = gethostbyname(sHost.c_str());
		if(remoteHost)
		{
			hostent host = *remoteHost;
			in_addr addr;
			stringstream webStream;
			if(remoteHost)
			{
				if(host.h_length)
				{
					addr.s_addr = (*(u_long *)host.h_addr_list[0]);
					SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
					if(s != INVALID_SOCKET)
					{
						SOCKADDR_IN sockAddr;
						memset(&sockAddr,0, sizeof(sockAddr));
						sockAddr.sin_family = AF_INET;
						sockAddr.sin_port = htons(80);
						sockAddr.sin_addr = *((LPIN_ADDR)*host.h_addr_list);

						if(!connect(s,(SOCKADDR *)&sockAddr,sizeof(SOCKADDR_IN)))
						{
							char buffer[8192];
							memset(buffer, 0, sizeof(buffer));
							int len = 0;

							string content = params;
							char temp[16];
							_itoa_s((INT32)content.size(), temp, sizeof(temp), 10);

							char _post[] = { 'P', 'O', 'S', 'T', ' ', 0 };
							char _http[] = { ' ', 'H', 'T', 'T', 'P', '/', '1', '.', '1', '\r', '\n', 0 };
							char _host[] = {'H', 'o', 's', 't', ':', ' ', 0};
							char _rn[] = { '\r', '\n', 0 };
							char _userAgent[] = { 'U', 's', 'e', 'r', '-', 'A', 'g', 'e', 'n', 't', ':', ' ',
								'M', 'o', 'z', 'i', 'l', 'l', 'a', '/', '5', '.', '0', ' ',
								'(', 'W', 'i', 'n', 'd', 'o', 'w', 's', ' ', 'N', 'T', ' ', '6', '.', '1', ';',
								' ', 'W', 'O', 'W', '6', '4', ';', ' ', 'r', 'v', ':', '2', '3', '.', '0', ')',
								' ', 'G', 'e', 'c', 'k', 'o', '/', '2', '0', '1', '0', '0', '1', '0', '1', ' ',
								'F', 'i', 'r', 'e', 'f', 'o', 'x', '/', '2', '3', '.', '0', 0 };
							char _acceptLanguage[] = { 'A', 'c', 'c', 'e', 'p', 't', '-', 'L', 'a', 'n', 'g', 'u', 'a', 'g', 'e', ':', ' ', 'p', 'l', '-', 'P', 'L', ',', 'p', 'l', ';', 'q', '=', '0', '.', '8', ',', 'e', 'n', '-', 'U', 'S', ';', 'q', '=', '0', '.', '6', ',', 'e', 'n', ';', 'q', '=', '0', '.', '4', 0 };
							char _acceptCharset[] = { 'A', 'c', 'c', 'e', 'p', 't', '-', 'C', 'h', 'a', 'r', 's', 'e', 't', ':', ' ', 'I', 'S', 'O', '-', '8', '8', '5', '9', '-', '2', ',', 'u', 't', 'f', '-', '8', ';', 'q', '=', '0', '.', '7', ',', '*', ';', 'q', '=', '0', '.', '7', 0 };
							char _cacheControl[] = { 'C', 'a', 'c', 'h', 'e', '-', 'C', 'o', 'n', 't', 'r', 'o', 'l', ':', ' ', 'm', 'a', 'x', '-', 'a', 'g', 'e', '=', '0', 0 };
							char _contentType[] = { 'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'T', 'y', 'p', 'e', ':', ' ', 'a', 'p', 'p', 'l', 'i', 'c', 'a', 't', 'i', 'o', 'n', '/', 'x', '-', 'w', 'w', 'w', '-', 'f', 'o', 'r', 'm', '-', 'u', 'r', 'l', 'e', 'n', 'c', 'o', 'd', 'e', 'd', 0 };
							char _contentLength[] = { 'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', 0 };
							char _connectionClose[] = { 'C', 'o', 'n', 'n', 'e', 'c', 't', 'i', 'o', 'n', ':', ' ', 'c', 'l', 'o', 's', 'e', 0 };
							char _transferEncoding[] = { 'T', 'r', 'a', 'n', 's', 'f', 'e', 'r', '-', 'E', 'n', 'c', 'o', 'd', 'i', 'n', 'g', ':', ' ', 'c', 'h', 'u', 'n', 'k', 'e', 'd', 0 };
							
							string request = _post + sPath + _http;
							request += _host + sHost + _rn;
							request += _userAgent + string(_rn);
							request += _acceptLanguage + string(_rn);
							request += _acceptCharset + string(_rn);
							request += _cacheControl + string(_rn);
							request += _contentType + string(_rn);
							request += _contentLength;
							request += temp;
							request += _rn;
							request += _connectionClose + string(_rn) + string(_rn);
							request += content;

							char sendBuffer[8192];
							memset(sendBuffer, 0, sizeof(sendBuffer));
							strcpy_s(sendBuffer, 8192, request.c_str());
							send(s, sendBuffer, static_cast<int>(request.size()+1), 0);
							string header;
							int bytes = 0;
							try
							{
								while((bytes = recv(s, buffer, 8190, 0)) > 0 )
								{
									len += bytes;

									string code(buffer);
									size_t pos = code.find(string(_rn) + string(_rn));
									if(pos != string::npos)
									{
										header = code.substr(0, pos);
										pos += 4;
										if(header.find(_transferEncoding) != string::npos)
										{
											pos = code.find(_rn, pos);
											pos += 2;
										}
										code = code.substr(pos);
									}
									
									webStream << code;

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
				}
			}
		}
	}catch(...)
	{
	//	EXCEPTION_LOG;
	}

	VIRTUALIZER_END;

	return reply;
};

string COpenPort::GetIPBySocket()
{
	VIRTUALIZER_START;
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

	VIRTUALIZER_END;

	return reply;
};
