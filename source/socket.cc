#include "defs.hh"
#include "socket.hh"

#ifndef __WINDOWS__
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <poll.h>

#define TYPE_SOCKETLEN socklen_t

#else
#include <WinSock2.h>
#include <WS2tcpip.h>
#pragma comment (lib, "ws2_32.lib")


#define TYPE_SOCKETLEN int

#if (_WIN32_WINNT <= 0x0501 || WINVER <= 0x0501)
HINSTANCE winSocketLib;

// Note: on Windows XP or older, the functions 'getaddrinfo' and 'freeaddrinfo'
//       should be loaded manually.

getaddrinfo_f getaddrinfo;

freeaddrinfo_f freeaddrinfo;
#endif


class WinSocket
{
	public:
		WinSocket();
		~WinSocket();
};


/**
 * @brief Initialize and terminate the WinSocket subsystem.
 */
static WinSocket winSocket;


WinSocket::WinSocket()
{
	#if defined (__WINDOWS__)
	int err = 0;

	WORD wVersionRequested;
	WSADATA wsaData;
	wVersionRequested = MAKEWORD( 2, 0 );
	err = WSAStartup( wVersionRequested, &wsaData );
	if( err != 0) return;

	#if (_WIN32_WINNT <= 0x0501 || WINVER <= 0x0501)
	winSocketLib = LoadLibrary( "WS2_32.dll" );
	if (winSocketLib == NULL) return;

	getaddrinfo = NULL;
	freeaddrinfo = NULL

	getaddrinfo = (getaddrinfo_f)GetProcAddress(winSocketLib, "getaddrinfo");
	if (getaddrinfo == NULL) return;

	freeaddrinfo = (freeaddrinfo_f)GetProcAddress(winSocketLib, "freeaddrinfo");
	if (freeaddrinfo == NULL) return;
	#endif

	#endif // __WINDOWS__
}


WinSocket::~WinSocket()
{
	#if (_WIN32_WINNT <= 0x0501 || WINVER <= 0x0501)
	getaddrinfo = NULL;
	freeaddrinfo = NULL;
	#endif
	WSACleanup();
}


#endif // __WINDOWS__

#define CTX  (*((Context*)ctx))

struct Context
{
	#ifdef __WINDOWS__
	SOCKET socketfd;
	#else
	int socketfd;
	#endif
	//struct sockaddr_in address;
	uint32_t ipv4;
};


Endpoint::Endpoint() : address(0), port(0)
{
}

Endpoint::Endpoint( const Endpoint &that ) : address(that.address), port(that.port)
{
}

Endpoint::Endpoint( uint32_t ipv4, uint16_t port ) : address(ipv4), port(port)
{
}

Endpoint::Endpoint( const std::string &ipv4, uint16_t port ) : port(port)
{
	inet_pton(AF_INET, ipv4.c_str(), &address);
}


std::string Endpoint::addressToString( uint32_t address )
{
	char output[16];
	snprintf(output, sizeof(output), "%d.%d.%d.%d",
        SOCKET_IP_O1(address),
        SOCKET_IP_O2(address),
        SOCKET_IP_O3(address),
        SOCKET_IP_O4(address));
	return output;
}


UDP::UDP()
{
	ctx = new Context();
	CTX.socketfd = socket(AF_INET, SOCK_DGRAM, 0);
}

UDP::~UDP()
{
	close();
	delete (Context*) ctx;
}


void UDP::close()
{
	if (CTX.socketfd == 0) return;

    #ifdef __WINDOWS__
	closesocket(CTX.socketfd);
	#else
	::close(CTX.socketfd);
	#endif
	CTX.ipv4 = 0;
	CTX.socketfd = 0;
}

bool UDP::send( const Endpoint &endpoint, const uint8_t *data, size_t size )
{
    struct sockaddr_in address;
	address.sin_family = AF_INET;
	#ifdef __WINDOWS__
    address.sin_addr.S_un.S_addr = htonl(endpoint.address);
	#else
	address.sin_addr.s_addr = htonl(endpoint.address);
	#endif
    address.sin_port = htons(endpoint.port);

    int result = (int) sendto(CTX.socketfd, (const char*) data, (int) size, 0,
        (struct sockaddr *) &address, (int) sizeof(address));
    return result > 0;
}

bool UDP::receive( Endpoint &endpoint, uint8_t *data, size_t *size, int timeout )
{
    struct sockaddr_in address;
	TYPE_SOCKETLEN length = sizeof(address);

	if (!poll(timeout)) return false;

    int result = (int) recvfrom(CTX.socketfd, (char*) data, (int) *size, 0,
        (struct sockaddr *) &address, &length);
    if (result >= 0)
	{
		*size = result;
		#ifdef __WINDOWS__
		endpoint.address = ntohl(address.sin_addr.S_un.S_addr);
		#else
		endpoint.address = ntohl(address.sin_addr.s_addr);
		#endif
		endpoint.port = ntohs(address.sin_port);
	}
    return result >= 0;
}

bool UDP::poll( int timeout )
{
    struct pollfd pfd;
    pfd.fd = CTX.socketfd;
    pfd.events = POLLIN;
    #ifdef __WINDOWS__
	if (WSAPoll(&pfd, 1, timeout) <= 0) return false;
	#else
	if (::poll(&pfd, 1, timeout) <= 0) return false;
	#endif
	return true;
}

uint32_t UDP::hostToIPv4( const std::string &host )
{
    if (host.empty()) return 0;

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    inet_pton(AF_INET, host.c_str(), &address.sin_addr);
    return (uint32_t) ntohl(address.sin_addr.s_addr);
}

bool UDP::bind( const std::string &host, uint16_t port )
{
	struct sockaddr_in address;
    address.sin_family = AF_INET;
    if (host.empty())
        address.sin_addr.s_addr = INADDR_ANY;
    else
    {
        inet_pton(AF_INET, host.c_str(), &address.sin_addr);
        CTX.ipv4 = address.sin_addr.s_addr;
    }
    address.sin_port = htons( (uint16_t) port);

	int result = ::bind(CTX.socketfd, (struct sockaddr *) &address, sizeof(address));
    if (result != 0)
    {
		close();
        return false;
    }
	return true;
}