#include "defs.hh"
#include "socket.hh"
#include <cstring>

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


Address::Address() : type(ADDR_TYPE_A)
{
	ipv4 = 0;
}

Address::Address( uint32_t ipv4, const std::string &name ) : name(name), type(ADDR_TYPE_A), ipv4(ipv4)
{
}

Address::Address( const Address &that ) : type(that.type)
{
	memcpy(ipv6, that.ipv6, sizeof(ipv6));
}

std::string Address::toString( bool empty ) const
{
	char output[48] = { 0 };

	if (empty && invalid()) return "";

	if (type == ADDR_TYPE_A)
	{
		snprintf(output, sizeof(output), "%d.%d.%d.%d",
			SOCKET_IP_O1(ipv4),
			SOCKET_IP_O2(ipv4),
			SOCKET_IP_O3(ipv4),
			SOCKET_IP_O4(ipv4));
	}
	else
	if (type == ADDR_TYPE_AAAA)
	{
		snprintf(output, sizeof(output), "%x:%x:%x:%x:%x:%x:%x:%x",
			ipv6[0], ipv6[1], ipv6[2], ipv6[3], ipv6[4], ipv6[5], ipv6[6],ipv6[7]);
	}

	return output;
}

bool Address::equivalent( const Address &that ) const
{
	if (type == that.type && type == ADDR_TYPE_A)
		return ipv4 == that.ipv4 || ( SOCKET_IP_O1(ipv4) == 127 && SOCKET_IP_O1(that.ipv4) == 127 );
	else
		return false;
}

bool Address::operator==( const Address &that ) const
{
	if (type != that.type) return false;
	if (type == ADDR_TYPE_A)
		return ipv4 == that.ipv4;
	else
	if (type == ADDR_TYPE_AAAA)
		return memcmp(ipv6, ipv6, sizeof(ipv6)) == 0;
	else
		return false;
}

bool Address::invalid() const
{
	if (type == ADDR_TYPE_A)
		return ipv4 == 0;
	else
	if (type == ADDR_TYPE_AAAA)
	{
		for (int i = 0; i < 8; ++i)
			if (ipv6[i] != 0) return false;
	}

	return true;
}

bool Address::local() const
{
	if (type == ADDR_TYPE_A && SOCKET_IP_O1(ipv4) == 127)
		return true;
	if (type == ADDR_TYPE_AAAA && ipv6[0] == 0)
		return true;
	return false;
}

Endpoint::Endpoint() : port(0)
{
}

Endpoint::Endpoint( const Endpoint &that ) : address(that.address), port(that.port)
{
}

Endpoint::Endpoint( const Address &address, uint16_t port ) : address(address), port(port)
{
}

Endpoint::Endpoint( const uint32_t &ipv4, uint16_t port ) : address(Address(ipv4)), port(port)
{
}

Endpoint::Endpoint( const std::string &ipv4, uint16_t port ) : port(port)
{
	inet_pton(AF_INET, ipv4.c_str(), &address);
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
    address.sin_addr.S_un.S_addr = htonl(endpoint.address.ipv4);
	#else
	address.sin_addr.s_addr = htonl(endpoint.address.ipv4);
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
		endpoint.address.ipv4 = ntohl(address.sin_addr.S_un.S_addr);
		#else
		endpoint.address.ipv4 = ntohl(address.sin_addr.s_addr);
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