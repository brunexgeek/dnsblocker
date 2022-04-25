#include "defs.hh"
#include "socket.hh"
#include <cstring>
#include <vector>

#ifndef __WINDOWS__
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <poll.h>
#include <iostream>

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

struct WinSocket
{
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

//
// ipv4_t
//

static const uint8_t IPV4_NXDOMAIN[] = DNS_NXDOMAIN_IPV4_ADDRESS;
const ipv4_t ipv4_t::NXDOMAIN(IPV4_NXDOMAIN);

ipv4_t::ipv4_t()
{
	clear();
}

ipv4_t::ipv4_t( const uint8_t *that )
{
	clear();
	if (that) memcpy(values, that, sizeof(values));
}

ipv4_t::ipv4_t( const uint32_t &that )
{
	values[0] = (uint8_t) that & 0xFF;
	values[1] = (uint8_t) (that >> 8) & 0xFF;
	values[2] = (uint8_t) (that >> 16) & 0xFF;
	values[3] = (uint8_t) (that >> 24) & 0xFF;
}

static std::vector<std::string> split_string( const std::string &value, char delim )
	{
	std::vector<std::string> out;
	std::string buf = "";
	size_t i = 0;
	while (i < value.length())
	{
		if (value[i] != delim)
			buf += value[i];
		else
		if (buf.length() > 0) {
			out.push_back(buf);
			buf = "";
		}
		i++;
	}
    if (!buf.empty())
        out.push_back(buf);
    return out;
}

ipv4_t::ipv4_t( const std::string &that )
{
	clear();
	auto temp = split_string(that, '.');
	if (temp.size() != 4) return;
	values[0] = (uint8_t) atoi(temp[0].c_str());
	values[1] = (uint8_t) atoi(temp[1].c_str());
	values[2] = (uint8_t) atoi(temp[2].c_str());
	values[3] = (uint8_t) atoi(temp[3].c_str());
}

ipv4_t::ipv4_t( const ipv4_t &that )
{
	memcpy(values, that.values, sizeof(values));
}

ipv4_t::ipv4_t( ipv4_t &&that )
{
	memcpy(values, that.values, sizeof(values));
}

bool ipv4_t::operator==( const ipv4_t &that ) const
{
	return memcmp(values, that.values, sizeof(values)) == 0;
}

ipv4_t &ipv4_t::operator=( const ipv4_t &that )
{
	memcpy(values, that.values, sizeof(values));
	return *this;
}

ipv4_t &ipv4_t::operator=( const uint32_t &that )
{
	values[0] = (uint8_t) that & 0xFF;
	values[1] = (uint8_t) (that >> 8) & 0xFF;
	values[2] = (uint8_t) (that >> 16) & 0xFF;
	values[3] = (uint8_t) (that >> 24) & 0xFF;
	return *this;
}

uint32_t ipv4_t::to_uint32() const
{
	return values[0] | (values[1] << 8) | (values[2] << 16) | (values[3] << 24);
}

void ipv4_t::clear()
{
	memset(values, 0, sizeof(values));
}

bool ipv4_t::empty() const
{
	return (!values[0] && !values[1] && !values[2] && !values[3]);
}

std::string ipv4_t::to_string() const
{
	char output[16] = { 0 };
	snprintf(output, sizeof(output), "%d.%d.%d.%d",
		(int) values[0],
		(int) values[1],
		(int) values[2],
		(int) values[3]);
	return output;
}

//
// ipv6_t
//

#ifdef ENABLE_IPV6

static const uint16_t IPV6_NXDOMAIN[] = DNS_NXDOMAIN_IPV6_ADDRESS;
const ipv6_t ipv6_t::NXDOMAIN(IPV6_NXDOMAIN);

ipv6_t::ipv6_t()
{
	clear();
}

ipv6_t::ipv6_t( const uint16_t *that )
{
	if (that) memcpy(values, that, sizeof(values));
}

ipv6_t::ipv6_t( const ipv6_t &that )
{
	memcpy(values, that.values, sizeof(values));
}

ipv6_t::ipv6_t( ipv6_t &&that )
{
	memcpy(values, that.values, sizeof(values));
}

bool ipv6_t::operator==( const ipv6_t &that ) const
{
	return memcmp(values, that.values, sizeof(values)) == 0;
}

ipv6_t &ipv6_t::operator=( const ipv6_t &that )
{
	memcpy(values, that.values, sizeof(values));
	return *this;
}

void ipv6_t::clear()
{
	memset(values, 0, sizeof(values));
}

bool ipv6_t::empty() const
{
	for (int i = 0; i < 8; ++i)
		if (values[i] != 0) return false;
	return true;
}

std::string ipv6_t::to_string() const
{
	char output[48] = { 0 };
	snprintf(output, sizeof(output), "%x:%x:%x:%x:%x:%x:%x:%x",
		values[0], values[1], values[2], values[3], values[4], values[5], values[6], values[7]);
	return output;
}

#endif

//
// Endpoint
//

Endpoint::Endpoint() : port(0)
{
}

Endpoint::Endpoint( const Endpoint &that ) : address(that.address), port(that.port)
{
}

Endpoint::Endpoint( const ipv4_t &ipv4, uint16_t port ) : address(ipv4), port(port)
{
}

Endpoint::Endpoint( const std::string &ipv4, uint16_t port ) : port(port)
{
	inet_pton(AF_INET, ipv4.c_str(), address.values);
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
	uint32_t ip = endpoint.address.to_uint32();
	#ifdef __WINDOWS__
    address.sin_addr.S_un.S_addr = ip;
	#else
	address.sin_addr.s_addr = ip;
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

	if (timeout > 0 && !poll(timeout)) return false;

    int result = (int) recvfrom(CTX.socketfd, (char*) data, (int) *size, 0,
        (struct sockaddr *) &address, &length);
    if (result >= 0)
	{
		*size = result;
		#ifdef __WINDOWS__
		endpoint.address = (uint32_t) address.sin_addr.S_un.S_addr;
		#else
		endpoint.address = (uint32_t) address.sin_addr.s_addr;
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

ipv4_t UDP::hostToIPv4( const std::string &host )
{
    if (host.empty()) return ipv4_t();

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    inet_pton(AF_INET, host.c_str(), &address.sin_addr);
    return ipv4_t(address.sin_addr.s_addr);
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