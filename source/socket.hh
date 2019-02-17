#ifndef DNSB_SOCKET_HH
#define DNSB_SOCKET_HH


#include <string>
#include <stdint.h>


#define SOCKET_IP_O1(x)          (((x) & 0xFF000000) >> 24)
#define SOCKET_IP_O2(x)          (((x) & 0x00FF0000) >> 16)
#define SOCKET_IP_O3(x)          (((x) & 0x0000FF00) >> 8)
#define SOCKET_IP_O4(x)          ((x) & 0x000000FF)

struct Endpoint
{
	uint32_t address;
	uint16_t port;

	Endpoint();
	Endpoint( const Endpoint &that );
	Endpoint( uint32_t ipv4, uint16_t port );
	Endpoint( const std::string &ipv4, uint16_t port );
	static std::string addressToString( uint32_t address );
};


class UDP
{
	public:
		UDP();
		~UDP();

		bool send( const Endpoint &endpoint, const uint8_t *data, size_t size );
		bool receive( Endpoint &endpoint, uint8_t *data, size_t *size );
		bool poll( int timeout );
		static uint32_t hostToIPv4( const std::string &host );
		void close();
		bool bind( const std::string &host, uint16_t port );

	private:
		void *ctx;
};


#endif //DNSB_SOCKET_HH