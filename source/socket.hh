#ifndef DNSB_SOCKET_HH
#define DNSB_SOCKET_HH


#include <string>
#include <stdint.h>


#define SOCKET_IP_O1(x)          (((x) & 0xFF000000) >> 24)
#define SOCKET_IP_O2(x)          (((x) & 0x00FF0000) >> 16)
#define SOCKET_IP_O3(x)          (((x) & 0x0000FF00) >> 8)
#define SOCKET_IP_O4(x)          ((x) & 0x000000FF)

#define SOCKET_IP_O1(x)          (((x) & 0xFF000000) >> 24)
#define SOCKET_IP_O2(x)          (((x) & 0x00FF0000) >> 16)
#define SOCKET_IP_O3(x)          (((x) & 0x0000FF00) >> 8)
#define SOCKET_IP_O4(x)          ((x) & 0x000000FF)

#define ADDR_TYPE_A            (uint16_t) 1
#define ADDR_TYPE_AAAA         (uint16_t) 28


struct Address
{
	std::string name;
    int type;
    union
    {
        uint32_t ipv4;
        uint16_t ipv6[8];
    };

	Address();
	explicit Address( uint32_t ipv4, const std::string &name = "" );
	Address( const Address &that );
	std::string toString() const;
	bool equivalent( const Address &address ) const;
	bool operator==( const Address &that ) const;
	bool invalid() const;
	bool local() const;
};


struct Endpoint
{
	Address address;
	uint16_t port;

	Endpoint();
	Endpoint( const Endpoint &that );
	Endpoint( const Address &address, uint16_t port );
	Endpoint( const uint32_t &ipv4, uint16_t port );
	Endpoint( const std::string &ipv4, uint16_t port );
};


class UDP
{
	public:
		UDP();
		~UDP();

		bool send( const Endpoint &endpoint, const uint8_t *data, size_t size );
		bool receive( Endpoint &endpoint, uint8_t *data, size_t *size, int timeout = 10000 );
		bool poll( int timeout );
		static uint32_t hostToIPv4( const std::string &host );
		void close();
		bool bind( const std::string &host, uint16_t port );

	private:
		void *ctx;
};


#endif //DNSB_SOCKET_HH