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

struct ipv4_t
{
	uint8_t values[4];

	ipv4_t();
	explicit ipv4_t( const uint8_t * );
	explicit ipv4_t( const uint32_t & );
	ipv4_t( const ipv4_t & );
	ipv4_t( ipv4_t && );
	bool operator==( const ipv4_t & ) const;
	ipv4_t &operator=( const ipv4_t & );
	ipv4_t &operator=( const uint32_t & );
	uint32_t to_uint32() const;
	void clear();
	bool empty() const;
	std::string to_string() const;
};

struct ipv6_t
{
	uint16_t values[8];

	ipv6_t();
	explicit ipv6_t( const uint16_t *values );
	ipv6_t( const ipv6_t & );
	ipv6_t( ipv6_t && );
	bool operator==( const ipv6_t & ) const;
	ipv6_t &operator=( const ipv6_t & );
	void clear();
	bool empty() const;
	std::string to_string() const;
};

struct Address
{
	typedef ipv4_t ipv4_type;
	typedef ipv6_t ipv6_type;
    ipv4_t ipv4;
    ipv6_t ipv6;
	std::string name;

	Address();
	explicit Address( const ipv4_t &ipv4, const std::string &name = "" );
	explicit Address( const ipv6_t &ipv6, const std::string &name = "" );
	Address( const Address &that );
	std::string to_string() const;
	bool operator==( const Address &that ) const;
	bool empty() const;
	bool local() const;
	void clear();
};


struct Endpoint
{
	Address address;
	uint16_t port;

	Endpoint();
	Endpoint( const Endpoint &that );
	Endpoint( const Address &address, uint16_t port );
	Endpoint( const ipv4_t &ipv4, uint16_t port );
	Endpoint( const ipv6_t &ipv6, uint16_t port );
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
		static ipv4_t hostToIPv4( const std::string &host );
		void close();
		bool bind( const std::string &host, uint16_t port );

	private:
		void *ctx;
};


#endif //DNSB_SOCKET_HH