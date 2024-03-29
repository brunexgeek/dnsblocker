#ifndef DNSB_SOCKET_HH
#define DNSB_SOCKET_HH

#include "defs.hh"
#include <string>
#include <stdint.h>

#define ADDR_TYPE_A            (uint16_t) 1
#define ADDR_TYPE_AAAA         (uint16_t) 28

struct ipv4_t
{
	static const ipv4_t EMPTY;
	static const ipv4_t NXDOMAIN;
	uint8_t values[4];

	ipv4_t();
	explicit ipv4_t( const uint8_t * );
	explicit ipv4_t( const uint32_t & );
	ipv4_t( const ipv4_t & );
	ipv4_t( ipv4_t && );
	ipv4_t( const std::string & );
	bool operator==( const ipv4_t & ) const;
	ipv4_t &operator=( const ipv4_t & );
	ipv4_t &operator=( const uint32_t & );
	uint32_t to_uint32() const;
	void clear();
	bool empty() const;
	std::string to_string() const;
};

template<>
struct std::hash<ipv4_t>
{
    std::size_t operator()(ipv4_t const& value) const noexcept
    {
        return value.to_uint32();
    }
};

struct ipv6_t
{
	static const ipv6_t EMPTY;
	static const ipv6_t NXDOMAIN;
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

struct Endpoint
{
	ipv4_t address;
	uint16_t port;

	Endpoint();
	Endpoint( const Endpoint &that );
	Endpoint( const ipv4_t &ipv4, uint16_t port );
	Endpoint( const std::string &ipv4, uint16_t port );
	Endpoint &operator=( const Endpoint &that ) = default;
};

class UDP
{
	public:
		UDP();
		UDP( const UDP &) = delete;
		UDP( UDP &&) = delete;
		~UDP();

		bool send( const Endpoint &endpoint, const uint8_t *data, size_t size );
		bool receive( Endpoint &endpoint, uint8_t *data, size_t *size, int timeout = 0 );
		bool poll( int timeout );
		static ipv4_t hostToIPv4( const std::string &host );
		void close();
		bool bind( const std::string &host, uint16_t port );

	private:
		void *ctx;
};


#endif // DNSB_SOCKET_HH