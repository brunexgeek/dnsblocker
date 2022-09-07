#ifndef DNSB_DNS_HH
#define DNSB_DNS_HH

#include <stdint.h>
#include <string>
#include <vector>
#include <unordered_map>
#include "defs.hh"
#include "log.hh"
#include "nodes.hh"
#include "socket.hh"
#include <shared_mutex>

#define DNS_FLAG_QR           (1 << 15) // Query/Response
#define DNS_FLAG_AA           (1 << 10) // Authoritative Answer
#define DNS_FLAG_TC           (1 <<  9) // message TrunCation
#define DNS_FLAG_RD           (1 <<  8) // Recursion Desired
#define DNS_FLAG_RA           (1 <<  7) // Recursion Available
#define DNS_FLAG_Z            (1 <<  6) // reserved for future use
#define DNS_FLAG_AD           (1 <<  5) // Authentic Data
#define DNS_FLAG_CD           (1 <<  4) // Checking Disabled

#define DNS_IP_O1(x)          (((x) & 0xFF000000) >> 24)
#define DNS_IP_O2(x)          (((x) & 0x00FF0000) >> 16)
#define DNS_IP_O3(x)          (((x) & 0x0000FF00) >> 8)
#define DNS_IP_O4(x)          ((x) & 0x000000FF)

#define DNS_TYPE_A            (uint16_t) 1
#define DNS_TYPE_NS           (uint16_t) 2
#define DNS_TYPE_CNAME        (uint16_t) 5
#define DNS_TYPE_PTR          (uint16_t) 12
#define DNS_TYPE_MX           (uint16_t) 15
#define DNS_TYPE_TXT          (uint16_t) 16
#define DNS_TYPE_AAAA         (uint16_t) 28

#define DNSB_STATUS_CACHE        1
#define DNSB_STATUS_RECURSIVE    2
#define DNSB_STATUS_NXDOMAIN     3
#define DNSB_STATUS_FAILURE      4
#define DNSB_STATUS_BLOCK        5

#define DNS_RCODE_NOERROR        0
#define DNS_RCODE_FORMERR        1
#define DNS_RCODE_SERVFAIL       2
#define DNS_RCODE_NXDOMAIN       3
#define DNS_RCODE_NOTIMP         4
#define DNS_RCODE_REFUSED        5

namespace dnsblocker {

struct dns_question_t
{
    // skip qname (variable length field)
    uint16_t type;
    uint16_t clazz;
};

struct dns_header_t
{
	uint16_t id; // identification number

	uint8_t rd :1; // recursion desired
	uint8_t tc :1; // truncated message
	uint8_t aa :1; // authoritive answer
	uint8_t opcode :4; // purpose of message
	uint8_t qr :1; // query/response flag

	uint8_t rcode :4; // response code
	uint8_t cd :1; // checking disabled
	uint8_t ad :1; // authenticated data
	uint8_t z :1; // its z! reserved
	uint8_t ra :1; // recursion available

	uint16_t q_count; // number of question entries
	uint16_t ans_count; // number of answer entries
	uint16_t auth_count; // number of authority entries
	uint16_t add_count; // number of resource entries
};

#ifndef DNS_MESSAGE_SIZE
#define DNS_MESSAGE_SIZE 512
#endif

struct dns_buffer_t
{
    uint8_t content[DNS_MESSAGE_SIZE];
    size_t size = DNS_MESSAGE_SIZE;
};

struct CacheEntry
{
    uint64_t timestamp;
    dns_buffer_t message;
    bool nxdomain;
};

struct Cache
{
    public:
        Cache( int size = DNS_CACHE_LIMIT, int ttl = DNS_CACHE_TTL );
        ~Cache();
        int find_ipv4( const std::string &host, dns_buffer_t &response );
        void append_ipv4( const std::string &host, const dns_buffer_t &response );
        int find_ipv6( const std::string &host, dns_buffer_t &response );
        void append_ipv6( const std::string &host, const dns_buffer_t &response );
        void dump( std::ostream &out );
        size_t cleanup( uint32_t ttl );
        size_t reset();

    private:
        int size_;
        int ttl_;
        std::unordered_map<std::string, CacheEntry> cache_;
        std::shared_mutex lock_;

        int find( const std::string &host, dns_buffer_t &response );
        void append( const std::string &host, const dns_buffer_t &response );
};

class Resolver
{
    public:
        Resolver();
        ~Resolver();
        uint16_t send( const Endpoint &endpoint, dns_buffer_t &response, uint16_t id );
        int receive( dns_buffer_t &response, int timeout = 0);
        uint16_t next_id();

    private:
        UDP conn_;
        std::shared_mutex id_mutex_;
        uint16_t id_;

};

}

#endif

