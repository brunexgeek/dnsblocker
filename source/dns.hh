#ifndef DNSB_DNS_HH
#define DNSB_DNS_HH


#include <stdint.h>
#include <string>
#include <vector>
#include <unordered_map>
#include "defs.hh"
#include "log.hh"
#include "nodes.hh"
#include "buffer.hh"
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

struct dns_header_t
{
    uint16_t id;
    uint16_t flags;
    uint8_t opcode;
    uint8_t rcode;

    dns_header_t();
    dns_header_t( const dns_header_t & ) = default;
    dns_header_t( dns_header_t && ) = default;
    void swap( dns_header_t & );
};

struct dns_question_t
{
    std::string qname;
    uint16_t type;
    uint16_t clazz;

    dns_question_t();
    dns_question_t( const dns_question_t & ) = default;
    dns_question_t( dns_question_t && ) = default;
    void read( buffer &bio );
    void write( buffer &bio ) const;
};

struct dns_record_t
{
    std::string qname;
    uint16_t type;
    uint16_t clazz;
    uint32_t ttl;
    uint16_t rdlen;
    uint8_t rdata[64];

    dns_record_t();
    dns_record_t( const dns_record_t & ) ;
    dns_record_t( dns_record_t && ) ;
    bool read( buffer &bio );
    void write( buffer &bio ) const;
};

struct dns_message_t
{
    dns_header_t header;
    std::vector<dns_question_t> questions;
    std::vector<dns_record_t> answers;
    std::vector<dns_record_t> authority;
    std::vector<dns_record_t> additional;

    dns_message_t() = default;
    dns_message_t( const dns_message_t & ) = delete;
    dns_message_t( dns_message_t && ) = delete;
    void swap( dns_message_t &that );
    void read( buffer &bio );
    void write( buffer &bio ) const;
    void print() const;
};

struct dns_visitor_t
{
    dns_visitor_t() = default;
    dns_visitor_t( const dns_visitor_t& ) = delete;
    dns_visitor_t( dns_visitor_t&& ) = delete;
    virtual bool visit_message_header( uint16_t &id, const uint16_t flags, const uint8_t opcode, const uint8_t rcode );
    virtual bool visit_question( const uint16_t type, uint16_t clazz, const std::string &qname );
    virtual bool visit_answer( const std::string &qname, const uint16_t type, const uint16_t clazz, uint32_t &ttl,
        const uint16_t rdlen, const uint8_t *rdata );
    bool visit( const uint8_t *buffer, size_t size );
};

template<class T>
struct named_value
{
    typedef T type;
    std::string name;
    T value;

    named_value() {}
    named_value( const std::string &name, const T &value ) : name(name), value(value) {}
    named_value( const std::string &name, T &&value ) : name(name), value(value) {}
};

struct dns_question_tt
{
    // skip qname (variable length field)
    uint16_t type;
    uint16_t clazz;
};

struct dns_header_tt
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
        uint16_t send( Endpoint &endpoint, dns_buffer_t &response );
        int receive( dns_buffer_t &response, int timeout = 0);

    private:
        UDP conn_;
        std::shared_mutex id_mutex_;
        uint16_t id_;

        uint16_t next_id();
};

}

#endif

