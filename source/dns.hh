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
#define DNSB_STATUS_BLOCKED      5 // custom
#define DNSB_STATUS_HEURISTIC    6 // custom

#define DNS_RCODE_NOERROR        0
#define DNS_RCODE_SERVFAIL       2
#define DNS_RCODE_NXDOMAIN       3
#define DNS_RCODE_REFUSED        5

namespace dnsblocker {

struct dns_header_t
{
    uint16_t id;
    uint16_t flags;
    uint8_t opcode;
    uint8_t rcode;
    uint16_t qdcount; // query count
    uint16_t ancount; // answer count
    uint16_t nscount; // name server count
    uint16_t arcount; // additional record count

    dns_header_t();
    dns_header_t( const dns_header_t & ) = default;
    void read( buffer &bio );
    void write( buffer &bio );
};

struct dns_question_t
{
    std::string qname;
    uint16_t type;
    uint16_t clazz;

    dns_question_t();
    dns_question_t( const dns_question_t &obj );
    void read( buffer &bio );
    void write( buffer &bio );
    void print() const;
};

struct dns_record_t
{
    std::string qname;
    uint16_t type;
    uint16_t clazz;
    uint32_t ttl;
    uint16_t rdlen;
    uint8_t rdata[16];  // IPv4 or IPv6

    dns_record_t();
    void read( buffer &bio );
    void write( buffer &bio );
    void print() const;
};

struct dns_message_t
{
    dns_header_t header;
    std::vector<dns_question_t> questions;
    std::vector<dns_record_t> answers;
    std::vector<dns_record_t> authority;
    std::vector<dns_record_t> additional;

    dns_message_t();
    dns_message_t( dns_message_t &&that );
    void swap( dns_message_t &that );
    void read( buffer &bio );
    void write( buffer &bio );
    void print() const;
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

struct CacheEntry
{
    uint64_t timestamp;
    ipv6_t ipv6;
    ipv4_t ipv4;
};

struct Cache
{
    public:
        Cache( int size = DNS_CACHE_LIMIT, int ttl = DNS_CACHE_TTL );
        ~Cache();
        int find( const std::string &host, ipv4_t *value );
        int find( const std::string &host, ipv6_t *value );
        void add( const std::string &host, const ipv4_t *ipv4, const ipv6_t *ipv6 );
        void dump( std::ostream &out );
        void cleanup( uint32_t ttl );
        void reset();

    private:
        int size_;
        int ttl_;
        std::unordered_map<std::string, CacheEntry> cache_;
        std::shared_mutex lock_;

        bool get( const std::string &host, ipv4_t *ipv4, ipv6_t *ipv6 );
};

class Resolver
{
    public:
        Resolver( Cache &cache, int timeout = 1000 );
        ~Resolver();
        void set_dns( const std::string &dns, const std::string &name );
        void set_dns( const std::string &dns, const std::string &name, const std::string &rule );
        //int resolve( const std::string &host, int type, std::string &name, Address &output );
        int resolve_ipv4( const std::string &host, std::string &name, ipv4_t &output );
        int resolve_ipv6( const std::string &host, std::string &name, ipv6_t &output );
        static int initiate_recursive( UDP &conn, const std::string &host, int type, const ipv4_t &dnsAddress, uint16_t &id );

    private:
        struct
        {
            uint32_t cache;
            uint32_t external;
        } hits_;
        named_value<ipv4_t> default_dns_;
        Tree<named_value<ipv4_t>> target_dns_;
        Cache &cache_;
        int timeout_;

        int recursive( const std::string &host, int type, const ipv4_t &dnsAddress, ipv4_t *ipv4, ipv6_t *ipv6 );
};

}

#endif

