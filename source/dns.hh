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
#include <mutex>


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

#define DNS_RCODE_NOERROR        0
#define DNS_RCODE_SERVFAIL       2
#define DNS_RCODE_NXDOMAIN       3
#define DNS_RCODE_REFUSED        5


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
    void read( BufferIO &bio );
    void write( BufferIO &bio );
};


struct dns_question_t
{
    std::string qname;
    uint16_t type;
    uint16_t clazz;

    dns_question_t();
    dns_question_t( const dns_question_t &obj );
    void read( BufferIO &bio );
    void write( BufferIO &bio );
    void print() const;
};

struct dns_record_t
{
    std::string qname;
    uint16_t type;
    uint16_t clazz;
    uint32_t ttl;
    uint16_t rdlen;
    Address rdata;  // IPv4 or IPv6

    dns_record_t();
    void read( BufferIO &bio );
    void write( BufferIO &bio );
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
    void swap( dns_message_t &that );
    void read( BufferIO &bio );
    void write( BufferIO &bio );
    void print() const;
};

struct dns_cache_t
{
    uint32_t timestamp;
    Address ipv4;
    Address ipv6;
    //uint32_t hits;
};


struct DNSCache
{
    public:
        DNSCache(
            int size = DNS_CACHE_LIMIT,
            int ttl = DNS_CACHE_TTL,
            int timeout = DNS_TIMEOUT );

        ~DNSCache();
        int resolve( const std::string &host, int type, Address *dnsAddress, Address *output );
        void dump( const std::string &path );
        void cleanup( uint32_t ttl );
        void reset();
        void setDefaultDNS( const std::string &dns );
        void addTarget( const std::string &rule, const std::string &dns );

    private:
        int size_;
        int ttl_;
        Address defaultDNS_;
        std::unordered_map<std::string, dns_cache_t> cache_;
        Tree<uint32_t> targets_;
        struct
        {
            uint32_t cache;
            uint32_t external;
        } hits_;
        int timeout_;
        std::mutex lock_;

        int recursive( const std::string &host, int type, Address dnsAddress, Address *address );
        Address nameserver( const std::string &host );
};


#endif
