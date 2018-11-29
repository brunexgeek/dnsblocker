#include <stdint.h>
#include <string>
#include <vector>
#include "config.hh"
#include "log.hh"
#include "buffer.hh"


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

static const uint16_t DNS_TYPE_A      = 1;
static const uint16_t DNS_TYPE_NS     = 2;
static const uint16_t DNS_TYPE_CNAME  = 5;
static const uint16_t DNS_TYPE_PTR    = 12;
static const uint16_t DNS_TYPE_MX     = 15;
static const uint16_t DNS_TYPE_TXT    = 16;
static const uint16_t DNS_TYPE_AAAA   = 28;



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
};

struct dns_record_t
{
    std::string qname;
    uint16_t type;
    uint16_t clazz;
    uint32_t ttl;
    //uint16_t rdlen;
    uint32_t rdata;  // IPv4

    dns_record_t();
    void read( BufferIO &bio );
    void write( BufferIO &bio );
};

struct dns_message_t
{
    dns_header_t header;
    std::vector<dns_question_t> questions;
    std::vector<dns_record_t> answers;
    std::vector<dns_record_t> authority;
    std::vector<dns_record_t> additional;

    void read( BufferIO &bio );
    void write( BufferIO &bio );
};


#ifdef ENABLE_RECURSIVE_DNS

bool dns_cache(
    const std::string &host,
    uint32_t *address );

bool dns_recursive(
    const std::string &host,
    uint32_t *address );

void dns_cacheInfo();


#endif
