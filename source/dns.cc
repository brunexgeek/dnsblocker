#include "dns.hh"
#include <stdio.h>
#include <string>
#include <string>
#include "log.hh"
#include "socket.hh"
#include <chrono>
#include <unordered_map>
#include <atomic>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <shared_mutex>

#ifndef __WINDOWS__
#include <poll.h>
#include <netinet/in.h>
#else
typedef int ssize_t;
#endif

#define DNS_GET_OPCODE(x)     (uint8_t) (((x) >> 11) & 15)
#define DNS_GET_RCODE(x)      (uint8_t) ((x) & 15)

#define DNS_SET_OPCODE(x,v)   ( x = (uint16_t) ( x | ( (v) & 15 ) << 11) )
#define DNS_SET_RCODE(x,v)    ( x = (uint16_t) ( x | ( (v) & 15 )) )

#ifdef __WINDOWS__
#include <WinSock2.h>
#include <WS2tcpip.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#endif

namespace dnsblocker {

uint64_t dns_time_ms()
{
    using std::chrono::duration_cast;
    using std::chrono::steady_clock;
    static const steady_clock::time_point startTime = steady_clock::now();
    return (uint64_t) duration_cast<std::chrono::milliseconds>(steady_clock::now() - startTime).count();
}

Resolver::Resolver() : id_(0)
{
}

Resolver::~Resolver()
{
}

uint16_t Resolver::next_id()
{
    std::unique_lock<std::shared_mutex> guard(id_mutex_);
    id_ = (id_ + 1) & 0x7FFF;
    if (id_ == 0) ++id_;
    return id_;
}

uint16_t Resolver::send( const Endpoint &endpoint, dns_buffer_t &request, uint16_t id )
{
    dns_header_t &header = *((dns_header_t*) request.content);
    header.id = htobe16(id);

    if (!conn_.send(endpoint, request.content, request.size))
        return 0;
    else
        return id;
}

int Resolver::receive( dns_buffer_t &response, int timeout )
{
    Endpoint endpoint;
    size_t size = response.size = sizeof(response.content);
    if (conn_.receive(endpoint, response.content, &size, timeout))
        return (int) (response.size = size);
    return -1;
}

bool Resolver::ready( int timeout )
{
    return conn_.poll(timeout);
}

Cache::Cache( int size , int ttl ) : size_(size), ttl_(ttl * 1000)
{
}

Cache::~Cache()
{
}

int Cache::find_ipv4( const std::string &host, dns_buffer_t &response )
{
    return find(host + "_4", response);
}

int Cache::find_ipv6( const std::string &host, dns_buffer_t &response )
{
    return find(host + "_6", response);
}

int Cache::find( const std::string &host, dns_buffer_t &response )
{
    std::shared_lock<std::shared_mutex> guard(lock_);
    uint64_t now = dns_time_ms();

    // try to use cache information
    auto it = cache_.find(host);
    if (it == cache_.end()) return DNSB_STATUS_FAILURE;
    // check whether the cache entry still valid
    if (now <= it->second.timestamp + ttl_)
    {
        it->second.timestamp = now;
        // is it NXDOMAIN?
        if (it->second.nxdomain)
            return DNSB_STATUS_NXDOMAIN;
        response = it->second.message;
        return DNSB_STATUS_CACHE;
    }
    return DNSB_STATUS_FAILURE;
}

size_t Cache::reset()
{
    std::unique_lock<std::shared_mutex> guard(lock_);
    auto size = cache_.size();
    cache_.clear();
    return size;
}

size_t Cache::cleanup( uint32_t ttl )
{
    if (ttl == 0) ttl = ttl_;

    std::unique_lock<std::shared_mutex> guard(lock_);

    auto now = dns_time_ms();
    size_t count = cache_.size();

    for (auto it = cache_.begin(); it != cache_.end();)
    {
        if (now <= it->second.timestamp + ttl)
            it = cache_.erase(it);
        else
             ++it;
    }
    count = count - cache_.size();

    if (count != 0)
        LOG_MESSAGE("\nCache: removed %d entries and kept %d entries\n\n", count, cache_.size());
    return count;
}

void Cache::append_ipv6( const std::string &host, const dns_buffer_t &response )
{
    return append(host + "_6", response);
}

void Cache::append_ipv4( const std::string &host, const dns_buffer_t &response )
{
    return append(host + "_4", response);
}

void Cache::append( const std::string &host, const dns_buffer_t &response )
{
    std::unique_lock<std::shared_mutex> guard(lock_);

    auto it = cache_.find(host);
    if (it == cache_.end())
    {
        CacheEntry &entry = cache_[host];
        entry.nxdomain = false;
        entry.timestamp = dns_time_ms();
        entry.message = response;
    }
}

static const char *dns_opcode( int value )
{
    switch (value)
    {
        case 0: return "QUERY";
        case 1: return "IQUERY";
        case 2: return "STATUS";
        default: return "?????";
    }
}

const char *dns_rcode( int value )
{
    switch (value)
    {
        case 0: return "NOERROR";
        case 1: return "FORMERR";
        case 2: return "SERVFAIL";
        case 3: return "NXDOMAIN";
        case 4: return "NOTIMP";
        case 5: return "REFUSED";
        case 6: return "YXDOMAIN";
        case 7: return "XRRSET";
        case 8: return "NOTAUTH";
        case 9: return "NOTZONE";
        default: return "?????";
    }
}

const char *dns_type( int value )
{
    switch (value)
    {
        case 1: return "A";          // RFC 1035[1]
        case 2: return "NS";         // RFC 1035[1]
        case 5: return "CNAME";      // RFC 1035[1]
        case 6: return "SOA";        // RFC 1035[1] and RFC 2308[11]
        case 12: return "PTR";       // RFC 1035[1]
        case 13: return "HINFO";     // RFC 8482
        case 15: return "MX";        // RFC 1035[1] and RFC 7505
        case 16: return "TXT";       // RFC 1035[1]
        case 17: return "RP";        // RFC 1183
        case 18: return "AFSDB";     // RFC 1183
        case 24: return "SIG";       // RFC 2535
        case 25: return "KEY";       // RFC 2535[3] and RFC 2930[4]
        case 28: return "AAAA";      // RFC 3596[2]
        case 29: return "LOC";       // RFC 1876
        case 33: return "SRV";       // RFC 2782
        case 35: return "NAPTR";     // RFC 3403
        case 36: return "KX";        // RFC 2230
        case 37: return "CERT";      // RFC 4398
        case 39: return "DNAME";     // RFC 6672
        case 42: return "APL";       // RFC 3123
        case 43: return "DS";        // RFC 4034
        case 44: return "SSHFP";     // RFC 4255
        case 45: return "IPSECKEY";  // RFC 4025
        case 46: return "RRSIG";     // RFC 4034
        case 47: return "NSEC";      // RFC 4034
        case 48: return "DNSKEY";    // RFC 4034
        case 49: return "DHCID";     // RFC 4701
        case 50: return "NSEC3";     // RFC 5155
        case 51: return "NSEC3PARAM";// RFC 5155
        case 52: return "TLSA";      // RFC 6698
        case 53: return "SMIMEA";    // RFC 8162[9]
        case 55: return "HIP";       // RFC 8005
        case 59: return "CDS";       // RFC 7344
        case 60: return "CDNSKEY";   // RFC 7344
        case 61: return "OPENPGPKEY";// RFC 7929
        case 62: return "CSYNC";     // RFC 7477
        case 63: return "ZONEMD";    // RFC 8976
        case 64: return "SVCB";      // IETF Draft
        case 65: return "HTTPS";     // IETF Draft
        case 108: return "EUI48";    // RFC 7043
        case 109: return "EUI64";    // RFC 7043
        case 249: return "TKEY";     // RFC 2930
        case 250: return "TSIG";     // RFC 2845
        case 256: return "URI";      // RFC 7553
        case 257: return "CAA";      // RFC 6844
        case 32768: return "TA";     // — 	DNSSEC Trust Authorities
        case 32769: return "DLV";    // RFC 4431
        default: return "?????";
    }
}

size_t dns_parse_qname( const dns_buffer_t &message, size_t offset, std::string &qname )
{
    const uint8_t *buffer = message.content;
    const uint8_t *ptr = buffer + offset;
    if (ptr < buffer || ptr >= buffer + message.size) return 0;

    while (*ptr != 0)
    {
        // check whether the label is a pointer (RFC-1035 4.1.4. Message compression)
        if ((*ptr & 0xC0) == 0xC0)
        {
            size_t offset = ((ptr[0] & 0x3F) << 8) | ptr[1];
            dns_parse_qname(message, offset, qname);
            return (size_t) ((ptr + 2) - buffer);
        }

        int length = (int) (*ptr++) & 0x3F;
        for (int i = 0; i < length; ++i)
        {
            char c = (char) *ptr++;
            if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
            qname.push_back(c);
        }

        if (*ptr != 0) qname.push_back('.');
    }

    return (size_t) ((ptr + 1) - buffer);
}

static const uint8_t *read_u16( const uint8_t *ptr, uint16_t &value )
{
    value = static_cast<uint16_t>((ptr[0] << 8) | ptr[1]);
    return ptr + sizeof(uint16_t);
}

static const uint8_t *read_u32( const uint8_t *ptr, uint32_t &value )
{
    value = (uint32_t) ( (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3] );
    return ptr + sizeof(uint32_t);
}

Message::Message( const dns_buffer_t &buffer )
{
    parse(buffer);
}

Message::~Message()
{
    for (auto value : question_) free(value);
    for (auto value : answer_) free(value);
    for (auto value : authority_) free(value);
    for (auto value : additional_) free(value);
}

bool Message::parse( const dns_buffer_t &buffer )
{
    if (buffer.size >= sizeof(dns_header_t))
    {
        memcpy(&header_, buffer.content, sizeof(dns_header_t));
        header_.id = be16toh(header_.id);
        header_.qst_count = be16toh(header_.qst_count);
        header_.ans_count = be16toh(header_.ans_count);
        header_.auth_count = be16toh(header_.auth_count);
        header_.add_count = be16toh(header_.add_count);

        // question
        size_t offset = sizeof(dns_header_t);
        for (int i = 0; i < header_.qst_count; ++i)
        {
            auto value = parse_question(buffer, &offset);
            if (value == nullptr) return false;
            question_.push_back(value);
        }
        // answer
        for (int i = 0; i < header_.ans_count; ++i)
        {
            auto value = parse_record(buffer, &offset);
            if (value == nullptr) return false;
            answer_.push_back(value);
        }
        // authority
        for (int i = 0; i < header_.auth_count; ++i)
        {
            auto value = parse_record(buffer, &offset);
            if (value == nullptr) return false;
            authority_.push_back(value);
        }
        // additional
        for (int i = 0; i < header_.add_count; ++i)
        {
            auto value = parse_record(buffer, &offset);
            if (value == nullptr) return false;
            additional_.push_back(value);
        }
        buffer_ = &buffer;
        return true;
    }
    return false;
}

#define MEM_ALIGN(x) (((x) + 3) & ~3)

dns_question_t *Message::parse_question( const dns_buffer_t &buffer, size_t *offset )
{
    std::string qname;
    *offset = dns_parse_qname(buffer, *offset, qname);
    if (*offset == 0) return nullptr;

    dns_question_t *result = (dns_question_t*) malloc( MEM_ALIGN(qname.length() + 1) + sizeof(dns_question_t));
    if (result == nullptr) return nullptr;
    result->qname = (char*) result + sizeof(dns_question_t);

    strcpy(result->qname, qname.c_str());
    const uint8_t *ptr = buffer.content + *offset;
    ptr = read_u16(ptr, result->type);
    ptr = read_u16(ptr, result->clazz);
    *offset += sizeof(uint16_t) * 2;
    return result;
}

/*size_t dns_read_question( const dns_buffer_t &message, size_t offset, dns_question_t &question )
{
    offset = dns_parse_qname(message, offset, question.qname);
    if (offset == 0) return 0;
    const uint8_t *ptr = message.content + offset;
    read_u16(ptr, question.type);
    read_u16(ptr, question.clazz);
    return offset + sizeof(uint16_t) * 2;
}*/

dns_record_t *Message::parse_record( const dns_buffer_t &buffer, size_t *offset )
{
    std::string qname;
    *offset = dns_parse_qname(buffer, *offset, qname);
    if (*offset == 0) return nullptr;

    uint16_t type, clazz, rdlen;
    uint32_t ttl;
    const uint8_t *ptr = buffer.content + *offset;
    ptr = read_u16(ptr, type);
    ptr = read_u16(ptr, clazz);
    ptr = read_u32(ptr, ttl);
    ptr = read_u16(ptr, rdlen);

    if (buffer.size < (size_t) (ptr - buffer.content) + rdlen) return nullptr; // TODO: improve this check

    dns_record_t *result = (dns_record_t*) malloc( MEM_ALIGN(qname.length() + 1) + sizeof(dns_record_t) + MEM_ALIGN(rdlen));
    if (result == nullptr) return nullptr;
    result->qname = (char*) result + sizeof(dns_record_t);
    result->rdata = (uint8_t*) result->qname + MEM_ALIGN(qname.length() + 1);

    strcpy(result->qname, qname.c_str());
    memcpy(result->rdata, ptr, rdlen);
    ptr += rdlen;
    result->type = type;
    result->clazz = clazz;
    result->ttl = ttl;
    result->rdlen = rdlen;
    *offset = ptr - buffer.content;
    return result;
}

const dns_header_t *Message::header()
{
    return &header_;
}

const dns_question_t *Message::question( int index )
{
    if (index < 0 || index >= (int) question_.size()) return nullptr;
    return question_[index];
}

const dns_record_t *Message::answer( int index )
{
    if (index < 0 || index >= (int) answer_.size()) return nullptr;
    return answer_[index];
}

const dns_record_t *Message::authority( int index )
{
    if (index < 0 || index >= (int) authority_.size()) return nullptr;
    return authority_[index];
}

const dns_record_t *Message::additional( int index )
{
    if (index < 0 || index >= (int) additional_.size()) return nullptr;
    return additional_[index];
}

bool Message::is_valid() const
{
    return buffer_ != nullptr;
}

void print_dns_message( std::ostream &out, const dns_buffer_t &message )
{
#if 0
    const auto &header = *((dns_header_t*) message.content);

    std::string sid = "[";
    sid += std::to_string(be16toh(header.id));
    sid += "]";

    out << sid <<
        " opcode: " << dns_opcode(header.opcode) <<
        ", status: " << dns_rcode(header.rcode) <<
        ", flags:";

    if (header.rd) out << " rd";
	if (header.tc) out << " tc";
	if (header.aa) out << " aa";
	if (header.qr) out << " qr";
	if (header.cd) out << " cd";
	if (header.ad) out << " ad";
	if (header.z) out << " z";
	if (header.ra) out << " ra";

    out << "; QUERY: " << be16toh(header.q_count) <<
        ", ANSWER: " << be16toh(header.ans_count) <<
        ", AUTHORITY: " << be16toh(header.auth_count) <<
        ", ADDITIONAL: " << be16toh(header.add_count) << "\n";

    // questions
    //--for (int i = 0; i < be16toh(header.q_count); ++i)
    //--{
        dns_question_t question;
        dns_read_question(message, sizeof(dns_header_t), question);
        out << sid << " question " << 0 << " = " << question.qname << " IN " << dns_type(question.type) << "\n";
    //--}
#endif
}

}