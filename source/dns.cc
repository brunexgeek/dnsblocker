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

namespace dnsblocker {

dns_header_t::dns_header_t() : id(0), flags(0), opcode(0), rcode(0)
{
}

void dns_header_t::swap( dns_header_t &that )
{
    std::swap(id, that.id);
    std::swap(flags, that.flags);
    std::swap(opcode, that.opcode);
    std::swap(rcode, that.rcode);
}

dns_question_t::dns_question_t() : type(0), clazz(0)
{
}

dns_record_t::dns_record_t()
{
    type = clazz = rdlen = 0;
    ttl = 0;
    memset(rdata, 0, sizeof(rdata));
}

void dns_question_t::read( buffer &bio )
{
    qname = bio.readQName();
    type = bio.readU16();
    clazz = bio.readU16();
}

void dns_question_t::write( buffer &bio ) const
{
    bio.writeQName(qname);
    bio.writeU16(type);
    bio.writeU16(clazz);
}

void dns_message_t::swap( dns_message_t &that )
{
    header.swap(that.header);
    questions.swap(that.questions);
    answers.swap(that.answers);
    authority.swap(that.authority);
    additional.swap(that.additional);
}

void dns_message_t::read( buffer &bio )
{
    questions.clear();
    answers.clear();
    authority.clear();
    additional.clear();

    // read the message header
    header.id = bio.readU16();
    header.flags = bio.readU16();
    header.opcode = DNS_GET_OPCODE(header.flags);
    header.rcode = DNS_GET_RCODE(header.flags);
    uint16_t qdc = bio.readU16(); // query count
    uint16_t anc = bio.readU16(); // answer count
    uint16_t nsc = bio.readU16(); // name server count
    uint16_t arc = bio.readU16(); // additional record count
    // read the questions
    questions.resize(qdc);
    for (auto &item : questions) item.read(bio);
    // read the answers
    answers.resize(anc);
    for (auto &item : answers) item.read(bio);
    #if 0
    // read the name servers
    authority.resize(nsc);
    for (auto &item : authority) item.read(bio);
    // read the additional records
    additional.resize(arc);
    for (auto &item : additional) item.read(bio);
    #endif
}

void dns_message_t::write( buffer &bio ) const
{
    // write the header
    uint16_t flags = header.flags;
    DNS_SET_OPCODE(flags, header.opcode);
    DNS_SET_RCODE(flags, header.rcode);
    bio.writeU16(header.id);
    bio.writeU16(flags);
    bio.writeU16( (uint16_t) questions.size() );
    bio.writeU16( (uint16_t) answers.size() );
    bio.writeU16( (uint16_t) authority.size() );
    bio.writeU16( (uint16_t) additional.size() );
    for (const auto &item : questions) item.write(bio);
    for (const auto &item : answers) item.write(bio);
    #if 0
    for (const auto &item : authority) item.write(bio);
    for (const auto &item : additional) item.write(bio);
    #endif
}

void dns_message_t::print() const
{
    LOG_MESSAGE("[qdcount: %d, ancount: %d, nscount: %d, arcount: %d]\n",
        (int) questions.size(), (int) answers.size(), (int) authority.size(), (int) additional.size());

    //LOG_MESSAGE("   [qname: '%s', type: %d, class: %d]\n", qname.c_str(), type, clazz);
    //for (auto it = questions.begin(); it != questions.end(); ++it) it->print();
    //for (auto it = answers.begin(); it != answers.end(); ++it) it->print();
}

void dns_record_t::write( buffer &bio ) const
{
    bio.writeQName(qname);
    bio.writeU16(type);
    bio.writeU16(clazz);
    bio.writeU32(ttl);
    if (type == ADDR_TYPE_A)
    {
        bio.writeU16(4);
        for (int i = 0; i < 4; ++i)
            bio.writeU8(rdata[i]);
    }
    else
    #ifdef ENABLE_IPV6
    if (type == ADDR_TYPE_AAAA)
    {
        const uint16_t *ptr = (const uint16_t*) rdata;
        bio.writeU16(16);
        for (int i = 0; i < 8; ++i)
            bio.writeU16(ptr[i]);
    }
    else
    #endif
    {
        // never should get here!
        bio.writeU16(4);
        bio.writeU32(0);
    }
}

void dns_record_t::read( buffer &bio )
{
    qname = bio.readQName();
    type = bio.readU16();
    clazz = bio.readU16();
    ttl = bio.readU32();
    rdlen = bio.readU16();
    if (rdlen == 4)
    {
        for (int i = 0; i < 4; ++i)
            rdata[i] = bio.readU8();
    }
    else
    #ifdef ENABLE_IPV6
    if (rdlen == 16)
    {
        uint16_t *ptr = (uint16_t*) rdata;
        for (int i = 0; i < 8; ++i)
            ptr[i] = bio.readU16();
    }
    else
    #endif
        bio.skip(rdlen);
}


/*void dns_record_t::print() const
{
    if (!rdata.empty())
    {
        LOG_MESSAGE("   [qname: '%s', type: %d, class: %d, ttl: %d, len: %d, addr: %d.%d.%d.%d]\n",
            qname.c_str(), type, clazz, ttl, rdlen, rdata.to_string().c_str());
    }
    else
    {
        LOG_MESSAGE("   [qname: '%s', type: %d, class: %d, ttl: %d, len: %d]\n",
            qname.c_str(), type, clazz, ttl, rdlen);
    }
}*/


#ifdef __WINDOWS__
#include <WinSock2.h>
#include <WS2tcpip.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#endif

static uint64_t dns_time()
{
    static std::chrono::high_resolution_clock::time_point startTime = std::chrono::high_resolution_clock::now();
    return (uint64_t) std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - startTime).count();
}

Cache::Cache( int size , int ttl ) : size_(size), ttl_(ttl)
{
}

Cache::~Cache()
{
}

int Cache::find( const std::string &host, ipv4_t *value )
{
    #ifdef ENABLE_IPV6
    if (get(host, value, nullptr))
    #else
    if (get(host, value))
    #endif
    {
        if (value->operator==(ipv4_t::NXDOMAIN))
            return DNSB_STATUS_NXDOMAIN;
        else
        if (value->empty())
            return DNSB_STATUS_FAILURE;
        return DNSB_STATUS_CACHE;
    }
    return DNSB_STATUS_FAILURE;
}

#ifdef ENABLE_IPV6
int Cache::find( const std::string &host, ipv6_t *value )
{
    if (get(host, nullptr, value))
    {
        if (value->operator==(ipv6_t::NXDOMAIN))
            return DNSB_STATUS_NXDOMAIN;
        else
        if (value->empty())
            return DNSB_STATUS_FAILURE;
        return DNSB_STATUS_CACHE;
    }
    return DNSB_STATUS_FAILURE;
}
#endif

#ifdef ENABLE_IPV6
bool Cache::get( const std::string &host, ipv4_t *ipv4, ipv6_t *ipv6 )
#else
bool Cache::get( const std::string &host, ipv4_t *ipv4 )
#endif
{
    #ifdef ENABLE_IPV6
    if (!ipv4 && !ipv6) return false;
    #else
    if (!ipv4) return false;
    #endif
    if (host.empty()) return false;
    uint64_t now = dns_time();

    std::shared_lock<std::shared_mutex> guard(lock_);

    auto it = cache_.find(host);
    // try to use cache information
    if (it != cache_.end())
    {
        // check whether the cache entry still valid
        if (now <= it->second.timestamp + ttl_)
        {
            if (ipv4) *ipv4 = it->second.ipv4;
            #ifdef ENABLE_IPV6
            if (ipv6) *ipv6 = it->second.ipv6;
            #endif
            it->second.timestamp = now;
            return true;
        }
    }
    return false;
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
    if (ttl <= 0) ttl = ttl_;

    std::unique_lock<std::shared_mutex> guard(lock_);

    auto now = dns_time();
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

Resolver::Resolver( Cache &cache, int timeout ) : cache_(cache), timeout_(timeout)
{
    default_dns_ = named_value<ipv4_t>("default", UDP::hostToIPv4("8.8.4.4"));
    hits_.cache = hits_.external = 0;
    if (timeout_ < 0) timeout_ = 100;
}

Resolver::~Resolver()
{
}

#ifdef ENABLE_IPV6
int Resolver::recursive( const std::string &host, int type, const ipv4_t &dnsAddress, ipv4_t *ipv4, ipv6_t *ipv6 )
#else
int Resolver::recursive( const std::string &host, int type, const ipv4_t &dnsAddress, ipv4_t *ipv4 )
#endif
{
    static std::atomic<uint16_t> lastId(1);

    // build the query message
    dns_message_t message;
    message.header.id = lastId.fetch_add(1);
    message.header.flags |= DNS_FLAG_RD;
    message.header.flags |= DNS_FLAG_AD;
    dns_question_t question;
    question.qname = host;
    question.type = (uint16_t) type;
    question.clazz = 1;
    message.questions.push_back(question);
    // encode the message
    buffer bio;
    message.write(bio);

    // send the query to the recursive DNS
    Endpoint endpoint(dnsAddress, 53);
	UDP conn;
	if (!conn.send(endpoint, bio.data(), bio.cursor())) return DNSB_STATUS_FAILURE;

	if (!conn.poll(timeout_)) return DNSB_STATUS_FAILURE;

    // wait for the response
    bio.reset();

    size_t size = bio.size();
	if (!conn.receive(endpoint, bio.data(), &size, 0)) return DNSB_STATUS_FAILURE;
    bio.resize(size);

    // decode the response
    message.read(bio);

    // use the first compatible answer
    if (message.header.rcode == 0 &&
        message.answers.size() > 0 &&
        message.questions.size() == 1 &&
        message.questions[0].qname == host)
    {
        for (auto it = message.answers.begin(); it != message.answers.end(); ++it)
        {
            if (it->type == type)
            {
                #ifdef ENABLE_IPV6
                if (type == ADDR_TYPE_AAAA)
                    *ipv6 = ipv6_t((uint16_t*)it->rdata);
                else
                #endif
                    *ipv4 = ipv4_t(it->rdata);
                return DNSB_STATUS_RECURSIVE;
            }
        }
    }

    return (message.header.rcode == DNS_RCODE_NXDOMAIN) ? DNSB_STATUS_NXDOMAIN : DNSB_STATUS_FAILURE;
}

int Resolver::resolve_ipv4( const std::string &host, std::string &name, ipv4_t &output )
{
    output.clear();

    // check wheter we have a match in the cache
    int result = cache_.find(host, &output);
    if (result != DNSB_STATUS_FAILURE)
        return result;

    // try to resolve the domain using the custom external DNS, if any
    auto node = target_dns_.match(host);
    if (node != nullptr && !node->value.value.empty())
    {
        result = recursive(host,
            ADDR_TYPE_A,
            node->value.value,
            &output
            #ifdef ENABLE_IPV6
            , nullptr
            #endif
            );
        if (result == DNSB_STATUS_RECURSIVE) name = node->value.name;
    }
    // try to resolve the domain using the defaylt external DNS
    if (result != DNSB_STATUS_RECURSIVE)
    {
        result = recursive(host,
            ADDR_TYPE_A,
            default_dns_.value,
            &output
            #ifdef ENABLE_IPV6
            ,nullptr
            #endif
            );
        if (result == DNSB_STATUS_RECURSIVE) name = default_dns_.name;
    }

    if (result == DNSB_STATUS_FAILURE) return result;

    if (result == DNSB_STATUS_RECURSIVE)
        #ifdef ENABLE_IPV6
        cache_.add(host, &output, nullptr);
        #else
        cache_.add(host, &output);
        #endif
    else
        #ifdef ENABLE_IPV6
        cache_.add(host, &ipv4_t::NXDOMAIN, nullptr);
        #else
        cache_.add(host, &ipv4_t::NXDOMAIN);
        #endif

    return result;
}

#ifdef ENABLE_IPV6
int Resolver::resolve_ipv6( const std::string &host, std::string &name, ipv6_t &output )
{
    output.clear();

    // check wheter we have a match in the cache
    int result = cache_.find(host, &output);
    if (result != DNSB_STATUS_FAILURE)
        return result;

    // try to resolve the domain using the custom external DNS, if any
    auto node = target_dns_.match(host);
    if (node != nullptr && !node->value.value.empty())
    {
        result = recursive(host, ADDR_TYPE_AAAA, node->value.value, nullptr, &output);
        if (result == DNSB_STATUS_RECURSIVE) name = node->value.name;
    }
    // try to resolve the domain using the defaylt external DNS
    if (result != DNSB_STATUS_RECURSIVE)
    {
        result = recursive(host, ADDR_TYPE_AAAA, default_dns_.value, nullptr, &output);
        if (result == DNSB_STATUS_RECURSIVE) name = default_dns_.name;
    }

    if (result == DNSB_STATUS_FAILURE) return result;

    if (result == DNSB_STATUS_RECURSIVE)
        cache_.add(host, nullptr, &output);
    else
        cache_.add(host, nullptr, &ipv6_t::NXDOMAIN);

    return result;
}
#endif

void Cache::dump( std::ostream &out )
{
    std::shared_lock<std::shared_mutex> raii(lock_);
    bool first = true;

    out << '[';
    for (auto &it : cache_)
    {
        if (!first) out << ',';

        if (!it.second.ipv4.empty())
        {
            out << "{\"ver\":\"4\",\"addr\":\"" << it.second.ipv4.to_string() << "\",\"name\":\"" << it.first << "\"}";
        }

        #ifdef ENABLE_IPV6
        if (!it.second.ipv6.empty())
        {
            if (!it.second.ipv4.empty()) out << ',';
            out << "{\"ver\":\"6\",\"addr\":\"" << it.second.ipv6.to_string() << "\",\"name\":\"" << it.first << "\"}";
        }
        #endif

        first = false;
    }
    out << ']';
}

/*
uint32_t DNSCache::addressToIPv4( const std::string &host )
{
    if (host.empty()) return 0;

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    inet_pton(AF_INET, host.c_str(), &address.sin_addr);
    return (uint32_t) address.sin_addr.s_addr;
}*/

void Resolver::set_dns( const std::string &dns, const std::string &name )
{
    default_dns_ = named_value<ipv4_t>(name, UDP::hostToIPv4(dns));
}

void Resolver::set_dns( const std::string &dns, const std::string &name, const std::string &rule )
{
    target_dns_.add(rule, named_value<ipv4_t>(name, UDP::hostToIPv4(dns)));
}

#ifdef ENABLE_IPV6
void Cache::add( const std::string &host, const ipv4_t *ipv4, const ipv6_t *ipv6 )
#else
void Cache::add( const std::string &host, const ipv4_t *ipv4 )
#endif
{
    std::unique_lock<std::shared_mutex> guard(lock_);

    auto it = cache_.find(host);
    if (it != cache_.end())
    {
        if (ipv4) it->second.ipv4 = *ipv4;
        #ifdef ENABLE_IPV6
        if (ipv6) it->second.ipv6 = *ipv6;
        #endif
        it->second.timestamp = dns_time();
    }
    else
    {
        CacheEntry entry;
        if (ipv4) entry.ipv4 = *ipv4;
        #ifdef ENABLE_IPV6
        if (ipv6) entry.ipv6 = *ipv6;
        #endif
        entry.timestamp = dns_time();
        cache_.insert(std::pair<std::string, CacheEntry>(host, entry));
    }
}

}