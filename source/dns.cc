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

dns_record_t::dns_record_t( const dns_record_t &that )
{
    qname = that.qname;
    type  = that.type ;
    clazz = that.clazz;
    ttl = that.ttl;
    rdlen = that.rdlen;
    memcpy(rdata, that.rdata, sizeof(rdata));
}

dns_record_t::dns_record_t( dns_record_t &&that )
{
    qname.swap(that.qname);
    type  = that.type ;
    clazz = that.clazz;
    ttl = that.ttl;
    rdlen = that.rdlen;
    memcpy(rdata, that.rdata, sizeof(rdata));
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
    for (int i = 0; i < anc; ++i)
    {
        dns_record_t entry;
        if (entry.read(bio))
        answers.push_back(std::move(entry));
    }
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
    if (rdlen > sizeof(rdata)) return;
    bio.writeQName(qname);
    bio.writeU16(type);
    bio.writeU16(clazz);
    bio.writeU32(ttl);
    bio.writeU16(rdlen);
    for (int i = 0; i < rdlen; ++i)
        bio.writeU8(rdata[i]);
}

bool dns_record_t::read( buffer &bio )
{
    qname = bio.readQName();
    type = bio.readU16();
    clazz = bio.readU16();
    ttl = bio.readU32();
    rdlen = bio.readU16();
    if (rdlen > sizeof(rdata))
    {
        bio.skip(rdlen);
        return false;
    }
    for (int i = 0; i < rdlen; ++i)
        rdata[i] = bio.readU8();
    return true;
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

Resolver::Resolver( int timeout ) : id_(0)
{
}

Resolver::~Resolver()
{
}

uint16_t Resolver::next_id()
{
    std::unique_lock<std::shared_mutex> guard(id_mutex_);
    if (++id_ == 0) ++id_;
    return id_;
}

uint16_t Resolver::send( Endpoint &endpoint, dns_buffer_t &response )
{
    dns_header_tt &header = *((dns_header_tt*) response.content);
    header.id = next_id();

    if (!conn_.send(endpoint, response.content, response.size))
        return 0;
    else
        return header.id;
}

int Resolver::receive( dns_buffer_t &response, int timeout )
{
    Endpoint endpoint;
    size_t size = response.size = sizeof(response.content);
    if (conn_.receive(endpoint, response.content, &size, timeout))
        return response.size = size;
    return -1;
}

Cache::Cache( int size , int ttl ) : size_(size), ttl_(ttl)
{
}

Cache::~Cache()
{
}

int Cache::find_ipv4( const std::string &host, dns_buffer_t &response )
{
    return find(host + "_4", response);
}

#ifdef ENABLE_IPV6
int Cache::find_ipv6( const std::string &host, dns_buffer_t &response )
{
    return find(host + "_6", response);
}
#endif

int Cache::find( const std::string &host, dns_buffer_t &response )
{
    std::shared_lock<std::shared_mutex> guard(lock_);
    uint64_t now = dns_time();

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
    if (ttl = 0) ttl = ttl_;

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

void Cache::dump( std::ostream &out )
{
#if 0
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
#endif
}

#ifdef ENABLE_IPV6
void Cache::append_ipv6( const std::string &host, const dns_buffer_t &response )
{
    return append(host + "_6", response);
}
#endif

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
        entry.timestamp = dns_time();
        entry.message = response;
    }
}

}