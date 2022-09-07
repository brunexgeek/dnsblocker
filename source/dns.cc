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

static uint64_t dns_time()
{
    static std::chrono::high_resolution_clock::time_point startTime = std::chrono::high_resolution_clock::now();
    return (uint64_t) std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - startTime).count();
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
    header.id = id & 0x7FFF;

    if (!conn_.send(endpoint, request.content, request.size))
        return 0;
    else
        return header.id;
}

int Resolver::receive( dns_buffer_t &response, int timeout )
{
    Endpoint endpoint;
    size_t size = response.size = sizeof(response.content);
    if (conn_.receive(endpoint, response.content, &size, timeout))
        return (int) (response.size = size);
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

int Cache::find_ipv6( const std::string &host, dns_buffer_t &response )
{
    return find(host + "_6", response);
}

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
    if (ttl == 0) ttl = ttl_;

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
        entry.timestamp = dns_time();
        entry.message = response;
    }
}

}