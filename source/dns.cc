#include "dns.hh"
#include <stdio.h>
#include <string>
#include <string>
#include "log.hh"
#include "socket.hh"
#include <chrono>
#include <unordered_map>
#include <atomic>

#ifndef __WINDOWS__
#include <poll.h>
#else
typedef int ssize_t;
#endif


#define DNS_GET_OPCODE(x)     (uint8_t) (((x) >> 11) & 15)
#define DNS_GET_RCODE(x)      (uint8_t) ((x) & 15)

#define DNS_SET_OPCODE(x,v)   ( x = (uint16_t) ( x | ( (v) & 15 ) << 11) )
#define DNS_SET_RCODE(x,v)    ( x = (uint16_t) ( x | ( (v) & 15 )) )


dns_header_t::dns_header_t()
{
    id = flags = qdcount = ancount = nscount = arcount = 0;
    opcode = rcode = 0;
}

dns_question_t::dns_question_t()
{
    type = clazz = 0;
}

dns_question_t::dns_question_t( const dns_question_t &obj )
{
    qname = obj.qname;
    type = obj.type;
    clazz = obj.clazz;
}

dns_record_t::dns_record_t()
{
    type = clazz = 0;
    ttl = 0;
}

void dns_header_t::read(
    BufferIO &bio )
{
    id = bio.readU16();
    flags = bio.readU16();
    opcode = DNS_GET_OPCODE(flags);
    rcode = DNS_GET_RCODE(flags);
    qdcount = bio.readU16();
    ancount = bio.readU16();
    nscount = bio.readU16();
    arcount = bio.readU16();
}


void dns_header_t::write(
    BufferIO &bio )
{
    DNS_SET_OPCODE(flags, opcode);
    DNS_SET_RCODE(flags, rcode);

    bio.writeU16(id);
    bio.writeU16(flags);
    bio.writeU16(qdcount);
    bio.writeU16(ancount);
    bio.writeU16(nscount);
    bio.writeU16(arcount);
}


void dns_question_t::read(
    BufferIO &bio )
{
    qname = bio.readQName();
    type = bio.readU16();
    clazz = bio.readU16();
}

void dns_question_t::write(
    BufferIO &bio )
{
    bio.writeQName(qname);
    bio.writeU16(type);
    bio.writeU16(clazz);
}


void dns_question_t::print() const
{
    LOG_MESSAGE("   [qname: '%s', type: %d, class: %d]\n",
        qname.c_str(), type, clazz);
}


dns_message_t::dns_message_t()
{
}


void dns_message_t::swap( dns_message_t &that )
{
    header = that.header;
    questions.swap(that.questions);
    answers.swap(that.answers);
    authority.swap(that.authority);
    additional.swap(that.additional);
}


void dns_message_t::read(
    BufferIO &bio )
{
    questions.clear();
    answers.clear();
    authority.clear();
    additional.clear();

    // read the message header
    header.read(bio);
    header.nscount = 0;
    header.arcount = 0;
    // read the questions
    questions.resize(header.qdcount);
    for (auto it = questions.begin(); it != questions.end(); ++it) it->read(bio);
    // read the answer records
    answers.resize(header.ancount);
    for (auto it = answers.begin(); it != answers.end(); ++it) it->read(bio);
}


void dns_message_t::write(
    BufferIO &bio )
{
    header.qdcount = (uint16_t) questions.size();
    header.ancount = (uint16_t) answers.size();
    header.nscount = 0;
    header.arcount = 0;

    // write the header
    header.write(bio);
    // write the questions
    for (auto it = questions.begin(); it != questions.end(); ++it) it->write(bio);
    // write the answer records
    for (auto it = answers.begin(); it != answers.end(); ++it) it->write(bio);
}


void dns_message_t::print() const
{
    LOG_MESSAGE("[qdcount: %d, ancount: %d, nscount: %d, arcount: %d]\n",
        header.qdcount, header.ancount, header.nscount, header.arcount);
    LOG_MESSAGE("questions:\n");
    for (auto it = questions.begin(); it != questions.end(); ++it) it->print();
    LOG_MESSAGE("answers:\n");
    for (auto it = answers.begin(); it != answers.end(); ++it) it->print();
}


void dns_record_t::write(
    BufferIO &bio )
{
    bio.writeQName(qname);
    bio.writeU16(type);
    bio.writeU16(clazz);
    bio.writeU32(ttl);
    bio.writeU16(4);
    bio.writeU32(rdata);
}

void dns_record_t::read(
    BufferIO &bio )
{
    qname = bio.readQName();
    type = bio.readU16();
    clazz = bio.readU16();
    ttl = bio.readU32();
    rdlen = bio.readU16();
    rdata = 0;
    if (rdlen == 4)
        rdata = bio.readU32();
    else
        bio.skip(rdlen);
}


void dns_record_t::print() const
{
    if (rdlen != 4)
        LOG_MESSAGE("   [qname: '%s', type: %d, class: %d, ttl: %d, len: %d]\n",
            qname.c_str(), type, clazz, ttl, rdlen);
    else
        LOG_MESSAGE("   [qname: '%s', type: %d, class: %d, ttl: %d, len: %d, addr: %d.%d.%d.%d]\n",
            qname.c_str(), type, clazz, ttl, rdlen, DNS_IP_O1(rdata), DNS_IP_O2(rdata),
            DNS_IP_O3(rdata), DNS_IP_O4(rdata));
}


#ifdef __WINDOWS__
#include <WinSock2.h>
#include <WS2tcpip.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#endif


DNSCache::DNSCache(
    int size ,
    int ttl,
    int timeout ) : size(size), ttl(ttl), timeout(timeout)
{
    defaultDNS = UDP::hostToIPv4("8.8.4.4");
    hits.cache = hits.external = 0;
}


DNSCache::~DNSCache()
{
}


int DNSCache::recursive(
    const std::string &host,
    uint32_t dnsAddress,
    uint32_t *output )
{
    static std::atomic<uint16_t> lastId(1);
    *output = 0;

    // build the query message
    dns_message_t message;
    message.header.id = lastId.fetch_add(1);
    message.header.flags |= DNS_FLAG_RD;
    message.header.flags |= DNS_FLAG_AD;
    dns_question_t question;
    question.qname = host;
    question.type = DNS_TYPE_A;
    question.clazz = 1;
    message.questions.push_back(question);
    // encode the message
    BufferIO bio(DNS_BUFFER_SIZE);
    message.write(bio);

    // send the query to the recursive DNS
    Endpoint endpoint(dnsAddress, 53);
	UDP conn;
	if (!conn.send(endpoint, bio.buffer, bio.cursor())) return DNSB_STATUS_FAILURE;

	if (!conn.poll(timeout)) return DNSB_STATUS_FAILURE;

    // wait for the response
    bio.reset();

	if (!conn.receive(endpoint, bio.buffer, &bio.size)) return DNSB_STATUS_FAILURE;

	FILE *temp = fopen("D:\\Users\\bruno\\AppData\\Local\\Temp\\last-udp", "wb+");
	if (temp != nullptr)
	{
		fwrite(bio.buffer, 1, bio.size, temp);
		fclose(temp);
	}

    // decode the response
    message.read(bio);

    // use the first 'type A' answer
    if (message.header.rcode == 0 &&
        message.answers.size() > 0 &&
        message.questions.size() == 1 &&
        message.questions[0].qname == host)
    {
        for (auto it = message.answers.begin(); it != message.answers.end(); ++it)
            if (it->type == DNS_TYPE_A) *output = it->rdata;
    }

#if 0
    if (message.header.rcode == 0)
        LOG_MESSAGE("-- tells '%s' is %d.%d.%d.%d\n",
            host.c_str(),
            DNS_IP_O1(*output),
            DNS_IP_O2(*output),
            DNS_IP_O3(*output),
            DNS_IP_O4(*output));
#endif
    return (*output == 0) ? DNSB_STATUS_NXDOMAIN : DNSB_STATUS_RECURSIVE;
}


static uint32_t dns_time()
{
    static std::chrono::high_resolution_clock::time_point startTime = std::chrono::high_resolution_clock::now();
    return (uint32_t) std::chrono::duration_cast<std::chrono::seconds>(std::chrono::high_resolution_clock::now() - startTime).count();
}


void DNSCache::cleanup( uint32_t ttl )
{
    if (ttl <= 0 || ttl <= (DNS_CACHE_TTL / 3))
        ttl = DNS_CACHE_TTL / 3;

    std::lock_guard<std::mutex> raii(lock);

    uint32_t currentTime = dns_time();
    size_t count = cache.size();

    for (auto it = cache.begin(); it != cache.end();)
    {
        if (currentTime <= it->second.timestamp + ttl)
            it = cache.erase(it);
        else
             ++it;
    }

    if (count != cache.size())
        LOG_MESSAGE("\nCache: removed %d entries and kept %d entries\n\n", count - cache.size(), cache.size());
}


uint32_t DNSCache::nameserver( const std::string &host )
{
    std::lock_guard<std::mutex> raii(lock);

    const Node<uint32_t> *node = targets.match(host);
    if (node == nullptr) return defaultDNS;
    return node->value;
}


int DNSCache::resolve(
    const std::string &host,
    uint32_t *dnsAddress,
    uint32_t *output )
{
    uint32_t currentTime = dns_time();

    {
        if (cache.size() > DNS_CACHE_LIMIT) cleanup(DNS_CACHE_TTL - DNS_CACHE_TTL / 4);

		std::lock_guard<std::mutex> raii(lock);

        *dnsAddress = 0;
        *output = 0;

        auto it = cache.find(host);
        // try to use cache information
        if (it != cache.end())
        {
            // check whether the cache entry still valid
            if (currentTime <= it->second.timestamp + DNS_CACHE_TTL)
            {
                *output = it->second.address;
                ++hits.cache;
                it->second.timestamp = currentTime;
                return DNSB_STATUS_CACHE;
            }
        }

        // check if we have a specific DNS server for this domain
        *dnsAddress = defaultDNS;
        const Node<uint32_t> *node = targets.match(host);
        if (node != nullptr && node->value != 0) *dnsAddress = node->value;
    }

    bool store = true;

    // try to resolve the domain using the external DNS
    int result = recursive(host, *dnsAddress, output);
    if (result != DNSB_STATUS_RECURSIVE && *dnsAddress == defaultDNS)
        return result;
    // if the previous resolution failed, try again using the default DNS server
    if (result == DNSB_STATUS_FAILURE)
    {
        store = false;
        *dnsAddress = defaultDNS;
        result = recursive(host, defaultDNS, output);
        if (result != DNSB_STATUS_RECURSIVE) return result;
    }

    if (*output != 0 && store)
    {
        std::lock_guard<std::mutex> raii(lock);

        ++hits.external;
        dns_cache_t &entry = cache[host];
        entry.address = *output;
        entry.timestamp = currentTime;
    }

    return result;
}


void DNSCache::dump( const std::string &path )
{
    std::lock_guard<std::mutex> raii(lock);

    FILE *output = fopen(path.c_str(), "wt");
    if (output != nullptr)
    {
        fprintf(output, "Hits: cache = %d, external = %d\n\n",
            hits.cache, hits.external);

        int removed = 0;
        char ipv4[16];
        uint32_t now = dns_time();
        for (auto it = cache.begin(); it != cache.end();)
        {
            uint32_t rt = 0;
            if (now <= it->second.timestamp + DNS_CACHE_TTL)
                rt = (it->second.timestamp + DNS_CACHE_TTL) - now;

            if (rt == 0)
            {
                // we use the opportunity to remove expired entries
                it = cache.erase(it);
                ++removed;
                continue;
            }

            sprintf(ipv4, "%d.%d.%d.%d",
                DNS_IP_O1(it->second.address),
                DNS_IP_O2(it->second.address),
                DNS_IP_O3(it->second.address),
                DNS_IP_O4(it->second.address));
            fprintf(output, "%-16s  %6d  %s\n",
                ipv4,
                rt,
                it->first.c_str());

            ++it;
        }

        if (removed > 0)
            LOG_MESSAGE("\nCache: removed %d entries and kept %d entries\n\n", removed, cache.size());

        fclose(output);
    }
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


void DNSCache::setDefaultDNS( const std::string &dns )
{
    defaultDNS = UDP::hostToIPv4(dns);
}


void DNSCache::addTarget( const std::string &rule, const std::string &dns )
{
    std::lock_guard<std::mutex> raii(lock);
    targets.add(rule, UDP::hostToIPv4(dns));
}

