#include "dns.hh"
#include <stdio.h>
#include <string>
#include <string>
#include "log.hh"
#include <chrono>
#include <unordered_map>
#include <poll.h>


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
    uint16_t rdlen = bio.readU16();
    //log_message("%s %d %d %d %d\n", it->qname.c_str(), it->type, it->clazz, it->ttl, rdlen);
    rdata = 0;
    if (rdlen == 4)
        rdata = bio.readU32();
    else
        bio.skip(rdlen);
}


#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>


DNSCache::DNSCache(
    int size ,
    int ttl ,
    uint32_t dnsAddress ) : size(size), ttl(ttl), dnsAddress(dnsAddress)
{
    socketfd = socket(AF_INET, SOCK_DGRAM, 0);
    hits.cache = hits.external = 0;
}


DNSCache::~DNSCache()
{
    if (socketfd > 0) close(socketfd);
}


int DNSCache::recursive(
    const std::string &host,
    uint32_t *output )
{
    static uint16_t lastId = 0;

    *output = 0;

    // build the query message
    dns_message_t message;
    message.header.id = ++lastId;
    message.header.flags |= DNS_FLAG_RD;
    dns_question_t question;
    question.qname = host;
    question.type = DNS_TYPE_A;
    question.clazz = 1;
    message.questions.push_back(question);
    // encode the message
    BufferIO bio(DNS_BUFFER_SIZE);
    message.write(bio);
//log_message("Message encoded in %d bytes \n", bio.cursor());

//log_message("-- message encoded\n");
    // send the query to the recursive DNS
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = ntohl(dnsAddress);
    address.sin_port = htons(53);
    ssize_t nbytes = sendto(socketfd, bio.buffer, bio.cursor(), 0, (struct sockaddr *) &address, sizeof(address));
    if (nbytes < 0) return DNSB_STATUS_FAILURE;

    struct pollfd pfd;
    pfd.fd = socketfd;
    pfd.events = POLLIN;
    if (poll(&pfd, 1, 5000) <= 0) return DNSB_STATUS_FAILURE;

//log_message("-- message sent to 0x%08X\n", RECURSIVE_DNS);
    // wait for the response
    bio.reset();
    socklen_t length = 0;
    nbytes = recvfrom(socketfd, bio.buffer, bio.size, 0, (struct sockaddr *) &address, &length);
    if (nbytes < 0) return DNSB_STATUS_FAILURE;
//log_message("-- message received %d bytes\n", nbytes);

    // decode the response
    message.read(bio);
    // use the first 'type A' answer
    if (message.header.rcode == 0 && message.answers.size() > 0)
    {
        for (auto it = message.answers.begin(); it != message.answers.end(); ++it)
            if (it->type == DNS_TYPE_A) *output = it->rdata;
    }

    /*if (DNS_GET_RCODE(message.header.fields) == 0)
        log_message("-- %d.%d.%d.%d tells '%s' is %d.%d.%d.%d\n",
            DNS_IP_O1(RECURSIVE_DNS),
            DNS_IP_O2(RECURSIVE_DNS),
            DNS_IP_O3(RECURSIVE_DNS),
            DNS_IP_O4(RECURSIVE_DNS),
            host.c_str(),
            DNS_IP_O1(*output),
            DNS_IP_O2(*output),
            DNS_IP_O3(*output),
            DNS_IP_O4(*output));*/
    return (*output == 0) ? DNSB_STATUS_NXDOMAIN : DNSB_STATUS_RECURSIVE;
}


static uint32_t dns_time()
{
    static std::chrono::system_clock::time_point startTime = std::chrono::high_resolution_clock::now();
    return (uint32_t) std::chrono::duration_cast<std::chrono::seconds>(std::chrono::high_resolution_clock::now() - startTime).count();
}


void DNSCache::cleanup()
{
    uint32_t currentTime = dns_time();
    size_t count = cache.size();

    for (auto it = cache.begin(); it != cache.end();)
    {
        if (currentTime <= it->second.timestamp + (DNS_CACHE_TTL / 2))
            it = cache.erase(it);
        else
             ++it;
    }

    if (count != cache.size())
        LOG_MESSAGE("\nCache: removed %d entries and kept %d entries\n\n", count - cache.size(), cache.size());
}


int DNSCache::resolve(
    const std::string &host,
    uint32_t *output )
{
    if (cache.size() > DNS_CACHE_LIMIT) cleanup();

    uint32_t currentTime = dns_time();
    *output = 0;

    auto it = cache.find(host);
    // try to use cache information
    if (it != cache.end())
    {
        // check whether the cache entry still valid
        if (currentTime <= it->second.timestamp + DNS_CACHE_TTL)
        {
            *output = it->second.address;
            //it->second.hits++;
            ++hits.cache;
            it->second.timestamp = currentTime;
            return DNSB_STATUS_CACHE;
        }
    }

    int result = recursive(host, output);
    if (result != DNSB_STATUS_RECURSIVE) return result;

    if (*output != 0)
    {
        ++hits.external;
        dns_cache_t &entry = cache[host];
        entry.address = *output;
        entry.timestamp = currentTime;
        //entry.hits = 1;
    }

    return result;
}


void DNSCache::dump( const std::string &path )
{
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


