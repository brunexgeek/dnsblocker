#include "dns.hh"
#include <stdio.h>
#include <string>
#include <string>
#include "log.hh"
#include <chrono>
#include <unordered_map>
#include <poll.h>


dns_header_t::dns_header_t()
{
    id = fields = qdcount = ancount = nscount = arcount = 0;
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

static void decodeHeader(
    BufferIO &bio,
    dns_header_t &header )
{
    header.id = bio.readU16();
    header.fields = bio.readU16();
    header.qdcount = bio.readU16();
    header.ancount = bio.readU16();
    header.nscount = bio.readU16();
    header.arcount = bio.readU16();
}


static void decodeQuestions(
    BufferIO &bio,
    int count,
    std::vector<dns_question_t> &output )
{
    output.resize(count);

    for (auto it = output.begin(); it != output.end(); ++it)
    {
        it->qname = bio.readQName();
        it->type = bio.readU16();
        it->clazz = bio.readU16();
    }
}


static void decodeAnswers(
    BufferIO &bio,
    int count,
    std::vector<dns_record_t> &output )
{
    output.resize(count);

    for (auto it = output.begin(); it != output.end(); ++it)
    {
        it->qname = bio.readQName();
        it->type = bio.readU16();
        it->clazz = bio.readU16();
        it->ttl = bio.readU32();
        uint16_t rdlen = bio.readU16();
        //log_message("%s %d %d %d %d\n", it->qname.c_str(), it->type, it->clazz, it->ttl, rdlen);
        it->rdata = 0;
        if (rdlen == 4)
            it->rdata = bio.readU32();
        else
            bio.skip(rdlen);
    }
}


void dns_decode(
    BufferIO &bio,
    dns_message_t &message )
{
    message.questions.clear();
    message.answers.clear();

    decodeHeader(bio, message.header);
    decodeQuestions(bio, message.header.qdcount, message.questions);
    decodeAnswers(bio, message.header.ancount, message.answers);
}


static void encodeHeader(
    BufferIO &bio,
    dns_header_t &header )
{
    bio.writeU16(header.id);
    bio.writeU16(header.fields);
    bio.writeU16(header.qdcount);
    bio.writeU16(header.ancount);
    bio.writeU16(header.nscount);
    bio.writeU16(header.arcount);
}


static void encodeQuestions(
    BufferIO &bio,
    const std::vector<dns_question_t> &input )
{
    for (auto it = input.begin(); it != input.end(); ++it)
    {
        bio.writeQName(it->qname);
        bio.writeU16(it->type);
        bio.writeU16(it->clazz);
    }
}


static void encodeRecords(
    BufferIO &bio,
    const std::vector<dns_record_t> &input )
{
    for (auto it = input.begin(); it != input.end(); ++it)
    {
        bio.writeQName(it->qname);
        bio.writeU16(it->type);
        bio.writeU16(it->clazz);
        bio.writeU32(it->ttl);
        bio.writeU16(4);
        bio.writeU32(it->rdata);
    }
}

void dns_encode(
    BufferIO &bio,
    dns_message_t &message )
{
    message.header.qdcount = (uint16_t) message.questions.size();
    message.header.ancount = (uint16_t) message.answers.size();
    message.header.nscount = 0;
    message.header.arcount = 0;

    encodeHeader(bio, message.header);
    encodeQuestions(bio, message.questions);
    encodeRecords(bio, message.answers);
}


#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>

#ifdef ENABLE_RECURSIVE_DNS

bool dns_recursive(
    const std::string &host,
    uint32_t *output )
{
    static uint16_t lastId = 0;

    *output = 0;

    // build the query message
    dns_message_t message;
    message.header.id = ++lastId;
    DNS_SET_RD(message.header.fields);
    dns_question_t question;
    question.qname = host;
    question.type = DNS_TYPE_A;
    question.clazz = 1;
    message.questions.push_back(question);
    // encode the message
    BufferIO bio(DNS_BUFFER_SIZE);
    dns_encode(bio, message);
//log_message("Message encoded in %d bytes \n", bio.cursor());
    static int socketfd = 0;
    if (socketfd == 0) socketfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketfd < 0) return false;

    // send the query to the recursive DNS
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = ntohl(RECURSIVE_DNS);
    address.sin_port = htons(53);
    ssize_t nbytes = sendto(socketfd, bio.buffer, bio.cursor(), 0, (struct sockaddr *) &address, sizeof(address));
    if (nbytes < 0) return false;

    struct pollfd pfd;
    pfd.fd = socketfd;
    pfd.events = POLLIN;
    if (poll(&pfd, 1, 5000) <= 0) return false;

//log_message("Message sent to 0x%08X\n", RECURSIVE_DNS);
    // wait for the response
    bio.reset();
    socklen_t length = 0;
    nbytes = recvfrom(socketfd, bio.buffer, bio.size, 0, (struct sockaddr *) &address, &length);
    if (nbytes < 0) return false;
//log_message("Message received %d bytes\n", nbytes);
    // decode the response
    dns_decode(bio, message);
    // use the first 'type A' answer
    if (DNS_GET_RCODE(message.header.fields) == 0 && message.answers.size() > 0)
    {
        for (auto it = message.answers.begin(); it != message.answers.end(); ++it)
            if (it->type == DNS_TYPE_A) *output = it->rdata;
    }

/*    if (DNS_GET_RCODE(message.header.fields) == 0)
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
    return true;
}


static uint64_t dns_time()
{
    static std::chrono::system_clock::time_point startTime = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::high_resolution_clock::now() - startTime).count();
}

struct dns_cache_t
{
    uint64_t timestamp;
    uint32_t address;
};

static std::unordered_map<std::string, dns_cache_t> cache;


void dns_cleanup()
{
    uint64_t currentTime = dns_time();
    size_t count = cache.size();

    for (auto it = cache.begin(); it != cache.end(); ++it)
    {
        if (currentTime <= it->second.timestamp + (DNS_CACHE_TTL / 2))
            it = cache.erase(it);
    }

    log_message("Removed %d cache entries from %d\n", count - cache.size(), count);
}


bool dns_cache(
    const std::string &host,
    uint32_t *output )
{
    if (cache.size() > DNS_CACHE_LIMIT) dns_cleanup();

    uint64_t currentTime = dns_time();
    *output = 0;

    auto it = cache.find(host);
    // try to use cache information
    if (it != cache.end())
    {
        // check whether the cache entry still valid
        if (currentTime <= it->second.timestamp + DNS_CACHE_TTL)
        {
            *output = it->second.address;
            it->second.timestamp = currentTime;
            //log_message("-- using cache\n");
            return true;
        }
        //log_message("-- cache expired\n");
    }

    if (!dns_recursive(host, output)) return false;

    if (*output != 0)
    {
        dns_cache_t &entry = cache[host];
        entry.address = *output;
        entry.timestamp = currentTime;
    }
    //log_message("-- recursive DNS\n");

    return true;
}


void dns_cacheInfo()
{
    log_message("Cache entries: %d\n", cache.size());
}

#endif