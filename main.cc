#define _POSIX_C_SOURCE 200112L

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fstream>
#include <unistd.h>

#include "Node.hh"


static const size_t BUFFER_SIZE   = 1024;

static const uint16_t QR_MASK     = 0x8000;
static const uint16_t OPCODE_MASK = 0x7800;
static const uint16_t AA_MASK     = 0x0400;
static const uint16_t TC_MASK     = 0x0200;
static const uint16_t RD_MASK     = 0x0100;
static const uint16_t RA_MASK     = 0x8000;
static const uint16_t RCODE_MASK  = 0x000F;

static const uint16_t DNS_TYPE_A      = 1;
static const uint16_t DNS_TYPE_NS     = 2;
static const uint16_t DNS_TYPE_CNAME  = 5;
static const uint16_t DNS_TYPE_PTR    = 12;
static const uint16_t DNS_TYPE_MX     = 15;
static const uint16_t DNS_TYPE_TXT    = 16;


FILE *LOG_FILE = nullptr;


static const char* getType( uint16_t type )
{
    switch (type)
    {
        case DNS_TYPE_A:     return "A";
        case DNS_TYPE_NS:    return "NS";
        case DNS_TYPE_CNAME: return "CNAME";
        case DNS_TYPE_PTR:   return "PTR";
        case DNS_TYPE_MX:    return "MX";
        case DNS_TYPE_TXT:   return "TXT";
        default:             return "?";
    }
}


struct Message
{
    uint16_t id;
    uint16_t qr;
    uint16_t opcode;
    uint16_t aa;
    uint16_t tc;
    uint16_t rd;
    uint16_t ra;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t aucount;
    uint16_t adcount;
    std::string qname;
    uint16_t type;
    uint16_t clazz;
    uint32_t ttl;
    uint8_t rcode;
    uint16_t rlength;
    uint8_t rdata[4];

    Message()
    {
        id = 0;
        qr = 0;
        opcode = 0;
        aa = 0;
        tc = 0;
        rd = 0;
        ra = 0;
        qdcount = 0;
        ancount = 0;
        aucount = 0;
        adcount = 0;
        type = 0;
        clazz = 0;
        ttl = 0;
        rcode = 0;
        rlength = 0;
        memset(rdata, 0, sizeof(rdata));
    }

    void print( std::ostream &output )
    {
        output << "QUERY:" << std::endl;
        output << "      ID: " << std::showbase << std::hex << id << std::endl << std::noshowbase << std::dec;
        output << "  Fields: [ QR: " << qr << " opCode: " << opcode << " ]" << std::endl;
        output << "   Count: " << qdcount  << ' ' << ancount << ' ' << aucount << ' ' << adcount << std::endl;
        output << "   QName: " << qname << std::endl;
        output << "    Type: " << getType(type) << std::endl;
        output << "   Class: " << clazz << std::endl;
    }
};


struct BufferIO
{
    uint8_t *buffer;
    size_t size;
    uint8_t *ptr;

    BufferIO(
        uint8_t *buffer,
        size_t size ) : buffer(buffer), size(size), ptr(buffer) {}

    uint16_t readU16()
    {
        uint16_t value = static_cast<uint16_t>(ptr[0] << 8);
        value = (uint16_t) (value + static_cast<uint16_t>(ptr[1]));
        ptr += sizeof(uint16_t);
        return value;
    }

    void writeU16( uint16_t value )
    {
        ptr[0] = (uint8_t) ((value & 0xFF00) >> 8);
        ptr[1] = (uint8_t) (value & 0xFF);
        ptr += sizeof(uint16_t);
    }

    void writeU32( uint32_t value )
    {
        ptr[0] = (uint8_t) ((value & 0xFF000000) >> 24);
        ptr[1] = (uint8_t) ((value & 0x00FF0000) >> 16);
        ptr[2] = (uint8_t) ((value & 0x0000FF00) >> 8);
        ptr[3] = (uint8_t) ((value & 0x000000FF));
        ptr += sizeof(uint32_t);
    }

    void reset()
    {
        ptr = buffer;
    }

    size_t remaining() const
    {
        return size - (size_t)(ptr - buffer);
    }

    size_t cursor() const
    {
        return (size_t)(ptr - buffer);
    }

    std::string readQName()
    {
        std::string qname;

        int length = *ptr++;
        while (length != 0)
        {
            for (int i = 0; i < length; i++)
            {
                char c = *ptr++;
                qname.append(1, c);
            }
            length = *ptr++;
            if (length != 0) qname.append(1,'.');
        }
        return qname;
    }

    void writeQName( const std::string &qname)
    {
        size_t start(0), end; // indexes

        while ((end = qname.find('.', start)) != std::string::npos) {

            *ptr++ = (uint8_t) (end - start); // label length octet
            for (size_t i=start; i<end; i++) {

                *ptr++ = qname[i]; // label octets
            }
            start = end + 1; // ignore dots
        }

        *ptr++ = (uint8_t) (qname.size() - start); // last label length octet
        for (size_t i=start; i<qname.size(); i++) {

            *ptr++ = qname[i]; // last label octets
        }

        *ptr++ = 0;
    }
};

static int socketfd = 0;


static int lookupIPv4(
	const char *host,
	struct sockaddr_in *address )
{
	int result = 0;

	if (address == NULL) return 1;
	if (host == NULL || host[0] == 0) host = "127.0.0.1";

    // get an IPv4 address from hostname
	struct addrinfo aiHints, *aiInfo;
    memset(&aiHints, 0, sizeof(aiHints));
	aiHints.ai_family = AF_INET;
	aiHints.ai_socktype = SOCK_STREAM;
	aiHints.ai_protocol = IPPROTO_TCP;
	result = getaddrinfo( host, NULL, &aiHints, &aiInfo );
	if (result != 0 || aiInfo->ai_addr->sa_family != AF_INET)
	{
		if (result == 0) freeaddrinfo(aiInfo);
		return 1;
	}
    // copy address information
    memcpy(address, (struct sockaddr_in*) aiInfo->ai_addr, sizeof(struct sockaddr_in));
	freeaddrinfo(aiInfo);

    return 1;
}

static int initialize( const std::string &host, int port = 53 )
{
    socketfd = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    lookupIPv4(host.c_str(), &address);
    address.sin_port = htons( (uint16_t) port);

    int rbind = bind(socketfd, (struct sockaddr *) & address, sizeof(struct sockaddr_in));

    if (rbind != 0)
    {
        fprintf(LOG_FILE, "Could not bind: %s", strerror(errno));
        exit(1);
    }

    return 0;
}


static int terminate()
{
    if (socketfd != 0) close(socketfd);
    return 0;
}

void decodeHeader(
    BufferIO &bio,
    Message &message )
{
    message.id = bio.readU16();

    uint fields = bio.readU16();
    message.qr = fields & QR_MASK;
    message.opcode = fields & OPCODE_MASK;
    message.aa = fields & AA_MASK;
    message.tc = fields & TC_MASK;
    message.rd = fields & RD_MASK;
    message.ra = fields & RA_MASK;

    message.qdcount = bio.readU16();
    message.ancount = bio.readU16();
    message.aucount = bio.readU16();
    message.adcount = bio.readU16();
}


static Message decode(
    BufferIO &bio )
{
    Message message;
    decodeHeader(bio, message);
    message.qname = bio.readQName();
    message.type = bio.readU16();
    message.clazz = bio.readU16();

    return message;
}


static void encodeHeader(
    BufferIO &bio,
    const Message &message )
{
    bio.writeU16(message.id);

    int fields = 0;
    if (message.qr) fields |= 1 << 15;
    fields |= (message.opcode & 0x000F) << 14;
    fields |= (message.rcode & 0x0F);
    bio.writeU16( (uint16_t) fields);
    bio.writeU16(message.qdcount);
    bio.writeU16(message.ancount);
    bio.writeU16(message.aucount);
    bio.writeU16(message.adcount);
}


static void encode(
    const Message &request,
    const Message &response,
    BufferIO &bio )
{
    encodeHeader(bio, response);

    // question
    bio.writeQName(request.qname);
    bio.writeU16(request.type);
    bio.writeU16(request.clazz);

    // answer
    if (response.ancount == 1)
    {
        bio.writeQName(response.qname);
        bio.writeU16(response.type);
        bio.writeU16(response.clazz);
        bio.writeU32(response.ttl);
        if (response.type == DNS_TYPE_A && response.rcode == 0)
        {
            bio.writeU16(4);
            bio.writeU32(0x7F0000FE);
        }
        else
        {
            bio.writeU16(1);
            //*bio.ptr++ = 0;
        }
    }
}


static void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
        return &(((struct sockaddr_in*)sa)->sin_addr);
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

static void process( Node &root )
{
    uint8_t buffer[BUFFER_SIZE];
    struct sockaddr_in clientAddress;
    socklen_t addrLen = sizeof (struct sockaddr_in);
    std::string lastQName;

    while (true)
    {
        int nbytes = (int) recvfrom(socketfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *) &clientAddress, &addrLen);

        BufferIO bio(buffer, nbytes);

        Message request = decode(bio);
        //request.print(std::cout);

        char source[INET6_ADDRSTRLEN + 1];
        inet_ntop(clientAddress.sin_family, get_in_addr((struct sockaddr *)&clientAddress), source, INET6_ADDRSTRLEN);

        bool isBlocked = root.match(request.qname);
        // avoid to log repeated queries
        if (request.qname != lastQName)
        {
            lastQName = request.qname;
            if (isBlocked)
                fprintf(LOG_FILE, "[BLOCK] %s asked for '%s'\n", source, request.qname.c_str());
            else
                fprintf(LOG_FILE, "        %s asked for '%s'\n", source, request.qname.c_str());
            fflush(LOG_FILE);
        }

        Message response;
        response.id = request.id;
        response.qdcount = 1;
        response.ancount = 1;
        response.qname = request.qname;
        response.type = request.type;
        response.ttl = 1200;
        response.clazz = request.clazz;
        response.qr = 1;
        if (!isBlocked || request.type != DNS_TYPE_A)
        {
            response.rcode = 2; // Server Failure
            response.ancount = 0;
        }

        bio.reset();
        encode(request, response, bio);
        nbytes = (int) bio.cursor();

        sendto(socketfd, buffer, nbytes, 0, (struct sockaddr *) &clientAddress, addrLen);
    }
}


static void daemonize()
{
    pid_t pid;

    // fork the parent process
    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);
    // turn the child process the session leader
    if (setsid() < 0) exit(EXIT_FAILURE);

    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    // close opened file descriptors
    for (long x = sysconf(_SC_OPEN_MAX); x>=0; x--) close ( (int) x);
}


int main( int argc, char** argv )
{
    if (argc != 4)
    {
        printf("Usage: ./dnsblocker <host> <port> <rules>\n");
        return 1;
    }

    daemonize();
    LOG_FILE = fopen("/var/log/dnsblocker.log", "wt");
    if (LOG_FILE == nullptr) exit(EXIT_FAILURE);

    fprintf(LOG_FILE, "DNS Blocker started\n");
    fflush(LOG_FILE);

    Node root;
    if (!Node::load(argv[3], root)) exit(1);
    fprintf(LOG_FILE, "Generated tree with %d nodes\n", Node::count());
    fprintf(LOG_FILE, "Using %2.3f KiB of memory to store the tree\n", (float) Node::allocated / 1024.0F);
    fflush(LOG_FILE);

    /*std::cerr << "digraph Nodes { " << std::endl;
    root.print(std::cerr);
    std::cerr << "}" << std::endl;
    return 0;*/

    initialize(argv[1], atoi(argv[2]));
    process(root);
    terminate();

    fprintf(LOG_FILE, "DNS Blocker terminated\n");

    return 0;
}
