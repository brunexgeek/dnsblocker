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

#include "nodes.hh"
#include "dns.hh"


static const size_t BUFFER_SIZE = 1024;
FILE *LOG_FILE = nullptr;
static int socketfd = 0;

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
        dns_message_t request;
        dns_decode(bio, request);
        //request.print(std::cout);

        char source[INET6_ADDRSTRLEN + 1];
        inet_ntop(clientAddress.sin_family, get_in_addr((struct sockaddr *)&clientAddress), source, INET6_ADDRSTRLEN);

        bool isBlocked = root.match(request.questions[0].qname);
        // avoid to log repeated queries
        if (request.questions[0].qname != lastQName)
        {
            lastQName = request.questions[0].qname;
            if (isBlocked)
                fprintf(LOG_FILE, "[BLOCK] %s asked for '%s'\n", source, request.questions[0].qname.c_str());
            else
                fprintf(LOG_FILE, "        %s asked for '%s'\n", source, request.questions[0].qname.c_str());
            fflush(LOG_FILE);
        }

        bio = BufferIO(buffer, BUFFER_SIZE);
        dns_message_t response;
        response.header.id = request.header.id;
        DNS_SET_QR(response.header.fields);
        // copy the request question
        response.questions.push_back(request.questions[0]);
        // decide whether we have to include an answer
        if (!isBlocked || request.questions[0].type != DNS_TYPE_A)
        {
            DNS_SET_RCODE(response.header.fields, 2);
        }
        else
        {
            dns_record_t answer;
            answer.qname = request.questions[0].qname;
            answer.type = request.questions[0].type;
            answer.clazz = request.questions[0].clazz;
            answer.ttl = 1200;
            // TODO: fill 'rdata'
            response.answers.push_back(answer);
        }

        dns_encode(bio, response);
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
