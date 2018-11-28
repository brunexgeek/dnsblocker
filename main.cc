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
#include <signal.h>
#include <limits.h>
#include "nodes.hh"
#include "dns.hh"
#include "config.hh"
#include "log.hh"


static int socketfd = 0;

static struct
{
    std::string rulesFileName;
    Node *root = nullptr;
    int signal = 0;
} context;


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


static bool main_initialize( const std::string &host, int port = 53 )
{
    if (host.empty() || port < 0 || port > 65535) return false;

    socketfd = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    inet_pton(AF_INET, host.c_str(), &address.sin_addr);
    address.sin_port = htons( (uint16_t) port);

    int rbind = bind(socketfd, (struct sockaddr *) & address, sizeof(struct sockaddr_in));
    if (rbind != 0)
    {
        log_message("Unable to bind: %s", strerror(errno));
        return false;
    }

    return true;
}


static int main_terminate()
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


bool main_loadRules()
{
    if (context.rulesFileName.empty()) return false;

    log_message("Loading rules from '%s'\n", context.rulesFileName.c_str());

    Node::counter = 0;
    Node::allocated = 0;
    Node *root = new(std::nothrow) Node();
    if (root == nullptr || !Node::load(context.rulesFileName, *root)) return false;

    log_message("Generated tree with %d nodes\n", Node::count());
    log_message("Using %2.3f KiB of memory to store the tree\n", (float) Node::allocated / 1024.0F);

    if (context.root != nullptr) delete context.root;
    context.root = root;

    return true;
}


static void main_process()
{
    uint8_t buffer[DNS_BUFFER_SIZE] = { 0 };
    struct sockaddr_in clientAddress;
    socklen_t addrLen = sizeof (struct sockaddr_in);

    while (true)
    {
        if (context.signal != 0)
        {
            log_message("Received signal %d\n", context.signal);
            if (context.signal == SIGUSR1) main_loadRules();
            if (context.signal == SIGINT) break;
            if (context.signal == SIGUSR2) dns_cacheInfo();
            context.signal = 0;
        }

        int nbytes = (int) recvfrom(socketfd, buffer, DNS_BUFFER_SIZE, 0, (struct sockaddr *) &clientAddress, &addrLen);
        if (nbytes <= 0) continue;

        BufferIO bio(buffer, 0, nbytes);
        dns_message_t request;
        request.read(bio);

        char source[INET6_ADDRSTRLEN + 1];
        inet_ntop(clientAddress.sin_family, get_in_addr((struct sockaddr *)&clientAddress), source, INET6_ADDRSTRLEN);

        bool isBlocked = context.root->match(request.questions[0].qname);
        uint32_t address = 0;

        #ifdef ENABLE_RECURSIVE_DNS
        // if the domain is not blocked, we retrieve the IP address from the cache
        if (!isBlocked && request.questions[0].type == DNS_TYPE_A)
        {
            if (!dns_cache(request.questions[0].qname, &address))
                log_message("Unable to get IP address '%s' from cache", request.questions[0].qname.c_str());
        }
        #endif

        // Questions of type other than 'A' are silently responded with 'Server Failure'

        if (request.questions[0].type == DNS_TYPE_A)
        {
            if (isBlocked)
                log_message("[DENIED] %s asked for '%s'\n", source, request.questions[0].qname.c_str());
            else
            if (address == 0)
                log_message("         %s asked for '%s' [NXDOMAIN]\n", source, request.questions[0].qname.c_str());
            else
                log_message("         %s asked for '%s' [%d.%d.%d.%d]\n", source, request.questions[0].qname.c_str(),
                    DNS_IP_O1(address),DNS_IP_O2(address), DNS_IP_O3(address), DNS_IP_O4(address));
        }

        // response message
        bio = BufferIO(buffer, 0, DNS_BUFFER_SIZE);
        dns_message_t response;
        response.header.id = request.header.id;
        response.header.flags |= DNS_FLAG_QR;
        // copy the request question
        response.questions.push_back(request.questions[0]);
        // decide whether we have to include an answer
        if (request.questions[0].type != DNS_TYPE_A || (!isBlocked && address == 0))
        {
            response.header.rcode = 2; // Server Failure
        }
        // TODO: send 'NXDomain' when address == 0 and is not blocked
        else
        {
            if (address == 0) address = BLOCK_ADDRESS;
            dns_record_t answer;
            answer.qname = request.questions[0].qname;
            answer.type = request.questions[0].type;
            answer.clazz = request.questions[0].clazz;
            answer.ttl = DNS_ANSWER_TTL;
            answer.rdata = address;
            response.answers.push_back(answer);
        }

        response.write(bio);
        sendto(socketfd, bio.buffer, bio.cursor(), 0, (struct sockaddr *) &clientAddress, addrLen);
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


static void main_signalHandler(
	int handle )
{
	(void) handle;
	context.signal = handle;
}


static std::string main_realPath( const char *path )
{
    char temp[PATH_MAX];
    if (realpath(path, temp) == nullptr) return "";
    return temp;
}


int main( int argc, char** argv )
{
    int result = 0;

    if (argc != 4)
    {
        printf("DNS Blocker %d.%d.%d\n", MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION);
        printf("Usage: ./dnsblocker <host> <port> <rules>\n");
        return 1;
    }

    #ifdef ENABLE_DAEMON
    daemonize();
    #endif
    if (!log_initialize()) exit(EXIT_FAILURE);

    log_message("DNS Blocker %d.%d.%d started\n", MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION);

    // get the absolute path of the input file
    context.rulesFileName = main_realPath(argv[3]);
    if (context.rulesFileName.empty())
    {
        log_message("Invalid rules file '%s'\n", argv[3]);
        result = 1;
        goto ESCAPE;
    }

    if (main_loadRules())
    {
        /*std::cerr << "digraph Nodes { " << std::endl;
        root.print(std::cerr);
        std::cerr << "}" << std::endl;
        return 0;*/

        // install the signal handler to stop the server with CTRL + C
        struct sigaction act;
        sigemptyset(&act.sa_mask);
        sigaddset(&act.sa_mask, SIGUSR2);
        sigaddset(&act.sa_mask, SIGUSR1);
        sigaddset(&act.sa_mask, SIGINT);
        act.sa_flags = 0;
        act.sa_handler = main_signalHandler;
        sigaction(SIGUSR2, &act, NULL);
        sigaction(SIGUSR1, &act, NULL);
        sigaction(SIGINT, &act, NULL);

        if (main_initialize( argv[1], atoi(argv[2]) ))
        {
            main_process();
            main_terminate();
        }
        delete context.root;
    }
    else
        log_message("Unable to load rules\n");

ESCAPE:
    log_message("DNS Blocker terminated\n");
    log_terminate();

    return result;
}
