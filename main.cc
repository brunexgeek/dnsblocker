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
#include <mutex>
#include <condition_variable>


struct Endpoint
{
    int socketfd;
    struct sockaddr_in address;
    socklen_t length = sizeof(struct sockaddr_in);
};


static int socketfd = 0;

static struct
{
    std::string rulesFileName;
    std::string externalDNS;
    std::string bindAddress;
    uint32_t bindIPv4;
    int port = 53;
    Node *root = nullptr;
    int signal = 0;
    bool deamonize = false;
    std::string logPath;
    std::string dumpPath;
    DNSCache *cache = nullptr;

    struct
    {
        std::mutex mutex;
        std::condition_variable cond;
    } waiting;

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


static bool main_initialize()
{
    LOG_MESSAGE("     Address: %s\n        Port: %d\nExternal DNS: %s\n",
        context.bindAddress.c_str(),
        context.port,
        context.externalDNS.c_str());

    if (context.port < 0 || context.port > 65535)
    {
        LOG_MESSAGE("Invalid port number %d\n", context.port);
        return false;
    }

    socketfd = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    if (context.bindAddress.empty())
        address.sin_addr.s_addr = INADDR_ANY;
    else
    {
        inet_pton(AF_INET, context.bindAddress.c_str(), &address.sin_addr);
        context.bindIPv4 = address.sin_addr.s_addr;
    }
    address.sin_port = htons( (uint16_t) context.port);

    int rbind = bind(socketfd, (struct sockaddr *) & address, sizeof(struct sockaddr_in));
    if (rbind != 0)
    {
        LOG_MESSAGE("Unable to bind to %s: %s\n", context.bindAddress.c_str(), strerror(errno));
        close(socketfd);
        socketfd = 0;
        return false;
    }

    context.cache = new DNSCache();

    return true;
}


static int main_terminate()
{
    delete context.cache;
    if (socketfd != 0) close(socketfd);
    socketfd = 0;
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

    LOG_MESSAGE("\nLoading rules from '%s'\n", context.rulesFileName.c_str());

    Node::counter = 0;
    Node::allocated = 0;
    Node *root = new(std::nothrow) Node();
    if (root == nullptr || !Node::load(context.rulesFileName, *root)) return false;

    LOG_MESSAGE("Generated tree with %d nodes\n", Node::count());
    LOG_MESSAGE("Using %2.3f KiB of memory to store the tree\n\n", (float) Node::allocated / 1024.0F);

    if (context.root != nullptr) delete context.root;
    context.root = root;

    return true;
}


static bool main_send(
    Endpoint &endpoint,
    BufferIO &bio )
{
    int result = (int) sendto(endpoint.socketfd, bio.buffer, bio.cursor(), 0,
        (struct sockaddr *) &endpoint.address, endpoint.length);
    return result >= 0;
}


static bool main_receive(
    Endpoint &endpoint,
    BufferIO &bio )
{
    int result = (int) recvfrom(endpoint.socketfd, bio.buffer, bio.size, 0,
        (struct sockaddr *) &endpoint.address, &endpoint.length);
    if (result >= 0) bio.size = result;
    return result >= 0;
}


static bool main_returnError(
    dns_message_t &request,
    int rcode,
    Endpoint &endpoint )
{
    uint8_t buffer[DNS_BUFFER_SIZE] = { 0 };
    BufferIO bio(buffer, 0, DNS_BUFFER_SIZE);
    dns_message_t response;
    response.header.id = request.header.id;
    response.header.flags |= DNS_FLAG_QR;
    response.questions.push_back(request.questions[0]);
    response.header.rcode = (uint8_t) rcode;
    response.write(bio);
    return main_send(endpoint, bio);
}


#ifdef ENABLE_DNS_CONSOLE
static void main_control( const std::string &command )
{
    if (command == "reload@dnsblocker")
        main_loadRules();
    else
    if (command == "dump@dnsblocker")
    {
        LOG_MESSAGE("\nDumping DNS cache to '%s'\n\n", context.dumpPath.c_str());
        context.cache->dump(context.dumpPath);
    }
}
#endif


static void main_process()
{
    std::string lastName;
    uint8_t buffer[DNS_BUFFER_SIZE] = { 0 };
    Endpoint endpoint;
    endpoint.socketfd = socketfd;

    while (true)
    {
        if (context.signal != 0)
        {
            LOG_MESSAGE("Received signal %d\n", context.signal);
            if (context.signal == SIGUSR1) main_loadRules();
            if (context.signal == SIGINT) break;
            //if (context.signal == SIGUSR2) dns_cacheInfo();
            context.signal = 0;
        }

        // receive the UDP message
        BufferIO bio(buffer, 0, DNS_BUFFER_SIZE);
        if (!main_receive(endpoint, bio)) continue;
        // parse the message
        dns_message_t request;
        request.read(bio);
        // ignore messages with the number of questions other than 1
        if (request.questions.size() != 1 || request.questions[0].type != DNS_TYPE_A)
        {
            main_returnError(request, DNS_RCODE_REFUSED, endpoint);
            continue;
        }

        #ifdef ENABLE_DNS_CONSOLE
        // check whether the message carry a remote command
        if (context.bindIPv4 == endpoint.address.sin_addr.s_addr &&
            request.questions[0].qname.find("@dnsblocker") != std::string::npos)
        {
            main_control(request.questions[0].qname);
            main_returnError(request, DNS_RCODE_NOERROR, endpoint);
            continue;
        }
        #endif

        // check whether the domain is blocked
        bool isBlocked = context.root->match(request.questions[0].qname);
        uint32_t address = 0;
        int result = 0;

        // if the domain is not blocked, we retrieve the IP address from the cache
        if (!isBlocked)
        {
            // assume NXDOMAIN for domains without periods (e.g. local host names)
            // otherwise we try the external DNS
            if (request.questions[0].qname.find('.') == std::string::npos)
                result = DNSB_STATUS_NXDOMAIN;
            else
                result = context.cache->resolve(request.questions[0].qname, &address);
        }
        else
            address = DNS_BLOCKED_ADDRESS;

        // print some information about the request
        if (lastName != request.questions[0].qname)
        {
            const char *status = "DE";
            if (result == DNSB_STATUS_CACHE)
                status = "CA";
            else
            if (result == DNSB_STATUS_RECURSIVE)
                status = "RE";
            else
            if (result == DNSB_STATUS_FAILURE)
                status = "FA";
            else
            if (result == DNSB_STATUS_NXDOMAIN)
                status = "NX";

            // extract the source IPv4 address
            char source[INET6_ADDRSTRLEN];
            inet_ntop(endpoint.address.sin_family,
                get_in_addr((struct sockaddr *)&endpoint.address), source, INET6_ADDRSTRLEN);

            char resolution[INET_ADDRSTRLEN];
            snprintf(resolution, INET_ADDRSTRLEN, "%d.%d.%d.%d",
                DNS_IP_O1(address),
                DNS_IP_O2(address),
                DNS_IP_O3(address),
                DNS_IP_O4(address));

            lastName = request.questions[0].qname;
            LOG_TIMED("%s  %-15s  %-15s  %s\n",
                status,
                source,
                resolution,
                lastName.c_str());
        }

        // decide whether we have to include an answer
        if (!isBlocked && result != DNSB_STATUS_CACHE && result != DNSB_STATUS_RECURSIVE)
        {
            if (result == DNSB_STATUS_NXDOMAIN)
                main_returnError(request, DNS_RCODE_NXDOMAIN, endpoint);
            else
                main_returnError(request, DNS_RCODE_SERVFAIL, endpoint);
        }
        else
        {
            // response message
            bio = BufferIO(buffer, 0, DNS_BUFFER_SIZE);
            dns_message_t response;
            response.header.id = request.header.id;
            response.header.flags |= DNS_FLAG_QR;
            // copy the request question
            response.questions.push_back(request.questions[0]);
            dns_record_t answer;
            answer.qname = request.questions[0].qname;
            answer.type = request.questions[0].type;
            answer.clazz = request.questions[0].clazz;
            answer.ttl = DNS_ANSWER_TTL;
            answer.rdata = address;
            response.answers.push_back(answer);

            response.write(bio);
            //sendto(socketfd, bio.buffer, bio.cursor(), 0, (struct sockaddr *) &clientAddress, addrLen);
            main_send(endpoint, bio);
        }
    }
}

#include <sys/stat.h>

static void daemonize()
{
    pid_t pid;

    // fork the parent process
    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

#if 0
    // turn the child process the session leader
    if (setsid() < 0) exit(EXIT_FAILURE);
#endif
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
#if 0
    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    umask(0);
    chdir("/");
#endif
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
    if (path == nullptr) return "";
    char temp[PATH_MAX];
    if (realpath(path, temp) == nullptr) return "";
    return temp;
}


void main_usage()
{
    std::cout << "Usage: ./dnsblocker -r <rules> -x <ipv4> [ -b <ipv4> -p <port> -d ]\n";
    exit(EXIT_FAILURE);
}


void main_error( const std::string &message )
{
    std::cerr << "ERROR: " << message << std::endl;
    exit(EXIT_FAILURE);
}

void main_parseArguments(
    int argc,
    char **argv )
{
    int c;
    while ((c = getopt (argc, argv, "r:x:b:p:dl:")) != -1)
    {
        switch (c)
        {
        case 'r':
            context.rulesFileName = optarg;
            break;
        case 'x':
            context.externalDNS = optarg;
            break;
        case 'b':
            context.bindAddress = optarg;
            break;
        case 'p':
            context.port = atoi(optarg);
            break;
        case 'd':
            context.deamonize = true;
            break;
        case 'l':
            context.logPath = main_realPath(optarg);
            context.logPath += '/';
            context.logPath += LOG_FILENAME;

            context.dumpPath = main_realPath(optarg);
            context.dumpPath += '/';
            context.dumpPath += LOG_CACHE_DUMP;
            break;
        case '?':
        default:
            main_usage();
        }
    }

    if (context.rulesFileName.empty())
        main_error("missing rules");
    if (context.externalDNS.empty())
        main_error("missing external DNS address");
}


int main( int argc, char** argv )
{
    int result = 0;

    main_parseArguments(argc, argv);

    if (context.deamonize) daemonize();
    Log::instance = new Log( context.logPath.c_str() );

    LOG_MESSAGE("DNS Blocker %d.%d.%d\n", MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION);

    // get the absolute path of the input file
    context.rulesFileName = main_realPath(context.rulesFileName.c_str());
    if (context.rulesFileName.empty())
    {
        LOG_MESSAGE("Invalid rules file '%s'\n", context.rulesFileName.c_str());
        result = 1;
        goto ESCAPE;
    }

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

    if (main_initialize())
    {
        if (main_loadRules())
        {
            main_process();
            delete context.root;
        }
        else
            LOG_MESSAGE("Unable to load rules from '%s'\n", context.rulesFileName.c_str());
        main_terminate();
    }

ESCAPE:
    LOG_MESSAGE("\nTerminated\n");

    delete Log::instance;

    return result;
}
