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


static const size_t BUFFER_SIZE = 1024;
FILE *LOG_FILE = nullptr;
static int socketfd = 0;

static struct
{
    std::string rulesFileName;
    Node *root = nullptr;
    int signal = 0;
} context;

#if 0
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
#endif


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
        fprintf(LOG_FILE, "Unable to bind: %s", strerror(errno));
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

    fprintf(LOG_FILE, "Loading rules from '%s'\n", context.rulesFileName.c_str());
    fflush(LOG_FILE);

    Node::counter = 0;
    Node::allocated = 0;
    Node *root = new(std::nothrow) Node();
    if (root != nullptr && !Node::load(context.rulesFileName, *root)) return false;

    fprintf(LOG_FILE, "Generated tree with %d nodes\n", Node::count());
    fprintf(LOG_FILE, "Using %2.3f KiB of memory to store the tree\n", (float) Node::allocated / 1024.0F);
    fflush(LOG_FILE);

    if (context.root != nullptr) delete root;
    context.root = root;

    return true;
}


static void main_process( Node &root )
{
    uint8_t buffer[BUFFER_SIZE];
    struct sockaddr_in clientAddress;
    socklen_t addrLen = sizeof (struct sockaddr_in);
    std::string lastQName;

    while (true)
    {
        if (context.signal != 0)
        {
            fprintf(LOG_FILE, "Received signal %d\n", context.signal);
            if (context.signal == SIGUSR1) main_loadRules();
            context.signal = 0;
        }

        int nbytes = (int) recvfrom(socketfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *) &clientAddress, &addrLen);
        if (nbytes <= 0) continue;

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
        printf("Usage: ./dnsblocker <host> <port> <rules>\n");
        return 1;
    }

    daemonize();
    LOG_FILE = fopen("/var/log/dnsblocker.log", "wt");
    if (LOG_FILE == nullptr) exit(EXIT_FAILURE);

    fprintf(LOG_FILE, "DNS Blocker started\n");
    fflush(LOG_FILE);

    // get the absolute path of the input file
    context.rulesFileName = main_realPath(argv[3]);
    if (context.rulesFileName.empty())
    {
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
        sigaddset(&act.sa_mask, SIGUSR1);
        act.sa_flags = 0;
        act.sa_handler = main_signalHandler;
        sigaction(SIGUSR1, &act, NULL);

        if (main_initialize( argv[1], atoi(argv[2]) ))
        {
            main_process(*context.root);
            main_terminate();
        }
    }
    else
        fprintf(LOG_FILE, "Unable to load rules\n");

ESCAPE:
    fprintf(LOG_FILE, "DNS Blocker terminated\n");
    fclose(LOG_FILE);

    return result;
}
