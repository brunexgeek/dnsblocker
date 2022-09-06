#ifndef DNSB_PROCESS_HH
#define DNSB_PROCESS_HH


#include <list>
#include <unordered_set>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <condition_variable>
#include "socket.hh"
#include "dns.hh"
#include "protogen.hh"
#include "config.pg.hh"

namespace dnsblocker {

enum class Status
{
    PENDING,
    BLOCK,
    WAITING,
    NXDOMAIN,
    ERROR,
};

struct Job
{
    Endpoint endpoint;
    dns_buffer_t request;
    //dns_buffer_t *response;
    uint16_t oid; // original DNS message id (from the client)
    uint16_t id; // DNS message id (zero means empty)
    std::string qname;
    dns_header_t *header = nullptr;
    uint16_t type;
    uint64_t duration = 0;

    Job( const Endpoint &ep, const dns_buffer_t &req )
    {
        endpoint = ep;
        request = req;
        //response = nullptr;
        oid = id = 0;
    }
    Job( const Job & ) = delete;
    Job( Job && ) = delete;
};

class Console;
struct ConsoleListener;

class Processor
{
    public:
        Processor( const Configuration &config, Console *console = nullptr );
        ~Processor();
        void push( Job *job );
        Job *pop();
        void run( int nthreads );
        bool finish();
        static uint8_t detect_heuristic( std::string name );
        bool console( const std::string &command );

    private:
        std::list<Job*> pending_;
        std::mutex mutex_;
        UDP *conn_;
        ipv4_t bindIP_;
        Cache *cache_;
        Resolver *resolver_;
        Configuration config_;
        Tree<uint8_t> blacklist_;
        Tree<uint8_t> whitelist_;
        std::unordered_set<ipv4_t> ipv4list_;
        bool running_;
        bool useHeuristics_;
        bool useFiltering_;
        Console *console_;
        std::shared_mutex lock_;
        Endpoint default_ns_;

        static void process( Processor *object, int num, std::mutex *mutex, std::condition_variable *cond );
        bool send_error(const Endpoint &endpoint,  const dns_buffer_t &request, int rcode);
        bool load_rules( const std::vector<std::string> &fileNames, Tree<uint8_t> &tree );
        static std::string realPath( const std::string &path );
        void send_success( const Endpoint &endpoint, const dns_buffer_t &request, const ipv4_t *ipv4, const ipv6_t *ipv6 );
        bool send_blocked( const Endpoint &endpoint, const dns_buffer_t &request );
        bool send_success( const Endpoint &endpoint, const dns_buffer_t &request, const dns_buffer_t &response, uint64_t duration, bool cache = false );
        bool in_whitelist( const std::string &host );

        friend struct ConsoleListener;
};

}

#endif // DNSB_PROCESS_HH