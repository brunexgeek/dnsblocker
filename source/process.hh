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

struct Job
{
    Endpoint endpoint;
    dns_message_t request;

    Job( Endpoint &endpoint, dns_message_t &request )
    {
        this->endpoint = endpoint;
        this->request.swap(request);
    }
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
        Tree<uint32_t> nameserver_;
        std::unordered_set<ipv4_t> ipv4list_;
        bool running_;
        bool useHeuristics_;
        bool useFiltering_;
        Console *console_;
        std::shared_mutex lock_;

        static void process( Processor *object, int num, std::mutex *mutex, std::condition_variable *cond );
        bool send_error(
            const dns_message_t &request,
            int rcode,
            const Endpoint &endpoint );
        bool load_rules( const std::vector<std::string> &fileNames, Tree<uint8_t> &tree );
        static std::string realPath( const std::string &path );

        friend struct ConsoleListener;
};

}

#endif // DNSB_PROCESS_HH