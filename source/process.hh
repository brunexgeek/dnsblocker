#ifndef DNSB_PROCESS_HH
#define DNSB_PROCESS_HH


#include <list>
#include <mutex>
#include <thread>
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
    //uint16_t pub_id = 0;
    uint16_t priv_id = 0;
    int result = 0;
    bool isBlocker = false;
    ipv4_t ipv4;
    ipv6_t ipv6;

    Job( const Endpoint &endpoint, dns_message_t &request ) : endpoint(endpoint)
    {
        this->request.swap(request);
    }
};

class Console;
struct ConsoleListener;

class JobList
{
    public:
        JobList() = default;
        ~JobList();
        void push(Job * job);
        Job* pop();
        Job* pop_priv( uint16_t id );
        Job* pop_pub( uint16_t id );
        Job* pop_done();
        bool empty() const;

    private:
        std::list<Job*> entries_;
        mutable std::mutex mutex_;
};

class Processor
{
    public:
        Processor( const Configuration &config, Console *console = nullptr );
        ~Processor();
        void push( Job *job );
        Job *pop();
        void run( int nthreads );
        bool finish();
        static bool isRandomDomain( std::string name );
        bool console( const std::string &command );

    private:
        struct
        {
            JobList list;
            std::condition_variable cond;
            std::mutex mutex;
        } idle_, pending_, done_;
        std::mutex mutex_;
        struct
        {
            UDP *pub; // used to communicate with clients
            UDP *priv; // used to communicate with external DNS
        } conn_;
        ipv4_t bindIP_;
        Cache *cache_;
        Resolver *resolver_;
        Configuration config_;
        Tree<uint8_t> blacklist_;
        Tree<uint8_t> whitelist_;
        Tree<uint32_t> nameserver_;
        bool running_;
        bool useHeuristics_;
        bool useFiltering_;
        Console *console_;

        static void process( Processor *object, int num, std::mutex *mutex, std::condition_variable *cond );
        bool send_error(
            const dns_message_t &request,
            int rcode,
            const Endpoint &endpoint );
        bool load_rules( const std::vector<std::string> &fileNames, Tree<uint8_t> &tree );
        static std::string realPath( const std::string &path );

        // receive DNS queries and put in the idle list
        void run_main();
        // apply whitelist and blacklist
        void run_idle();
        // try to resolve (cache and external DNS)
        void run_pending();
        // get the external DNS response and send the answer
        void run_done();

        friend struct ConsoleListener;
};

}

#endif // DNSB_PROCESS_HH