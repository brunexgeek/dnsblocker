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

// TODO: group jobs by qname intead of id and all jobs with the same qname could be grouped using a linked list ('next' pointer)

struct Job
{
    Endpoint endpoint; // client endpoint
    dns_buffer_t request;
    dns_buffer_t response;
    uint16_t oid = 0; // original DNS message id (from the client)
    uint16_t id = 0; // external DNS message id (zero means empty)
    std::string qname;
    uint16_t qtype = 0; // question type
    uint64_t start_time = 0;
    int max = 0; // number of external DNS queries made
    int count = 0; // number of external DNS responses received

    Job( const Endpoint &ep, const dns_buffer_t &req ) : endpoint(ep), request(req) {}
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
        Tree<std::pair<std::string,Endpoint>> other_ns_;
        std::unordered_set<ipv4_t> ipv4list_;
        bool running_;
        bool useHeuristics_;
        bool useFiltering_;
        Console *console_;
        std::shared_mutex lock_;
        Endpoint default_ns_;

        static void process( Processor *object, int num, std::mutex *mutex, std::condition_variable *cond );
        bool send_error(const Endpoint &endpoint,  const dns_buffer_t &request, uint64_t start_time, int rcode);
        bool load_rules( const std::vector<std::string> &fileNames, Tree<uint8_t> &tree );
        static std::string realPath( const std::string &path );
        void send_success( const Endpoint &endpoint, const dns_buffer_t &request, const ipv4_t *ipv4, const ipv6_t *ipv6 );
        bool send_blocked( const Endpoint &endpoint, const dns_buffer_t &request );
        bool send_success( const Endpoint &endpoint, const dns_buffer_t &request, const dns_buffer_t &response, uint64_t duration, bool cache );
        bool in_whitelist( const std::string &host );
        bool finish_job( Job &item, std::map<uint16_t, dnsblocker::Job *> &wait_list );
        bool check_blocked_domain( const std::string &host );
        bool check_blocked_address( const ipv4_t &address );
        bool answer_with_cache( Job *job );

        friend struct ConsoleListener;
};

}

#endif // DNSB_PROCESS_HH