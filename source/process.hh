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

    Job( Endpoint &endpoint, dns_message_t &request )
    {
        this->endpoint = endpoint;
        this->request.swap(request);
    }
};


class Processor
{
    public:
        Processor( const Configuration &config );
        ~Processor();
        void push( Job *job );
        Job *pop();
        void run();
        bool finish();
        static bool isRandomDomain( std::string name );
        void console( const std::string &command );

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
        bool running_;
        bool useHeuristics_;
        bool useFiltering_;

        static void process( Processor *object, int num, std::mutex *mutex, std::condition_variable *cond );
        bool send_error(
            const dns_message_t &request,
            int rcode,
            const Endpoint &endpoint );
        bool load_rules( const std::vector<std::string> &fileNames, Tree<uint8_t> &tree );
        static std::string realPath( const std::string &path );
};

}

#endif // DNSB_PROCESS_HH