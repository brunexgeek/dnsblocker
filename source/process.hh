#ifndef DNSB_PROCESS_HH
#define DNSB_PROCESS_HH


#include <list>
#include <mutex>
#include <thread>
#include <condition_variable>
#include "socket.hh"
#include "dns.hh"
#include "config.pg.hh"

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

    private:
        std::list<Job*> pending_;
        std::mutex mutex_;
        UDP *conn_;
        uint32_t bindIPv4_;
        DNSCache *cache_;
        Configuration config_;
        Tree<uint8_t> blacklist_;
        Tree<uint32_t> nameserver_;
        bool running_;
        std::string dumpPath_;

        static void process( Processor *object, int num, std::mutex *mutex, std::condition_variable *cond );
        void console( const std::string &command );
        bool sendError(
            const dns_message_t &request,
            int rcode,
            const Endpoint &endpoint );
        bool loadRules( const std::vector<std::string> &fileNames );
        static std::string realPath( const std::string &path );
};


#endif // DNSB_PROCESS_HH