#include "defs.hh"

#if !defined(DNSB_CONSOLE_HH) && defined(ENABLE_DNS_CONSOLE)
#define  DNSB_CONSOLE_HH

#include <string>
#include <thread>
#include "socket.hh"

namespace dnsblocker {

class Processor;

class Console
{
    public:
        Console( const std::string &host, int port, Processor &proc );
        void start();
        void stop();
    private:
        std::string host_;
        int port_;
        Processor &proc_;
        std::thread *thread_;
        bool done_;
        UDP udp_;

        static void thread_proc( Console *instance );
};

}

#endif // DNSB_CONSOLE_HH