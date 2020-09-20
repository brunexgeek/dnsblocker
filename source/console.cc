#include "defs.hh"

#ifdef ENABLE_DNS_CONSOLE

#include "console.hh"
#include "process.hh"

namespace dnsblocker {

Console::Console( const std::string &host, int port, Processor &proc ) :
    host_(host), port_(port), proc_(proc), thread_(nullptr), done_(false)
{
}

void Console::thread_proc( Console *instance )
{
    char buffer[256] = {0};
    UDP conn;
    conn.bind(CONSOLE_IPV4_ADDRESS, CONSOLE_IPV4_PORT);
    while (!instance->done_)
    {
        if (conn.poll(1000))
        {
            Endpoint endpoint;
            size_t size = sizeof(buffer) - 1;
            conn.receive(endpoint, (uint8_t*) buffer, &size);
            if (size == 0) continue;
            buffer[size] = 0;
            const char *s = buffer;
            char *e = buffer + size;
            while (*s == ' ') ++s;
            while (e > s && (*e == '\n' || *e == '\r' || *e == ' ' || *e == 0)) *e-- = 0;
            instance->proc_.console((char*) s);
        }
    }
    conn.close();
}

void Console::start()
{
    if (thread_ != nullptr) return;
    thread_ = new std::thread(thread_proc, this);
}

void Console::stop()
{
    if (thread_ == nullptr) return;
    done_ = true;
    thread_->join();
}

}

#endif