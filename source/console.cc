#include "defs.hh"

#ifdef ENABLE_DNS_CONSOLE

#ifdef WIN32_
#include <WinSock2.h>
#include <WS2tcpip.h>
#endif

#include "webster.hh"

#include "console.hh"
#include "process.hh"

namespace dnsblocker {

using webster::Parameters;
using webster::HttpServer;
using webster::HttpClient;

struct ConsoleListener : public webster::HttpListener
{
    Processor &proc_;

    ConsoleListener( Processor &proc ) : proc_(proc) { }

    int return_error( webster::Message &response, int status, const std::string &message )
    {
        response.header.status = status;
        response << "{\"status\":\"error\",\"message\":\"" << message << "\"}";
        return WBERR_OK;
    }
	int operator()( webster::Message &request, webster::Message &response )
	{
        std::vector<uint8_t> data;
        request.ready();
        request.finish();
        if (request.header.method != webster::Method::WBM_GET)
            return return_error(response, 404, "Invalid method");
        if (request.header.target.path.find("/console/") == 0)
        {
            auto command = request.header.target.path.substr(9);
            if (!proc_.console(command))
                return return_error(response, 404, "Unable to process command '" + command + "'");
        }
        else
            return return_error(response, 404, "Invalid resource");

        response.write("{\"status\":\"OK\"}");
		return WBERR_OK;
	}
};

Console::Console( const std::string &host, int port, Processor &proc ) :
    host_(host), port_(port), proc_(proc), thread_(nullptr), done_(false)
{
}

void Console::thread_proc( Console *instance )
{
    Parameters params;
    params.buffer_size = 1024;
	HttpServer server(params);
	if (server.start("http://127.0.0.2:53022") == WBERR_OK)
	{
		ConsoleListener listener(instance->proc_);
		while (!instance->done_)
		{
			HttpClient *remote = nullptr;
			// wait for connections (uses `read_timeout`from `Parameters` class)
			int result = server.accept(&remote);
			if (result == WBERR_OK)
			{
				// keep processing requests until some error occurs
				while (!instance->done_ && (result = remote->communicate(listener)) == WBERR_OK);
				// close the client (optional, closed by destructor) and destroy the object
				remote->close();
				delete remote;
			}
			else
			// `HttpServer::accept` will return `WBERR_TIMEOUT` if there were no connections
			if (result != WBERR_TIMEOUT)
				break;
		}
	}
	server.stop();
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