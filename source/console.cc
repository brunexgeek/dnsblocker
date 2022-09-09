#include "defs.hh"

#ifdef ENABLE_DNS_CONSOLE

#ifdef WIN32_
#include <WinSock2.h>
#include <WS2tcpip.h>
#endif

#include "webster.hh"

#include "console.hh"
#include "process.hh"
#include "monitor.hh"
#include <fstream>

namespace dnsblocker {

using webster::Parameters;
using webster::HttpServer;
using webster::HttpClient;

struct ConsoleListener : public webster::HttpListener
{
    std::string log_;
    Processor &proc_;

    ConsoleListener( std::string log, Processor &proc ) : log_(log), proc_(proc) {};

    int return_error( webster::Message &response, int status, const std::string &message )
    {
        response.header.status = status;
        response.header.fields.set(WBFI_CONTENT_TYPE, "application/json");
        response << "{\"status\":\"error\",\"message\":\"" << message << "\"}";
        return WBERR_OK;
    }

    int return_ok( webster::Message &response, const std::string &custom = "" )
    {
        response.header.status = 200;
        response.header.fields.set(WBFI_CONTENT_TYPE, "application/json");
        response.write("{\"status\":\"ok\"");
        if (!custom.empty())
        {
            response.write(",");
            response.write(custom);
            response.write("}");
        }
        else
            response.write("}");
        return WBERR_OK;
    }

    int return_events( webster::Message &request, webster::Message &response )
    {
        size_t start = strtol(request.header.target.query.c_str(), nullptr, 10);

        response.header.status = 200;
        response.header.fields.set(WBFI_CONTENT_TYPE, "application/json");
        response.header.fields.set(WBFI_CACHE_CONTROL, "no-cache");

        int etag = Log::instance->etag();
        response.header.fields.set(WBFI_ETAG, etag);
        // check if the file changed
        if (false && request.header.fields.get(WBFI_IF_NONE_MATCH, (int)0) == etag)
        {
            response.header.status = 304; // Not Modified
            response.header.fields.set(WBFI_CONTENT_LENGTH, 0);
            return WBERR_OK;
        }

        EventRing events( std::move(Log::instance->get_events(start)) );
        bool first = true;

        response.write("[");
        for (auto entry : events)
        {
            if (!first) response << ',';
            response << "{\"id\":" << entry.id << ',';
            response << "\"time\":" << entry.time << ',';
            response << "\"source\":\"" << entry.source << "\",";
            response << "\"type\":\"" << entry.type << "\",";
            response << "\"server\":\"" << entry.server << "\",";
            response << "\"qtype\":\"" << entry.qtype << "\",";
            response << "\"duration\":\"" << entry.duration << "\",";
            response << "\"heuristic\":" << (int) entry.heuristic << ",";
            response << "\"domain\":\"" << entry.domain << "\"}";
            first = false;
        }
        response.write("]");

        return WBERR_OK;
    }

    int whitelist( webster::Message &request, webster::Message &response )
    {
        std::string domain;
        auto pos = request.header.target.path.find("allow/");
        if (pos != std::string::npos)
            domain = request.header.target.path.substr(pos + 6);
        if (domain.empty())
            return return_error(response, 400, "Missing domain name");
        if (proc_.whitelist_.add(domain, 0, nullptr) != DNSBERR_OK)
            return return_error(response, 400, "Invalid domain name");
        else
            return return_ok(response);
    }

    int return_monitor( webster::Message &request, webster::Message &response )
    {
        (void) request;

        response.header.status = 200;
        response.header.fields.set(WBFI_CONTENT_TYPE, "text/html");
        response.header.fields.set(WBFI_CONTENT_LENGTH, HTML_MONITOR_SIZE);
        response.header.fields.set("X-DNS-Prefetch-Control", "off");
        response.header.fields.set(WBFI_CACHE_CONTROL, "max-age=300000, must-revalidate");
        response.write((const char*)HTML_MONITOR);
        return WBERR_OK;
    }

	int operator()( webster::Message &request, webster::Message &response )
	{
        request.ready();
        request.finish();
        if (request.header.method != webster::Method::WBM_GET)
            return return_error(response, 404, "Invalid method");
        if (request.header.target.path.find("/console/") == 0)
        {
            auto command = request.header.target.path.substr(9);
            if (command == "monitor")
                return return_monitor(request, response);
            else
            if (command == "monitor/events")
                return return_events(request, response);
            else
            if (command.find("allow/") == 0)
                return whitelist(request, response);
            else
            if (command == "cache/reset")
            {
                auto count = proc_.cache_->reset();
                return return_ok(response, "\"removed\":" + std::to_string(count));
            }
            else
            if (!proc_.console(command))
                return return_error(response, 404, "Unable to process command '" + command + "'");
        }
        else
            return return_error(response, 404, "Invalid resource");

        return return_ok(response);
	}
};

Console::Console( const std::string &host, int port, Processor &proc, const std::string &log ) :
    host_(host), port_(port), proc_(proc), thread_(nullptr), done_(false),
    log_(log)
{
}

void Console::thread_proc( Console *instance )
{
    Parameters params;
    params.buffer_size = 1024;
    params.connect_timeout = 3000;
    params.read_timeout = 3000;
	HttpServer server(params);
    std::string url = "http://" + instance->host_ + ":" + std::to_string(instance->port_);
	if (server.start(url) == WBERR_OK)
	{
		ConsoleListener listener(instance->log_, instance->proc_);
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
        server.stop();
	}
    else
        LOG_MESSAGE("Unable to start console at %s\n", url.c_str());
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