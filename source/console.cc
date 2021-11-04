#include "defs.hh"

#ifdef ENABLE_DNS_CONSOLE

#ifdef WIN32_
#include <WinSock2.h>
#include <WS2tcpip.h>
#endif

#include "webster.hh"

#include "console.hh"
#include "process.hh"
#include "html1.hh"
#include "html2.hh"
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

    int return_cache( webster::Message &response )
    {
        response.header.status = 200;
        response.header.fields.set(WBFI_CONTENT_TYPE, "application/json");

        std::stringstream ss;
        proc_.cache_->dump(ss);
        response.write(ss.str());

        return WBERR_OK;
    }

    void print_events( webster::Message &response )
    {
        Buffer events( std::move(Log::instance->get_events()) );
        int count = 0;

        for (auto line : events)
        {
            std::string css;
            if (line.empty())
                response.write("<p>&nbsp;</p>\n");
            else
            if (line.length() >= 3 && isdigit(line[0]) && isdigit(line[1]) && line[2] == ':')
            {
                // set the line color
                if (line.find("DE ") != std::string::npos)
                    response.write("<p class='de'>");
                else
                if (line.find("NX ") != std::string::npos)
                    response.write("<p class='nx'>");
                else
                if (line.find("FA ") != std::string::npos)
                    response.write("<p class='fa'>");
                else
                    response.write("<p>");
                // extract the domain name
                auto pos = line.rfind(' ');
                auto name = line.substr(pos+1);
                line.erase(pos+1);
                // write the line
                response.write(line);
                // write the domain name as hyperlink
                response.write("<a target='_blank' href='http://");
                response.write(name);
                response.write("'>");
                response.write(name);
                response.write("</a>");
                if (line.find("*") != std::string::npos)
                {
                    std::string btn = "addbtn";
                    btn += std::to_string(count++);
                    response.write("<button onclick=\"javascript: call_rest('/console/allow/**.");
                    response.write(name);
                    response.write("');\" class='ibtn'>+</button>");
                }
                response.write("</p>\n");
            }
            else
            {
                response.write("<p>");
                response.write(line);
                response.write("</p>\n");
            }
        }
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
        response.header.fields.set("X-DNS-Prefetch-Control", "off");
        response.header.fields.set(WBFI_CACHE_CONTROL, "max-age=300000, must-revalidate");

        int etag = Log::instance->etag();
        response.header.fields.set(WBFI_ETAG, etag);

        // check if the file changed
        if (request.header.fields.get(WBFI_IF_NONE_MATCH, (int)0) == etag)
        {
            response.header.status = 304; // Not Modified
            response.header.fields.set(WBFI_CONTENT_LENGTH, 0);
            return WBERR_OK;
        }

        response.write((const char*)HTML_HEADER);
        print_events(response);
        response.write((const char*)HTML_FOOTER);
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
            if (command == "monitor")
                return return_monitor(request, response);
            else
            if (command.find("allow/") == 0)
                return whitelist(request, response);
            else
            if (command == "cache")
                return return_cache(response);
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
        LOG_MESSAGE("Unable to star console at %s\n", url.c_str());
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