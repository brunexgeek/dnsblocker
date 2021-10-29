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

    int return_ok( webster::Message &response )
    {
        response.header.status = 200;
        response.header.fields.set(WBFI_CONTENT_TYPE, "application/json");
        response << "{\"status\":\"ok\"}";
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

    int return_log( webster::Message &request, webster::Message &response )
    {
        (void) request;

        response.header.status = 200;
        response.header.fields.set(WBFI_CONTENT_TYPE, "text/html");

        std::ifstream input(log_);
        if (input.good())
        {
            response.write((const char*)HTML_HEADER);
            std::string line;
            while (input.good())
            {
                std::string css;
                std::getline(input, line);
                if (line.empty())
                    response.write("<p>&nbsp;</p>");
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
                    response.write("</a></p>");
                }
                else
                {
                    response.write("<p>");
                    response.write(line);
                    response.write("</p>");
                }
            }
            response.write((const char*)HTML_FOOTER);
            return WBERR_OK;
        }
        return return_error(response, 404, "Unable to open log file");
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
            if (command == "log")
                return return_log(request, response);
            else
            if (command == "cache")
                return return_cache(response);
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