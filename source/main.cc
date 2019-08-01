#define _POSIX_C_SOURCE 200112L

#include "defs.hh"

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <list>
#include <fstream>

#include <signal.h>
#include <limits.h>
#include "nodes.hh"
#include "dns.hh"
#include "socket.hh"
#include "config.pg.hh"
#include "log.hh"
#include "process.hh"
#include <mutex>
#include <thread>
#include <condition_variable>
#include <dns-blocker/errors.hh>

#ifdef __WINDOWS__
#include <Windows.h>
#define PATH_SEPARATOR '\\'
#else
#include <sys/stat.h>
#include <unistd.h>
#define PATH_SEPARATOR '/'
#endif


static struct
{
    std::string basePath;
    Processor *processor = nullptr;
    std::string logPath;
    std::string dumpPath;
    std::string configFileName;
    Configuration config;

    struct
    {
        std::mutex mutex;
        std::condition_variable cond;
    } waiting;

} context;

/*
static const char* getType( uint16_t type )
{
    switch (type)
    {
        case DNS_TYPE_A:     return "A";
        case DNS_TYPE_NS:    return "NS";
        case DNS_TYPE_CNAME: return "CNAME";
        case DNS_TYPE_PTR:   return "PTR";
        case DNS_TYPE_MX:    return "MX";
        case DNS_TYPE_TXT:   return "TXT";
        default:             return "?";
    }
}*/

static std::string main_realPath( const std::string &path )
{
	if (path.empty()) return "";

	#ifdef __WINDOWS__

	char temp[MAX_PATH];
	int result = GetFullPathName( path.c_str(), MAX_PATH, temp, NULL);
	if (result == 0 || result > MAX_PATH) return "";
	return temp;

	#else

    char temp[PATH_MAX];
    if (realpath(path.c_str(), temp) == nullptr) return "";
    return temp;

	#endif
}


#ifdef __WINDOWS__

static BOOL WINAPI main_signalHandler(
  _In_ DWORD dwCtrlType )
{
	(void) dwCtrlType;
    if (context.processor->finish()) exit(1);
	return TRUE;
}

#else

static void main_signalHandler(
	int handle )
{
	(void) handle;
	if (context.processor->finish()) exit(1);
}

#endif


void main_usage()
{
    std::cerr << "dnsblocker " << DNSB_VERSION << std::endl;
    std::cout << "Usage: dnsblocker <configuration> [ <log directory> ]\n";
    exit(EXIT_FAILURE);
}


void main_error( const std::string &message )
{
    std::cerr << "ERROR: " << message << std::endl;
    exit(EXIT_FAILURE);
}

void main_parseArguments(
    int argc,
    char **argv )
{
	if (argc != 2 && argc != 3) main_usage();

	context.configFileName = argv[1];
    if (argc == 3)
	{
        context.logPath = main_realPath(argv[2]);
		context.logPath += PATH_SEPARATOR;
        context.logPath += LOG_FILENAME;

        context.dumpPath = main_realPath(argv[2]);
        context.dumpPath += PATH_SEPARATOR;
        context.dumpPath += LOG_CACHE_DUMP;
    }

    if (context.configFileName.empty())
        main_error("missing configuration file");
}


Configuration main_defaultConfig()
{
    Configuration config;
    config.monitoring("none");
    config.binding().port(53);
    config.binding().address("127.0.0.2");
    config.cache().limit(DNS_CACHE_LIMIT);
    config.cache().ttl(DNS_CACHE_TTL);
    return config;
}


static std::string main_basePath( const std::string &path )
{
	std::string result;

	#ifdef __WINDOWS__

	size_t pos = path.rfind('\\');
    if (pos == std::string::npos)
        result = ".\\";
    else
        result = path.substr(0, pos);

	#else

	size_t pos = path.rfind('/');
    if (pos == std::string::npos)
        result = '/';
    else
        result = path.substr(0, pos);

	#endif

    return result;
}


void main_prepare()
{
    // extract the base path from the configuration file name
    context.basePath = context.configFileName = main_realPath(context.configFileName);
    if (context.configFileName.empty())
    {
        LOG_MESSAGE("Invalid configuration path '%s'\n", context.configFileName.c_str());
        exit(1);
    }
    context.basePath = main_basePath(context.configFileName);
    // change the current path
	#ifdef __WINDOWS__
	SetCurrentDirectory(context.basePath.c_str());
	#else
	chdir(context.basePath.c_str());
	#endif

    context.config = main_defaultConfig();

    // load configuration
    std::ifstream in(context.configFileName.c_str());
    Configuration::ErrorInfo err;
    if (!in.good() || !context.config.deserialize(in, false, &err))
    {
        LOG_MESSAGE("ERROR: Unable to load configuration from '%s'\n", context.configFileName.c_str());
        if (!err.message.empty())
            LOG_MESSAGE("ERROR: %s at %d:%d\n", err.message.c_str(), err.line, err.column);
        exit(1);
    }
    in.close();

    if (context.config.cache().limit() <= 0) context.config.cache().limit(DNS_CACHE_LIMIT);
    if (context.config.cache().limit() <= 0) context.config.cache().ttl(DNS_CACHE_TTL);

    // get the absolute path of the input file
    for (auto it = context.config.blacklist().begin(); it != context.config.blacklist().end();)
    {
        *it = main_realPath(*it);
        if (it->empty())
            it = context.config.blacklist().erase(it);
        else
            ++it;
    }
    if (context.config.blacklist.undefined())
    {
        LOG_MESSAGE("No valid blacklist specified\n");
        exit(1);
    }

    if (context.config.external_dns.undefined())
    {
        LOG_MESSAGE("The default external DNS is required\n");
        exit(1);
    }

    LOG_MESSAGE("\ndnsblocker %s\n", DNSB_VERSION);
    LOG_MESSAGE("    Base path: %s\n", context.basePath.c_str());
    LOG_MESSAGE("Configuration: %s\n", context.configFileName.c_str());
    LOG_MESSAGE("    Blacklist: %s\n", context.config.blacklist()[0].c_str());
    for (auto it = context.config.blacklist().begin() + 1; it != context.config.blacklist().end(); ++it)
        LOG_MESSAGE("               %s\n", it->c_str());
    LOG_MESSAGE(" External DNS: ");
    for (auto it = context.config.external_dns().begin(); it != context.config.external_dns().end(); ++it)
        LOG_MESSAGE("%s ", it->address().c_str());
    LOG_MESSAGE("\n");
    LOG_MESSAGE("      Address: %s\n", context.config.binding().address().c_str());
    LOG_MESSAGE("         Port: %d\n", context.config.binding().port());
}


int main( int argc, char** argv )
{
    main_parseArguments(argc, argv);

    Log::instance = new Log( context.logPath.c_str() );

    LOG_MESSAGE("DNS Blocker %d.%d.%d\n", MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION);

    main_prepare();

    #ifdef __WINDOWS__
    SetConsoleCtrlHandler(main_signalHandler, TRUE);
    #else
    // install the signal handler to stop the server with CTRL + C
    struct sigaction act;
    sigemptyset(&act.sa_mask);
    sigaddset(&act.sa_mask, SIGUSR2);
    sigaddset(&act.sa_mask, SIGUSR1);
    sigaddset(&act.sa_mask, SIGINT);
    act.sa_flags = 0;
    act.sa_handler = main_signalHandler;
    sigaction(SIGUSR2, &act, NULL);
    sigaction(SIGUSR1, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    #endif

    context.processor = new Processor(context.config);
    context.processor->run();

    LOG_MESSAGE("\nTerminated\n");
    delete Log::instance;
    return 0;
}
