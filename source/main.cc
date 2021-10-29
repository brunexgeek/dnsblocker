#define _POSIX_C_SOURCE 200112L

#include "defs.hh"

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <list>
#include <fstream>

#include <signal.h>
#include <limits.h>
#include <defs.hh>
#include "nodes.hh"
#include "dns.hh"
#include "socket.hh"
#include "console.hh"
#include "protogen.hh"
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

using namespace dnsblocker;

static struct
{
    std::string basePath;
    Processor *processor = nullptr;
    std::string logPath;
    std::string dumpPath;
    std::string configFileName;
    Configuration config;
} context;

static const char *CONSOLE_HOST = "127.0.0.2";
static const int CONSOLE_PORT = 53022;

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
    config.binding.port = 53;
    config.binding.address = "127.0.0.2";
    config.cache.limit = DNS_CACHE_LIMIT;
    config.cache.ttl = DNS_CACHE_TTL;
    config.use_ipv6 = true;
    config.threads = 2;
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
    LOG_MESSAGE("\ndnsblocker %s\n\n", DNSB_VERSION);

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
	if (!SetCurrentDirectory(context.basePath.c_str()))
	#else
	if (chdir(context.basePath.c_str()) != 0)
	#endif
    {
        LOG_MESSAGE("Unable to change the current directory to '%s'\n", context.basePath.c_str());
    }

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

    context.config.dump_path_ = context.dumpPath;
    if (context.config.cache.limit <= 0) context.config.cache.limit = DNS_CACHE_LIMIT;
    if (context.config.cache.limit <= 0) context.config.cache.ttl = DNS_CACHE_TTL;
    if (context.config.threads <= 0) context.config.threads = 1;
    if (context.config.threads > 32) context.config.threads = 32;

    // get the absolute path of the input file
    for (auto it = context.config.blacklist.begin(); it != context.config.blacklist.end();)
    {
        *it = main_realPath(*it);
        if (it->empty())
            it = context.config.blacklist.erase(it);
        else
            ++it;
    }
    for (auto it = context.config.whitelist.begin(); it != context.config.whitelist.end();)
    {
        *it = main_realPath(*it);
        if (it->empty())
            it = context.config.whitelist.erase(it);
        else
            ++it;
    }
    if (context.config.blacklist.empty())
    {
        LOG_MESSAGE("No valid blacklist specified\n");
        exit(1);
    }

    if (context.config.external_dns.empty())
    {
        LOG_MESSAGE("The default external DNS is required\n");
        exit(1);
    }

    int flags = 0;
    if (context.config.monitoring.empty())
        context.config.monitoring.push_back("all");
    for (auto item : context.config.monitoring)
    {
        if (item == "allowed") flags |= MONITOR_SHOW_ALLOWED;
        else
        if (item == "denied") flags |= MONITOR_SHOW_DENIED;
        else
        if (item == "all") flags |= MONITOR_SHOW_ALLOWED | MONITOR_SHOW_DENIED;
        else
        if (item == "cache") flags |= MONITOR_SHOW_CACHE;
        else
        if (item == "recursive") flags |= MONITOR_SHOW_RECURSIVE;
        else
        if (item == "nxdomain") flags |= MONITOR_SHOW_NXDOMAIN;
        else
        if (item == "failure") flags |= MONITOR_SHOW_FAILURE;
    }
    context.config.monitoring_ = flags;

    LOG_MESSAGE("    Base path: %s\n", context.basePath.c_str());
    LOG_MESSAGE("Configuration: %s\n", context.configFileName.c_str());
    LOG_MESSAGE("    Blacklist: %s\n", context.config.blacklist[0].c_str());
    for (auto it = context.config.blacklist.begin() + 1; it != context.config.blacklist.end(); ++it)
        LOG_MESSAGE("               %s\n", it->c_str());
    if (!context.config.whitelist.empty())
    {
        LOG_MESSAGE("    Whitelist: %s\n", context.config.whitelist[0].c_str());
        for (auto it = context.config.whitelist.begin() + 1; it != context.config.whitelist.end(); ++it)
            LOG_MESSAGE("               %s\n", it->c_str());
    }
    LOG_MESSAGE(" External DNS: ");
    for (auto &dns : context.config.external_dns)
        LOG_MESSAGE("%s (%s) ", dns.address.c_str(), dns.name.c_str());
    LOG_MESSAGE("\n");
    LOG_MESSAGE("      Address: %s\n", context.config.binding.address.c_str());
    LOG_MESSAGE("         Port: %d\n", context.config.binding.port());
    LOG_MESSAGE("   Monitoring: ");
    for (auto item : context.config.monitoring)
        LOG_MESSAGE("%s ", item.c_str());
    LOG_MESSAGE("\n");
    #ifdef ENABLE_DNS_CONSOLE
    LOG_MESSAGE("      Console: TCP at %s:%d\n", CONSOLE_IPV4_ADDRESS, CONSOLE_IPV4_PORT);
    #endif
    LOG_MESSAGE("\n");
}


#ifndef __WINDOWS__


int main( int argc, char** argv )
{
    main_parseArguments(argc, argv);

    Log::instance = new Log( context.logPath.c_str() );
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
    #ifdef ENABLE_DNS_CONSOLE
    Console console(CONSOLE_HOST, CONSOLE_PORT, *context.processor, context.logPath);
    console.start();
    #endif
    context.processor->run(context.config.threads);
    #ifdef ENABLE_DNS_CONSOLE
    console.stop();
    #endif

    LOG_MESSAGE("\nTerminated\n");
    delete Log::instance;
    return 0;
}

#else

static SERVICE_STATUS serviceStatus = { 0 };
static SERVICE_STATUS_HANDLE statusHandle = NULL;


static VOID WINAPI serviceCtrlHandler (
	DWORD CtrlCode )
{
	if (CtrlCode == SERVICE_CONTROL_STOP && serviceStatus.dwCurrentState == SERVICE_RUNNING)
	{
		LOG_MESSAGE("Stopping...\n");
		serviceStatus.dwControlsAccepted = 0;
		serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		serviceStatus.dwWin32ExitCode = 0;
		serviceStatus.dwCheckPoint = 4;
		if (SetServiceStatus (statusHandle, &serviceStatus) == FALSE)
			LOG_MESSAGE("ERROR: SetServiceStatus returned error");
		context.processor->finish();
	}
}


#ifdef __cplusplus
extern "C" {
#endif


VOID WINAPI serviceMain( DWORD argc, LPSTR *argv )
{
	statusHandle = RegisterServiceCtrlHandlerA("dnsblocker", serviceCtrlHandler);
	if (statusHandle == NULL) return;

	ZeroMemory(&serviceStatus, sizeof (serviceStatus));
	serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	serviceStatus.dwControlsAccepted = 0;
	serviceStatus.dwCurrentState = SERVICE_START_PENDING;
	serviceStatus.dwWin32ExitCode = 0;
	serviceStatus.dwServiceSpecificExitCode = 0;
	serviceStatus.dwCheckPoint = 0;

	if (SetServiceStatus(statusHandle , &serviceStatus) == FALSE)
	{
		LOG_MESSAGE("ERROR: SetServiceStatus returned error");
		return;
	}

	serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	serviceStatus.dwCurrentState = SERVICE_RUNNING;
	serviceStatus.dwWin32ExitCode = 0;
	serviceStatus.dwCheckPoint = 0;
	if (SetServiceStatus(statusHandle, &serviceStatus) == FALSE)
	{
		LOG_MESSAGE("ERROR: SetServiceStatus returned error");
		return;
	}

	LOG_MESSAGE("dnsblocker %d.%d.%d (Windows Service)\n", MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION);

	main_prepare();
	context.processor = new Processor(context.config);

    #ifdef ENABLE_DNS_CONSOLE
    Console console(CONSOLE_HOST, CONSOLE_PORT, *context.processor);
    console.start();
    #endif
    context.processor->run();
    #ifdef ENABLE_DNS_CONSOLE
    console.stop();
    #endif

    LOG_MESSAGE("\nTerminated\n");
    delete Log::instance;

	serviceStatus.dwControlsAccepted = 0;
	serviceStatus.dwCurrentState = SERVICE_STOPPED;
	serviceStatus.dwWin32ExitCode = 0;
	serviceStatus.dwCheckPoint = 3;
	if (SetServiceStatus (statusHandle, &serviceStatus) == FALSE)
		LOG_MESSAGE("ERROR: SetServiceStatus returned error");
}


int main(int argc, char **argv)
{
	main_parseArguments(argc, argv);
	Log::instance = new Log( context.logPath.c_str() );

    LOG_MESSAGE("Windows service arguments:\n", i, argv[i]);
	for (int i = 0; i < argc; ++i)
		LOG_MESSAGE("   argv[%d] = %s\n", i, argv[i]);

	SERVICE_TABLE_ENTRYA table[] =
    {
        { "dnsblocker", (LPSERVICE_MAIN_FUNCTIONA) serviceMain },
        { NULL, NULL }
    };
	StartServiceCtrlDispatcher(table);
	return 0;
}


#ifdef __cplusplus
}
#endif

#endif
