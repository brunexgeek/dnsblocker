#include "process.hh"
#include "console.hh"
#include "log.hh"
#include <stdexcept>
#include <limits.h>
#include <chrono>
#include <atomic>
#include <defs.hh>

#ifdef __WINDOWS__
#include <Windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace dnsblocker {

static const uint8_t IPV4_BLOCK_VALUES[] = DNS_BLOCKED_IPV4_ADDRESS;
static const ipv4_t IPV4_BLOCK_ADDRESS(IPV4_BLOCK_VALUES);
#ifdef ENABLE_IPV6
static const uint16_t IPV6_BLOCK_VALUES[] = DNS_BLOCKED_IPV6_ADDRESS;
static const ipv6_t IPV6_BLOCK_ADDRESS(IPV6_BLOCK_VALUES);
#endif

Processor::Processor( const Configuration &config, Console *console ) :
    config_(config), running_(false), useHeuristics_(false), useFiltering_(true),
    console_(console)
{
    if (config.binding.port() > 65535)
    {
        LOG_MESSAGE("Invalid port number %d\n", config.binding.port);
        throw std::runtime_error("Invalid port number");
    }
    useHeuristics_ = config.use_heuristics();

    bindIP_ = UDP::hostToIPv4(config.binding.address);
	conn_ = new UDP();
	if (!conn_->bind(config.binding.address, (uint16_t) config.binding.port))
    {
        #ifdef __WINDOWS__
		LOG_MESSAGE("Unable to bind to %s:%d\n", config.binding.address.c_str(), config.binding.port());
		#else
		LOG_MESSAGE("Unable to bind to %s:%d: %s\n", config.binding.address.c_str(), config.binding.port(), strerror(errno));
		#endif
        delete conn_;
		conn_ = nullptr;
        throw std::runtime_error("Unable to bind");
    }

    cache_ = new Cache(config.cache.limit(), config.cache.ttl * 1000);
    resolver_ = new Resolver(*cache_);
    bool found = false;
    for (auto it = config.external_dns.begin(); it != config.external_dns.end(); ++it)
    {
        if (it->targets.empty())
        {
            resolver_->set_dns(it->address, it->name);
            found = true;
        }
        else
        {
            for (size_t i = 0; i < it->targets.size(); ++i)
            {
                resolver_->set_dns(it->address, it->name, it->targets[i]);
            }
        }
    }
    if (!found)
    {
        LOG_MESSAGE("Missing default external DNS\n");
        throw std::runtime_error("Missing default external DNS");
    }

    load_rules(config_.blacklist, blacklist_);
    load_rules(config_.whitelist, whitelist_);
}


Processor::~Processor()
{
	conn_->close();
	delete conn_;
	conn_ = nullptr;
    delete cache_;
	cache_ = nullptr;
}


void Processor::push( Job *job )
{
    std::lock_guard<std::mutex> guard(mutex_);
    pending_.push_back(job);
}

Job *Processor::pop()
{
    std::lock_guard<std::mutex> guard(mutex_);
    if (pending_.size() == 0) return nullptr;
    Job *result = pending_.front();
    pending_.pop_front();
    return result;
}


bool Processor::load_rules( const std::vector<std::string> &fileNames, Tree<uint8_t> &tree )
{
    if (fileNames.empty()) return false;

    tree.clear();

    for (auto it = fileNames.begin(); it != fileNames.end(); ++it)
    {
        int c = 0;
        LOG_MESSAGE("Loading rules from '%s'\n", it->c_str());

        std::ifstream rules(it->c_str());
        if (!rules.good()) return false;

        std::string line;

        while (!rules.eof())
        {
            std::getline(rules, line);
            if (line.empty()) continue;

            // remove comments
            size_t pos = line.find('#');
            if (pos != std::string::npos) line = line.substr(0, pos);

            int result = tree.add(line, 0, &line);
            if (line.empty()) continue;

            if (result == DNSBERR_OK)
            {
                ++c;
                continue;
            }
            else
            if (result == DNSBERR_DUPLICATED_RULE)
                LOG_MESSAGE("  [!] Duplicated '%s'\n", line.c_str());
            else
                LOG_MESSAGE("  [!] Invalid rule '%s'\n", line.c_str());
        }

        rules.close();
        LOG_MESSAGE("  Loaded %d rules\n", c);
    }

    float mem = (float) tree.memory();
    const char *unit = "bytes";
    if (mem > 1024 * 1024)
    {
        mem /= 1024 * 1024;
        unit = "MiB";
    }
    else
    if (mem > 1024)
    {
        mem /= 1024;
        unit = "KiB";
    }
    LOG_MESSAGE("Generated tree with %d nodes (%2.3f %s)\n\n", tree.size(), mem, unit);

    return true;
}

#ifdef ENABLE_DNS_CONSOLE
bool Processor::console( const std::string &command )
{
    if (command == "reload")
    {
        std::lock_guard<std::shared_mutex> guard(lock_);
        load_rules(config_.blacklist, blacklist_);
        load_rules(config_.whitelist, whitelist_);
        cache_->reset(); // TODO: we really need this?
    }
    else
    if (command == "filter/on")
    {
        LOG_MESSAGE("\nCONSOLE: Filtering enabled\n");
        useFiltering_ = true;
    }
    else
    if (command == "filter/off")
    {
        LOG_MESSAGE("\nCONSOLE: Filtering disabled\n");
        useFiltering_ = false;
    }
    else
    if (command == "heuristic/on")
    {
        LOG_MESSAGE("\nCONSOLE: Heuristics enabled\n");
        useHeuristics_ = true;
    }
    else
    if (command == "heuristic/off")
    {
        LOG_MESSAGE("\nCONSOLE: Heuristics disabled\n");
        useHeuristics_ = false;
    }
    else
        return false;
    return true;
}
#endif

bool Processor::send_error(
    const dns_message_t &request,
    int rcode,
    const Endpoint &endpoint )
{
    if (request.questions.size() == 0) return false;
    buffer bio;
    dns_message_t response;
    response.header.id = request.header.id;
    response.header.flags |= DNS_FLAG_QR;
    response.questions.push_back(request.questions[0]);
    response.header.rcode = (uint8_t) rcode;
    response.write(bio);
    return conn_->send(endpoint, bio.data(), bio.cursor());
}

bool Processor::isRandomDomain( std::string name )
{
    static const int MINLEN = 8;

    if (name.length() < 8) return false;

    const char *p = name.c_str();
    while (*p != 0)
    {
        while (*p == '.') ++p;

        int gon = 0; // group of numbers (a0bc32de1 = 3 groups)
        char gs = 0; // group size
        char bgs = 0; // biggest group size
        int vc = 0; // vowel count
        int cc = 0; // consonant count
        int len = 0;

        while (*p != 0 && *p != '.')
        {
            if (isdigit(*p))
                ++gs;
            else
            {
                if (strchr("aeiouyAEIOUY", *p) != nullptr)
                    ++vc;
                else
                if (*p != '-')
                    ++cc;
                if (gs > 0)
                {
                    ++gon;
                    if (bgs < gs) bgs = gs;
                    gs = 0;
                }
            }
            ++p;
            ++len;
        }

        if (gs > 0)
        {
            ++gon;
            if (bgs < gs) bgs = gs;
        }

        if (len < MINLEN) continue;
        if (bgs > 4) return std::cerr << name << ": bgs\n", true; // at least 5 digits in the biggest group
        if (gon > 1) return std::cerr << name << ": gon\n", true; // at least 2 groups of digits
        if ((float) vc / (float) cc < 0.3F) return std::cerr << name << ": vowels" << vc << ' ' << cc << "\n", true; // less than 30% of vowels
    }
    return false;
}

static uint64_t current_epoch()
{
    #ifdef __WINDOWS__
    return _time64(NULL);
    #else
    struct timespec current;
    clock_gettime(CLOCK_REALTIME, &current);
    return (uint64_t) current.tv_sec;
    #endif
}

static void print_request(
    const std::string &host,
    const std::string &remote,
    const std::string &dns_name,
    int type, const Configuration &config,
    bool is_blocked,
    int result,
    ipv4_t &ipv4,
#ifdef ENABLE_IPV6
    ipv6_t &ipv6,
#endif
    bool is_heuristic )
{
    Event event;
    const char *status = nullptr;
    int32_t flags = config.monitoring_;
    static std::atomic<uint64_t> last_id(1);

    if (is_blocked && flags & MONITOR_SHOW_DENIED)
        status = "DE";
    else
    if (result == DNSB_STATUS_CACHE && flags & MONITOR_SHOW_CACHE)
        status = "CA";
    else
    if (result == DNSB_STATUS_RECURSIVE && flags & MONITOR_SHOW_RECURSIVE)
        status = "RE";
    else
    if (result == DNSB_STATUS_FAILURE && flags & MONITOR_SHOW_FAILURE)
        status = "FA";
    else
    if (result == DNSB_STATUS_NXDOMAIN && flags & MONITOR_SHOW_NXDOMAIN)
        status = "NX";

    if (status != nullptr)
    {
        std::string addr;
        if (result == DNSB_STATUS_CACHE || result == DNSB_STATUS_RECURSIVE)
        {
            #ifdef ENABLE_IPV6
            if (type == ADDR_TYPE_AAAA)
                addr = ipv6.to_string();
            else
            #else
            (void) type;
            #endif
                addr = ipv4.to_string();
        }

        #ifdef ENABLE_IPV6
        const int proto = (type == ADDR_TYPE_AAAA) ? 6 : 4;
        #else
        constexpr int proto = 4;
        #endif

        event.id = last_id.fetch_add(1, std::memory_order::memory_order_relaxed);
        event.time = current_epoch();
        event.source = remote;
        event.ip = addr;
        event.server = dns_name;
        event.domain = host;
        event.proto = proto;
        event.type = status;
        event.heuristic = is_heuristic;
        LOG_EVENT(event);
    }
}

void Processor::process(
    Processor *object,
    int num,
    std::mutex *mutex,
    std::condition_variable *cond )
{
    (void) num;
    std::unique_lock<std::mutex> guard(*mutex);

    while (object->running_)
    {
        Job *job = object->pop();
        if (job == nullptr)
        {
            cond->wait_for(guard, std::chrono::seconds(1));
            continue;
        }

        Endpoint &endpoint = job->endpoint;
        dns_message_t &request = job->request;
        ipv4_t ipv4;
        #ifdef ENABLE_IPV6
        ipv6_t ipv6;
        #endif
        std::string dns_name;
        int result = DNSB_STATUS_FAILURE;
        bool is_heuristic = false;
        bool is_blocked = false;

        // check whether the domain is blocked
        if (object->useFiltering_)
        {
            if (object->whitelist_.match(request.questions[0].qname) == nullptr)
            {
                // try the blacklist
                {
                    std::shared_lock<std::shared_mutex> guard(object->lock_);
                    is_blocked = object->blacklist_.match(request.questions[0].qname) != nullptr;
                }
                // try the heuristics
                if (!is_blocked && object->useHeuristics_)
                    is_blocked = is_heuristic = isRandomDomain(request.questions[0].qname);
            }
        }

        // if the domain is blocked, returns an 'invalid' IP address
        if (is_blocked)
        {
            #ifdef ENABLE_IPV6
            if (request.questions[0].type == ADDR_TYPE_AAAA)
                ipv6 = IPV6_BLOCK_ADDRESS;
            else
            #endif
                ipv4 = IPV4_BLOCK_ADDRESS;
        }
        else
        {
            // assume NXDOMAIN for domains without periods (e.g. local host names)
            // otherwise we try the external DNS
            if (request.questions[0].qname.find('.') == std::string::npos)
                result = DNSB_STATUS_NXDOMAIN;
            else
            if (request.header.flags & DNS_FLAG_RD)
            {
                #ifdef ENABLE_IPV6
                if (request.questions[0].type == ADDR_TYPE_AAAA)
                    result = object->resolver_->resolve_ipv6(request.questions[0].qname, dns_name, ipv6);
                else
                #endif
                    result = object->resolver_->resolve_ipv4(request.questions[0].qname, dns_name, ipv4);
            }
            else
                result = DNSB_STATUS_NXDOMAIN;
        }

        // print information about the request
        print_request(request.questions[0].qname,
            endpoint.address.to_string(),
            dns_name,
            request.questions[0].type,
            object->config_,
            is_blocked,
            result,
            ipv4,
            #ifdef ENABLE_IPV6
            ipv6,
            #endif
            is_heuristic);

        // send the response
        if (!is_blocked && result != DNSB_STATUS_CACHE && result != DNSB_STATUS_RECURSIVE)
        {
            if (result == DNSB_STATUS_NXDOMAIN)
                object->send_error(request, DNS_RCODE_NXDOMAIN, endpoint);
            else
                object->send_error(request, DNS_RCODE_SERVFAIL, endpoint);
        }
        else
        {
            // response message
            buffer bio;
            dns_message_t response;
            response.header.id = request.header.id;
            response.header.flags |= DNS_FLAG_QR;
            if (request.header.flags & DNS_FLAG_RD)
            {
                response.header.flags |= DNS_FLAG_RA;
                response.header.flags |= DNS_FLAG_RD;
            }
            // copy the request question
            response.questions.push_back(request.questions[0]);
            dns_record_t answer;
            answer.qname = request.questions[0].qname;
            answer.type = request.questions[0].type;
            answer.clazz = request.questions[0].clazz;
            answer.ttl = DNS_ANSWER_TTL;
            #ifdef ENABLE_IPV6
            if (request.questions[0].type == ADDR_TYPE_AAAA)
                memcpy(answer.rdata, ipv6.values, 16);
            else
            #endif
                memcpy(answer.rdata, ipv4.values, 4);
            response.answers.push_back(answer);

            response.write(bio);
            object->conn_->send(endpoint, bio.data(), bio.cursor());
        }

        delete job;
    }
}

struct process_unit_t
{
    std::thread *thread;
    std::mutex mutex;
};

void Processor::run(int nthreads)
{
    std::string lastName;
    Endpoint endpoint;
    std::vector<process_unit_t> pool(nthreads);
    std::condition_variable cond;

    running_ = true;
    for (int i = 0; i < nthreads; ++i)
        pool[i].thread = new std::thread(process, this, i + 1, &pool[i].mutex, &cond);

    LOG_MESSAGE("Spawning %d threads to handle requests\n", nthreads);

    while (running_)
    {
        // receive the UDP message
        buffer bio;
        size_t size = bio.size();
        if (!conn_->receive(endpoint, bio.data(), &size, 2000)) continue;
        bio.resize(size);

        // parse the message
        dns_message_t request;
        request.read(bio);

        // ignore messages with the number of questions other than 1
        int type = 0;
        if (request.questions.size() == 1) type = request.questions[0].type;
        #ifdef ENABLE_IPV6
        if (type == DNS_TYPE_A || (config_.use_ipv6 && type == DNS_TYPE_AAAA))
        #else
        if (type == DNS_TYPE_A)
        #endif
        {
            push( new Job(endpoint, request) );
            cond.notify_all();
        }
        else
            send_error(request, DNS_RCODE_REFUSED, endpoint);
    }

    for (int i = 0; i < nthreads; ++i)
    {
        cond.notify_all();
        pool[i].thread->join();
        delete pool[i].thread;
    }
}

bool Processor::finish()
{
    if (!running_) return true;
    running_ = false;
    return false;
}

}