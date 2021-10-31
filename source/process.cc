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
static const uint16_t IPV6_BLOCK_VALUES[] = DNS_BLOCKED_IPV6_ADDRESS;
static const ipv4_t IPV4_BLOCK_ADDRESS(IPV4_BLOCK_VALUES);
static const ipv6_t IPV6_BLOCK_ADDRESS(IPV6_BLOCK_VALUES);

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
	conn_.pub = new UDP();
	if (!conn_.pub->bind(config.binding.address, (uint16_t) config.binding.port))
    {
        #ifdef __WINDOWS__
		LOG_MESSAGE("Unable to bind to %s:%d\n", config.binding.address.c_str(), config.binding.port());
		#else
		LOG_MESSAGE("Unable to bind to %s:%d: %s\n", config.binding.address.c_str(), config.binding.port(), strerror(errno));
		#endif
        delete conn_.pub;
		conn_.pub = nullptr;
        throw std::runtime_error("Unable to bind");
    }
	conn_.priv = new UDP();

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
	conn_.pub->close();
	delete conn_.pub;
	conn_.pub = nullptr;
    delete cache_;
	cache_ = nullptr;
}

static uint64_t clock_micro()
{
    #ifdef __WINDOWS__
    LARGE_INTEGER fq, t;
    QueryPerformanceFrequency(&fq);
    QueryPerformanceCounter(&t);
    uint64_t div = fq.QuadPart / (1000 * 1000);
    if (div == 0) div = 1;
    return (uint64_t) t.QuadPart / div;
    #else
    struct timespec current;
    clock_gettime(CLOCK_MONOTONIC, &current);
    return (uint64_t) current.tv_sec * (1000 * 1000) + ((uint64_t) current.tv_nsec / 1000);
    #endif
}

JobList::~JobList()
{
    std::lock_guard<std::mutex> guard(mutex_);
    for (auto item : entries_) delete item;
}

void JobList::push( Job *job )
{
    std::lock_guard<std::mutex> guard(mutex_);
    entries_.push_back(job);
}

Job *JobList::pop()
{
    std::lock_guard<std::mutex> guard(mutex_);
    if (entries_.size() == 0) return nullptr;
    Job *result = entries_.front();
    entries_.pop_front();
    return result;
}

Job *JobList::pop_priv( uint16_t id )
{
    std::lock_guard<std::mutex> guard(mutex_);
    Job *result = nullptr;
    if (entries_.size() == 0) return nullptr;
    for (auto it = entries_.begin(); it != entries_.end(); ++it)
        if ((*it)->priv_id == id)
        {
            result = *it;
            entries_.erase(it);
            return result;
        }
    return nullptr;
}
/*
Job *JobList::pop_pub( uint16_t id )
{
    std::lock_guard<std::mutex> guard(mutex_);
    Job *result = nullptr;
    if (entries_.size() == 0) return nullptr;
    for (auto it = entries_.begin(); it != entries_.end(); ++it)
        if ((*it)->pub_id == id)
        {
            result = *it;
            entries_.erase(it);
            return result;
        }
    return nullptr;
}*/

Job *JobList::pop_done()
{
    std::lock_guard<std::mutex> guard(mutex_);
    Job *result = nullptr;
    if (entries_.size() == 0) return nullptr;
    for (auto it = entries_.begin(); it != entries_.end(); ++it)
        if ((*it)->result != DNSB_STATUS_RECURSIVE)
        {
            result = *it;
            entries_.erase(it);
            return result;
        }
    return nullptr;
}

bool JobList::empty() const
{
    std::lock_guard<std::mutex> guard(mutex_);
    return entries_.empty();
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
        // TODO: protect with lock
        load_rules(config_.blacklist, blacklist_);
        load_rules(config_.whitelist, whitelist_);
        cache_->reset(); // TODO: we really need this?
    }
    else
    if (command == "forget")
    {
        cache_->reset();
        LOG_MESSAGE("\nCONSOLE: Cache reset\n");
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
    return conn_.priv->send(endpoint, bio.data(), bio.cursor());
}

bool Processor::isRandomDomain( std::string name )
{
    if (name.find("www.") == 0)
        name = name.c_str() + 4;
    if (name.find("cloudfront") == std::string::npos)
    {
        int i = 0;
        for (char c : name) if (c == '.') ++i;
        if (i > 1) return false;
    }

    auto pos = name.find('.');
    if (pos == std::string::npos) return false;
    name = name.substr(0, pos);

    if (name.length() < 10) return false;

    int gon = 0; // group of numbers a0bc32de1 = 3
    char gs = 0; // group size
    char bgs = 0; // biggest group size
    int vc = 0; // vowel count
    int cc = 0; // consonant count

    const char *c = name.c_str();
    while (*c != 0)
    {
        if (isdigit(*c))
            ++gs;
        else
        if (strchr("aeiouAEIOU", *c) != nullptr)
            ++vc;
        else
            ++cc;
        if (gs > 0)
        {
            ++gon;
            if (bgs < gs) bgs = gs;
            gs = 0;
        }
        ++c;
    }

    //if (gon == 0) return false; // require digits
    if (bgs > 4) return true; // at least 5 digits in the biggest group
    if (gon > 1) return true; // at least 2 groups
    if ((float) vc / (float) name.length() < 0.3F) return true; // less than 30% of vowels
    return false;
}

static void print_request( const std::string &host, const std::string &remote, const std::string &dns_name,
    int type, const Configuration &config, bool is_blocked, int result, ipv4_t &ipv4, ipv6_t &ipv6,
    bool is_heuristic, bool colors )
{
    const char *COLOR_RED = "\033[31m";
    const char *COLOR_YELLOW = "\033[33m";
    const char *COLOR_RESET = "\033[39m";

#if !defined(_WIN32) && !defined(_WIN64)
    if (!colors)
#endif
    {
        COLOR_RED = "";
        COLOR_YELLOW = "";
        COLOR_RESET = "";
    }

    static const char *IPV4_FORMAT = "%s%-15s  %s %c  %-8s  %-15s  %s%s\n";
    static const char *IPV6_FORMAT = "%s%-40s  %s %c  %-8s  %-40s  %s%s\n";
    static const char *FORMAT = nullptr;
    if (config.use_ipv6)
        FORMAT = IPV6_FORMAT;
    else
        FORMAT = IPV4_FORMAT;

    const char *status = nullptr;
    const char *color = COLOR_RED;
    int32_t flags = config.monitoring_;

    if (is_blocked && flags & MONITOR_SHOW_DENIED)
    {
        status = "DE";
        color = COLOR_RED;
    }
    else
    if (result == DNSB_STATUS_CACHE && flags & MONITOR_SHOW_CACHE)
    {
        status = "CA";
        color = COLOR_RESET;
    }
    else
    if (result == DNSB_STATUS_RECURSIVE && flags & MONITOR_SHOW_RECURSIVE)
    {
        status = "RE";
        color = COLOR_RESET;
    }
    else
    if (result == DNSB_STATUS_FAILURE && flags & MONITOR_SHOW_FAILURE)
    {
        status = "FA";
        color = COLOR_YELLOW;
    }
    else
    if (result == DNSB_STATUS_NXDOMAIN && flags & MONITOR_SHOW_NXDOMAIN)
    {
        status = "NX";
        color = COLOR_YELLOW;
    }

    if (status != nullptr)
    {
        std::string addr;
        if (result == DNSB_STATUS_CACHE || result == DNSB_STATUS_RECURSIVE)
        {
            if (type == ADDR_TYPE_AAAA)
                addr = ipv6.to_string();
            else
                addr = ipv4.to_string();
        }

        LOG_EVENT(FORMAT,
            color,
            remote.c_str(),
            status,
            (type == ADDR_TYPE_AAAA) ? '6' : '4',
            (is_heuristic) ? "*" : dns_name.c_str(),
            addr.c_str(),
            host.c_str(),
            COLOR_RESET);
    }
}

#if 0
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
        ipv6_t ipv6;
        std::string dns_name;
        int result = DNSB_STATUS_FAILURE;
        bool is_heuristic = false;
        bool is_blocked = false;

        // check whether the domain is blocked
        if (object->useFiltering_)
        {
            if (object->whitelist_.match(request.questions[0].qname) == nullptr)
            {
                if (object->useHeuristics_)
                    is_blocked = is_heuristic = isRandomDomain(request.questions[0].qname);
                if (!is_blocked)
                    is_blocked = object->blacklist_.match(request.questions[0].qname) != nullptr;
            }
        }

        // if the domain is blocked, returns an 'invalid' IP address
        if (is_blocked)
        {
            if (request.questions[0].type == ADDR_TYPE_AAAA)
                ipv6 = IPV6_BLOCK_ADDRESS;
            else
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
                if (request.questions[0].type == ADDR_TYPE_AAAA)
                    result = object->resolver_->resolve_ipv6(request.questions[0].qname, dns_name, ipv6);
                else
                    result = object->resolver_->resolve_ipv4(request.questions[0].qname, dns_name, ipv4);
            }
            else
                result = DNSB_STATUS_NXDOMAIN;
        }

        // print information about the request
        print_request(request.questions[0].qname, endpoint.address.to_string(), dns_name, request.questions[0].type, object->config_,
            is_blocked, result, ipv4, ipv6, is_heuristic, false);

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
            if (request.questions[0].type == ADDR_TYPE_AAAA)
                memcpy(answer.rdata, ipv6.values, 16);
            else
                memcpy(answer.rdata, ipv4.values, 4);
            response.answers.push_back(answer);

            response.write(bio);
            object->conn_->send(endpoint, bio.data(), bio.cursor());
        }

        delete job;
    }
}
#endif

struct process_unit_t
{
    std::thread *thread;
    std::mutex mutex;
};

static void print_job( const std::string &msg, Job &job )
{
    std::cout << msg << "\n   [pub_id=" << job.request.header.id << "  priv_id=" << job.priv_id << "  domain='" << job.request.questions[0].qname << "']\n";
}

void Processor::run_main()
{
    Endpoint endpoint;

    while (running_)
    {
        if (!conn_.pub->poll(2000)) continue;

        uint64_t start = clock_micro();

        // receive the UDP message
        buffer bio;
        size_t size = bio.size();
        if (!conn_.pub->receive(endpoint, bio.data(), &size, 1000)) continue;
        bio.resize(size);
std::cerr << "--- Read " << size << " bytes in " << ((clock_micro() -start)/1000) << " ms\n";
        // parse the message
        dns_message_t request;
        request.read(bio);

        // ignore messages with the number of questions other than 1
        int type = 0;
        if (request.questions.size() == 1) type = request.questions[0].type;
        if (type == DNS_TYPE_A || (config_.use_ipv6 && type == DNS_TYPE_AAAA))
        {
            std::cout << __FUNCTION__ << ": got something\n";
            Job *job = new Job(endpoint, request);
            job->timer = start;
            idle_.list.push(job);
            idle_.cond.notify_all();
        }
        else
            send_error(request, DNS_RCODE_REFUSED, endpoint);
    }
}

void Processor::run_idle()
{
    std::unique_lock<std::mutex> guard(idle_.mutex);

    while (running_)
    {
        Job *job = idle_.list.pop();
        if (job == nullptr)
        {
            idle_.cond.wait_for(guard, std::chrono::seconds(1));
            continue;
        }

        const dns_message_t &request = job->request;
        bool is_heuristic = false;
        bool is_blocked = false;

        // check whether the domain is blocked
        if (useFiltering_)
        {
            if (whitelist_.match(request.questions[0].qname) == nullptr)
            {
                if (useHeuristics_)
                    is_blocked = is_heuristic = isRandomDomain(request.questions[0].qname);
                if (!is_blocked)
                    is_blocked = blacklist_.match(request.questions[0].qname) != nullptr;
            }
        }

        // if the domain is blocked, returns an 'invalid' IP address
        if (is_heuristic)
            job->result = DNSB_STATUS_HEURISTIC;
        else
        if (is_blocked)
            job->result = DNSB_STATUS_BLOCKED;
        else
        // assume NXDOMAIN for domains without dots (e.g. local host names)
        // otherwise we try the external DNS
        if (request.questions[0].qname.find('.') == std::string::npos)
            job->result = DNSB_STATUS_NXDOMAIN;
        else
        if (request.header.flags & DNS_FLAG_RD)
            job->result = DNSB_STATUS_RECURSIVE;
        else
            job->result = DNSB_STATUS_NXDOMAIN;

        if (job->result == DNSB_STATUS_RECURSIVE)
        {
            std::cout << "Job is going to pending ->" << job->result << '\n';
            pending_.list.push(job);
            pending_.cond.notify_all();
        }
        else
        {
            std::cout << "Job is going to done ->" << job->result << '\n';
            done_.list.push(job);
            done_.cond.notify_all();
        }
    }
}

void Processor::run_pending()
{
    std::unique_lock<std::mutex> guard(pending_.mutex);
    auto default_dns_ = named_value<ipv4_t>("default", UDP::hostToIPv4("8.8.8.8"));

    while (running_)
    {
        Job *job = pending_.list.pop();
        if (job == nullptr)
        {
            pending_.cond.wait_for(guard, std::chrono::seconds(1));
            continue;
        }

        // should never happen
        if (job->result != DNSB_STATUS_RECURSIVE)
        {
            done_.list.push(job);
            done_.cond.notify_all();
            continue;
        }

        const dns_message_t &request = job->request;
        std::string domain = request.questions[0].qname;

        // check wheter we have a match in the cache
        if (request.questions[0].type == ADDR_TYPE_AAAA)
            job->result = cache_->find(domain, &job->ipv6);
        else
            job->result = cache_->find(domain, &job->ipv4);
        // if we have a cache miss try to solve with external DNS
        if (job->result != DNSB_STATUS_CACHE)
            job->result = Resolver::initiate_recursive(*conn_.priv, domain, request.questions[0].type,
                default_dns_.value, job->priv_id);
        else
            std::cout << "Using cache for " << domain << '\n';

        done_.list.push(job);
        done_.cond.notify_all();
    }
}

static void answer( UDP &conn, dns_message_t &request, Endpoint &endpoint, const ipv4_t &ipv4, const ipv6_t &ipv6 )
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
    if (request.questions[0].type == ADDR_TYPE_AAAA)
        memcpy(answer.rdata, ipv6.values, 16);
    else
        memcpy(answer.rdata, ipv4.values, 4);
    response.answers.push_back(answer);

    response.write(bio);
    conn.send(endpoint, bio.data(), bio.cursor());
}

void Processor::run_done()
{
    static constexpr int CYCLE_SIZE = 5;
    std::unique_lock<std::mutex> guard(done_.mutex);

    while (running_)
    {
        if (done_.list.empty())
            done_.cond.wait_for(guard, std::chrono::milliseconds(1000));

        for (int i = 0; i < CYCLE_SIZE * 2; ++i)
        {
            bool is_blocked = false;
            bool is_heuristic = false;

            auto job = done_.list.pop_done();
            if (job == nullptr) break;

            if (job->result == DNSB_STATUS_HEURISTIC || job->result == DNSB_STATUS_BLOCKED)
            {
                is_blocked = true;
                is_heuristic = job->result == DNSB_STATUS_HEURISTIC;
                job->result = DNSB_STATUS_BLOCKED;

                if (job->request.questions[0].type == ADDR_TYPE_AAAA)
                    job->ipv6 = IPV6_BLOCK_ADDRESS;
                else
                    job->ipv4 = IPV4_BLOCK_ADDRESS;
                answer(*conn_.pub, job->request, job->endpoint, job->ipv4, job->ipv6);
            }
            else
            if (job->result == DNSB_STATUS_CACHE)
                answer(*conn_.pub, job->request, job->endpoint, job->ipv4, job->ipv6);
            else
            if (job->result == DNSB_STATUS_FAILURE)
                send_error(job->request, DNS_RCODE_SERVFAIL, job->endpoint);
            else
            {
                job->result = DNSB_STATUS_NXDOMAIN;
                send_error(job->request, DNS_RCODE_NXDOMAIN, job->endpoint);
            }

            std::cerr << "Job #" << (size_t) job << " took " << (clock_micro() - job->timer)/1000 << " ms to complete\n";

            print_request(job->request.questions[0].qname, job->endpoint.address.to_string(), "", job->request.questions[0].type, config_,
                is_blocked, job->result, job->ipv4, job->ipv6, is_heuristic, false);

            delete job;
        }

        if (done_.list.empty()) continue;

        for (int i = 0; i < CYCLE_SIZE; ++i)
        {
            if (!conn_.priv->poll(100)) break;

            // receive the UDP message
            Endpoint endpoint;
            buffer bio;
            size_t size = bio.size();
            if (!conn_.priv->receive(endpoint, bio.data(), &size, 100)) break;
            bio.resize(size);
            // parse the message
            dns_message_t response;
            response.read(bio);

            Job *job = done_.list.pop_priv(response.header.id);
            if (job == nullptr) continue;

            // use the first compatible answer
            if (response.header.rcode == 0 &&
                response.answers.size() > 0 &&
                response.questions.size() == 1 &&
                response.questions[0].qname == job->request.questions[0].qname)
            {
                for (auto it = response.answers.begin(); it != response.answers.end(); ++it)
                {
                    if (it->type == job->request.questions[0].type)
                    {
                        if (it->type == ADDR_TYPE_AAAA)
                        {
                            job->ipv6 = ipv6_t((uint16_t*)it->rdata);
                            cache_->add(response.questions[0].qname, nullptr, &job->ipv6);
                        }
                        else
                        {
                            job->ipv4 = ipv4_t(it->rdata);
                            cache_->add(response.questions[0].qname, &job->ipv4, nullptr);
                        }
                        answer(*conn_.pub, job->request, job->endpoint, job->ipv4, job->ipv6);
                        std::cerr << "Job #" << (size_t) job << " took " << (clock_micro() - job->timer)/1000 << " ms to complete\n";
                        break;
                    }
                }
            }

            print_request(job->request.questions[0].qname, job->endpoint.address.to_string(), "", job->request.questions[0].type, config_,
                false, job->result, job->ipv4, job->ipv6, false, false);

            delete job;
        }

        // TODO: handle expired jobs
    }
}

void Processor::run(int nthreads)
{
    running_ = true;

    std::thread *pool[3];
    pool[0] = new std::thread( [this]() { this->run_idle(); } );
    pool[1] = new std::thread( [this]() { this->run_pending(); } );
    pool[2] = new std::thread( [this]() { this->run_done(); } );

    run_main();

    for (int i = 0; i < 3; ++i)
    {
        pool[i]->join();
        delete pool[i];
    }
}

bool Processor::finish()
{
    if (!running_) return true;
    running_ = false;
    return false;
}

}