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

static bool is_ipv4( const std::string &value, ipv4_t &ipv4 )
{
    if (value.length() < 8 && value.length() > 15) return false;
    int number = 0;
    int dots = 0;

    char temp[16] = { 0 };
    // copy ignoring leading and trailing whitespaces
    for (size_t i = 0, j = 0; j < value.length(); ++j)
    {
        if (isdigit(value[j]))
        {
            ++number;
            temp[i++] = value[j];
        }
        else
        if (value[j] == '.')
        {
            if (number == 0) return false;
            temp[i++] = value[j];
            number = 0;
            ++dots;
        }
        else
        if (value[j] == ' ' || value[j] == '\t')
            continue;
        else
            return false;
    }
    if (temp[0] != 0 && dots == 3 && number > 0)
    {
        ipv4 = ipv4_t(temp);
        return true;
    }
    return false;
}

bool Processor::load_rules( const std::vector<std::string> &fileNames, Tree<uint8_t> &tree )
{
    if (fileNames.empty()) return false;

    tree.clear();
    //ipv4list_.clear();

    for (auto it = fileNames.begin(); it != fileNames.end(); ++it)
    {
        int rc = 0, ic = 0;
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

            ipv4_t ipv4;
            if (is_ipv4(line, ipv4))
            {
                ipv4list_.emplace(ipv4);
                ++ic;
            }
            else
            {
                int result = tree.add(line, 0, &line);
                if (line.empty()) continue;

                if (result == DNSBERR_OK)
                {
                    ++rc;
                    continue;
                }
                else
                if (result == DNSBERR_DUPLICATED_RULE)
                    LOG_MESSAGE("  [!] Duplicated '%s'\n", line.c_str());
                else
                    LOG_MESSAGE("  [!] Invalid rule '%s'\n", line.c_str());
            }
        }

        rules.close();
        LOG_MESSAGE("  Loaded %d rules\n", rc);
        LOG_MESSAGE("  Loaded %d IPs\n", ic);
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
        ipv4list_.clear();
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

bool Processor::send_error( const Endpoint &endpoint,  const dns_message_t &request, int rcode )
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



uint8_t Processor::detect_heuristic( std::string name )
{
    constexpr uint8_t RULE_BGS = 1;
    constexpr uint8_t RULE_GON = 2;
    constexpr uint8_t RULE_VOW = 3;
    static const int MINLEN = 8;

    if (name.length() < 8) return 0;

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
        if (bgs > 4) return RULE_BGS; // at least 5 digits in the biggest group
        if (gon > 1) return RULE_GON; // at least 2 groups of digits
        if ((float) vc / (float) len < 0.3F) return RULE_VOW; // less than 30% of vowels
    }
    return 0;
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
    uint8_t heuristic )
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
        event.heuristic = heuristic;
        LOG_EVENT(event);
    }
}

static const int MAX_PENDINGS = 10;

uint16_t next_id( int thread_num, int &counter )
{
    counter = (counter + 1) & 0x0FFF;
    if (counter == 0) counter = 1; // to avoid id = 0
    return (uint16_t) (((thread_num & 0x0F) << 12) | counter);
}

#ifdef ENABLE_IPV6
void Processor::send_success( const Endpoint &endpoint, const dns_message_t &request,
    const ipv4_t &ipv4, const ipv6_t &ipv6 )
#else
void Processor::send_success( const Endpoint &endpoint, const dns_message_t &request,
    const ipv4_t &ipv4 )
#endif
{
    // response message
    buffer bio;
    dns_message_t response;
    response.header.id = request.header.id;
    response.header.flags = DNS_FLAG_QR;
    if (request.header.flags & DNS_FLAG_RD)
        response.header.flags |= DNS_FLAG_RA | DNS_FLAG_RD;
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
    conn_->send(endpoint, bio.data(), bio.cursor());
}

void Processor::send_blocked( const Endpoint &endpoint, const dns_message_t &request )
{
    send_success(endpoint, request, IPV4_BLOCK_ADDRESS
    #ifdef ENABLE_IPV6
    , IPV6_BLOCK_ADDRESS
    #endif
    );
}

/*
 * Forward to the client the answers received by external DNS server.
 */
bool Processor::send_success( const Endpoint &endpoint, const dns_message_t &request, const std::vector<dns_record_t> &answers )
{
    // build the query message
    dns_message_t response;
    response.header.id = request.header.id;
    response.header.flags = DNS_FLAG_QR;
    if (request.header.flags & DNS_FLAG_RD)
        response.header.flags |= DNS_FLAG_RA | DNS_FLAG_RD;
    response.questions.push_back(request.questions[0]);
    for (auto &item : answers)
        response.answers.push_back(item);
    // encode the message
    buffer bio;
    response.write(bio);

    return conn_->send(endpoint, bio.data(), bio.cursor());
}

bool Processor::forward_request( UDP &conn, const Endpoint &endpoint, const dns_message_t &request, uint16_t id )
{
    // build the query message
    dns_message_t message;
    message.header.id = id;
    message.header.flags = DNS_FLAG_RD | DNS_FLAG_AD;
    message.questions.push_back(request.questions[0]);
    // encode the message
    buffer bio;
    message.write(bio);

    std::cerr << "Sending request #" << id << " to external DNS\n";

    return conn.send(endpoint, bio.data(), bio.cursor());
}

void Processor::process(
    Processor *object,
    int thread_num,
    std::mutex *mutex,
    std::condition_variable *cond )
{
    std::unique_lock<std::mutex> guard(*mutex);
    //Resolver resolver(*object->cache_);
    UDP extns; // external name server
    Endpoint extep("8.8.8.8", 53);
    std::list<Job*> jobs;
    int counter = 0; // per-thread counter

    while (object->running_)
    {
        bool new_job = false;
        // try to pick another job
        if (jobs.size() < MAX_PENDINGS)
        {
            Job *job = object->pop();
            if (job != nullptr)
            {
                job->id = next_id(thread_num, counter);
                jobs.push_back(job);
                new_job = true;
            }
            else
            if (jobs.size() == 0) // no jobs
            {
                cond->wait_for(guard, std::chrono::seconds(2));
                continue;
            }
        }

        // process jobs from the internal list
        for (auto it = jobs.begin(); it != jobs.end();)
        {
            auto &item = **it;
            if (item.status == Status::BLOCK)
            {
                object->send_blocked(item.endpoint, item.request);
                it = jobs.erase(it);
            }
            else
            if (item.status == Status::ERROR)
            {
                object->send_error(item.endpoint, item.request, DNS_RCODE_SERVFAIL);
                it = jobs.erase(it);
            }
            else
            if (item.status == Status::NXDOMAIN)
            {
                object->send_error(item.endpoint, item.request, DNS_RCODE_NXDOMAIN);
                it = jobs.erase(it);
            }
            else
            if (item.status == Status::PENDING)
            {
                const dns_message_t &request = item.request;
                bool is_blocked = false;
                bool heuristic = false;

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
                            is_blocked = (heuristic = detect_heuristic(request.questions[0].qname)) != 0;
                    }
                }

                if (is_blocked)
                    item.status = Status::BLOCK;
                else
                {
                    // assume NXDOMAIN for domains without periods (e.g. local host names)
                    // otherwise we try the external DNS
                    if (request.questions[0].qname.find('.') != std::string::npos && request.header.flags & DNS_FLAG_RD)
                    {
                        std::string dns_name; // external DNS name in configuration file
                        ipv4_t ipv4;

                        if (!object->forward_request(extns, extep, item.request, item.id))
                            item.status = Status::ERROR;
                        else
                            item.status = Status::WAITING;
                    }
                    else
                        item.status = Status::NXDOMAIN;
                }
                ++it;
            }
            else
                // current status is WAITING
                ++it;
        }

        // process each UDP response
        Endpoint endpoint;
        buffer buf;
        while (extns.poll(new_job ? 0 : 250)) // wait up until 250ms only if no job was got in this iteration
        {
            size_t size = buf.size();
            if (extns.receive(endpoint, buf.data(), &size))
            {
                dns_message_t response;
                response.read(buf); // TODO: just parse the header
                std::cerr << "Received response #" << response.header.id << "\n";

                // look for a matching pending entry
                auto it = jobs.begin();
                while (it != jobs.end() && (*it)->id != response.header.id)
                    it++;
                if (it != jobs.end())
                {
                    Job &item = **it;

                    std::cerr << "Received response from external DNS for #" << item.id << "\n";
                    object->send_success(item.endpoint, item.request, response.answers);
                    it = jobs.erase(it);
                }
            }
        }
    }

#if 0
                                std::shared_lock<std::shared_mutex> guard(object->lock_);
                                if (object->ipv4list_.find(ipv4) != object->ipv4list_.end())
                                {
                                    std::cerr << "Blocked by IP " << ipv4.to_string() << '\n';
                                    ipv4 = IPV4_BLOCK_ADDRESS;
                                    dns_name.clear();
                                    result = DNSB_STATUS_FAILURE;
                                    is_blocked = true;
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
            heuristic);

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
#endif
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
            send_error(endpoint, request, DNS_RCODE_REFUSED);
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