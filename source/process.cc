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
static const uint8_t IPV6_BLOCK_VALUES[] = DNS_BLOCKED_IPV6_ADDRESS;

/**
 * Copy header and question from DNS request.
 */
static int copy_prologue( const dns_buffer_t &request, dns_buffer_t &response )
{
    dns_header_t &header = *((dns_header_t*) request.content);
    if (be16toh(header.q_count) != 1) return -1;
    const uint8_t *p = request.content + sizeof(dns_header_t);
    while (*p != 0) ++p;
    p += 1 + sizeof(uint16_t) * 2;
    int offset = (int) (p - request.content);
    memcpy(response.content, request.content, (size_t) offset);
    return offset;
}

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
    bool found = false;
    for (auto it = config.external_dns.begin(); it != config.external_dns.end(); ++it)
    {
        if (it->targets.empty())
        {
            //resolver_->set_dns(it->address, it->name);
            default_ns_ = Endpoint(it->address, 53);
            found = true;
        }
        else
        {
            for (size_t i = 0; i < it->targets.size(); ++i)
            {
                other_ns_.add(it->targets[i], std::pair(it->name, Endpoint(it->address, 53)));
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

static uint64_t current_ms()
{
    #ifdef __WINDOWS__
    return _time64(NULL);
    #else
    struct timespec current;
    clock_gettime(CLOCK_REALTIME, &current);
    return (uint64_t) current.tv_sec * 1000 + (uint64_t) current.tv_nsec / 1000 / 1000;
    #endif
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

static int rcode_to_status( int rcode, bool cache, bool blocked )
{
    if (blocked) return DNSB_STATUS_BLOCK;
    switch (rcode)
    {
        case DNS_RCODE_NOERROR: return cache ? DNSB_STATUS_CACHE : DNSB_STATUS_RECURSIVE;
        case DNS_RCODE_NXDOMAIN: return DNSB_STATUS_NXDOMAIN;
        default: return DNSB_STATUS_FAILURE;
    }
}

static void print_request(
    const std::string &host,
    const Endpoint &remote,
    const std::string &dns_name,
    int type,
    const Configuration &config,
    int result,
    uint8_t heuristic,
    uint64_t duration )
{
    Event event;
    const char *status = nullptr;
    int32_t flags = config.monitoring_;
    static std::atomic<uint64_t> last_id(1);

    if (result == DNSB_STATUS_BLOCK && flags & MONITOR_SHOW_DENIED)
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
    else
        return; // ignore event

    if (status != nullptr)
    {
        const int proto = (type == ADDR_TYPE_AAAA) ? 6 : 4;

        event.id = last_id.fetch_add(1, std::memory_order::memory_order_relaxed);
        event.time = current_epoch();
        event.source = remote.address.to_string();
        //event.ip = addr;
        event.duration = duration;
        event.server = dns_name;
        event.domain = host;
        event.proto = (uint8_t) proto;
        event.type = status;
        event.heuristic = heuristic;
        LOG_EVENT(event);
    }
}

static uint8_t *write_u16( uint8_t *ptr, uint16_t value )
{
    ptr[0] = (uint8_t) (value >> 8);
    ptr[1] = (uint8_t) value;
    return ptr + sizeof(uint16_t);
}

static uint8_t *write_u32( uint8_t *ptr, uint32_t value )
{
    ptr[0] = (uint8_t) (value >> 24);
    ptr[1] = (uint8_t) (value >> 16);
    ptr[2] = (uint8_t) (value >> 8);
    ptr[3] = (uint8_t) value;
    return ptr + sizeof(uint32_t);
}

bool Processor::send_error( const Endpoint &endpoint, const dns_buffer_t &request, int rcode )
{
    dns_buffer_t response;

    int size = copy_prologue(request, response);
    if (size < 0) return false;

    dns_question_t question;
    if (dns_read_question(request, sizeof(dns_header_t), question) == 0) return false;

    dns_header_t &header = *((dns_header_t*) response.content);
    header.qr = 1;
    header.rcode = rcode & 0xF;
    header.ans_count = 0;
    header.add_count = 0;
    header.auth_count = 0;
    auto result = conn_->send(endpoint, response.content, size);
    if (result)
        print_request(question.qname, endpoint, "default", question.type, config_, DNSB_STATUS_BLOCK, false, 0);
    return result;
}

bool Processor::send_blocked( const Endpoint &endpoint, const dns_buffer_t &request )
{
    dns_buffer_t response;
    std::string qname;

    int offset = copy_prologue(request, response);
    if (offset < 0) return false;
    dns_question_t question;
    if (dns_read_question(request, sizeof(dns_header_t), question) == 0) return false;

    // ignore questions not type A and AAAA
    if (question.type != DNS_TYPE_A && question.type != DNS_TYPE_AAAA)
        return false;

    dns_header_t &header = *((dns_header_t*) response.content);
    header.qr = 1;
    header.rcode = DNS_RCODE_NOERROR;
    header.ans_count = htobe16(1);
    header.add_count = 0;
    header.auth_count = 0;

    // qname (pointer to question)
    uint8_t *ptr = response.content + offset;
    *ptr++ = 0xC0;
    *ptr++ = (uint8_t) sizeof(dns_header_t);
    ptr = write_u16(ptr, question.type); // type
    ptr = write_u16(ptr, 1); // clazz
    ptr = write_u32(ptr, DNS_CACHE_TTL); // ttl

    if (question.type == DNS_TYPE_A)
    {
        ptr = write_u16(ptr, 4); // rdlen
        for (int i = 0; i < 4; ++i) // rdata
            *ptr++ = IPV4_BLOCK_VALUES[i];
    }
    else
    {
        ptr = write_u16(ptr, 16); // rdlen
        for (int i = 0; i < 16; ++i) // rdata
            *ptr++ = IPV6_BLOCK_VALUES[i];
    }

    auto result = conn_->send(endpoint, response.content, (size_t) (ptr - response.content));
    if (result)
        print_request(question.qname, endpoint, "default", question.type, config_, DNSB_STATUS_BLOCK, false, 0);
    return result;
}

/*
 * Forward to the client the answers received by external DNS server.
 */
bool Processor::send_success( const Endpoint &endpoint, const dns_buffer_t &request, const dns_buffer_t &response,
    uint64_t duration, bool cache )
{
    dns_header_t &header = *((dns_header_t*) response.content);
    dns_question_t question;
    if (dns_read_question(request, sizeof(dns_header_t), question) == 0) return false;

    int status = rcode_to_status(header.rcode, cache, false);

    auto result = conn_->send(endpoint, response.content, response.size);
    if (result)
        // TODO: detect error responses and log appropriately
        print_request(question.qname, endpoint, "default", question.type, config_, status, false, duration);
    return result;
}

void Processor::process(
    Processor *object,
    int thread_num,
    std::mutex *mutex,
    std::condition_variable *cond )
{
    (void) thread_num;

    std::unique_lock<std::mutex> guard(*mutex);
    Resolver resolver;
    std::map<uint16_t, Job*> wait_list;

    while (object->running_)
    {
        dns_buffer_t response;
        Job *job = object->pop();
        if (job != nullptr)
        {
            auto &item = *job;
            item.header = ((dns_header_t*) item.request.content);
            dns_question_t question;
            dns_read_question(item.request, sizeof(dns_header_t), question);
            item.type = question.type;
            item.qname = question.qname;

print_dns_message(std::cerr, job->request);

            bool is_pass_through = (item.type != DNS_TYPE_A && item.type != DNS_TYPE_AAAA);
            bool is_blocked = false;
            bool heuristic = false;

            if (!is_pass_through)
            {
                // assume NXDOMAIN for domains without periods (e.g. local host names)
                // TODO: add configuration option for local domain
                if (item.qname.find('.') == std::string::npos || item.header->rd == 0)
                {
                    object->send_error(item.endpoint, item.request, DNS_RCODE_NXDOMAIN);
                    delete job;
                    job = nullptr;
                    continue; // TODO: get new job or process jobs in the wait list?
                }

                // check whether the domain is blocked
                if (object->useFiltering_)
                {
                    std::shared_lock<std::shared_mutex> guard(object->lock_);
                    if (object->whitelist_.match(item.qname) == nullptr)
                    {
                        is_blocked = object->blacklist_.match(item.qname) != nullptr;
                        // try the heuristics
                        //--if (!is_blocked && object->useHeuristics_)
                        //--    is_blocked = (heuristic = detect_heuristic(item.qname)) != 0;
                    }
                }
            }

            // is the query blocked?
            if (is_blocked)
            {
                object->send_blocked(item.endpoint, item.request);
                delete job;
                job = nullptr;
            }
            else
            {
                bool cache_used = false;
                if (!is_pass_through)
                {
                    // cache look up
                    int result = DNSB_STATUS_FAILURE;
                    if (item.type == DNS_TYPE_A)
                        result = object->cache_->find_ipv4(item.qname, response);
                    else
                    if (item.type == DNS_TYPE_AAAA)
                        result = object->cache_->find_ipv6(item.qname, response);
                    if (result != DNSB_STATUS_FAILURE)
                    {
                        dns_header_t *rh = ((dns_header_t*) response.content);
                        rh->id = item.oid;
                        object->send_success(item.endpoint, item.request, response, 0, true);
                        cache_used = true;
                        delete job;
                        job = nullptr;
                    }
                }

                // send the request to external DNS
                if (!cache_used)
                {
                    item.id = resolver.next_id();
                    item.max = 1;
                    int sent = 0;

                    // try the secondary DNS
                    auto node = object->other_ns_.match(item.qname);
                    if (node != nullptr)
                    {
                        item.max = 2;
                        sent |= resolver.send(node->value.second, item.request, item.id | 0x8000);
                    }
                    // try the primary DNS
                    sent |= resolver.send(object->default_ns_, item.request, item.id);

                    if (sent)
                        wait_list.insert( std::pair(job->id, job) );
                    else
                        object->send_error(item.endpoint, item.request, DNS_RCODE_SERVFAIL);
                }
            }
        }
        else
        if (wait_list.empty())
        {
            cond->wait_for(guard, std::chrono::seconds(2));
            continue;
        }

        // process each UDP response
        while (resolver.receive(response, 0) > 0)
        {
            dns_header_t &header = *((dns_header_t*) response.content);
            // look for a matching pending entry
            auto it = wait_list.find(header.id & 0x7FFF);
            if (it != wait_list.end())
            {
                Job &item = *it->second;
                item.response = response;
                ++item.count;

                // is a successfully secondary response?
                if (header.id & 0x8000 && header.rcode == DNS_RCODE_NOERROR)
                    item.count = 255; // force the transmission
            }
        }

        for (auto it = wait_list.begin(); it != wait_list.end();)
        {
            auto &item = *it->second;

            // check whether is time to send the current response
            if (item.count == item.max || (item.count == 1 && (current_ms() - item.duration) > 2500))
            {
                // use the current response as correct
                dns_header_t &header = *((dns_header_t*) item.response.content);
                header.id = item.oid; // recover the original ID
                item.duration = current_ms() - item.duration;
                object->send_success(item.endpoint, item.request, item.response, item.duration, false);
                // update cache
                if (item.type == DNS_TYPE_A)
                    object->cache_->append_ipv4(item.qname, response);
                else
                if (item.type == DNS_TYPE_AAAA)
                    object->cache_->append_ipv6(item.qname, response);

                it = wait_list.erase(it);
                delete &item;
            }
            else
            // discard timed out job
            if (current_ms() - item.duration > 2500)
            {
                it = wait_list.erase(it);
                delete &item;
            }
            else
                ++it;
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

    dns_buffer_t buffer;
    while (running_)
    {
        buffer.size = sizeof(buffer.content);
        // receive the UDP message
        if (!conn_->receive(endpoint, buffer.content, &buffer.size, 2000)) continue;
        // ignore messages with the number of questions other than 1
        dns_header_t &header = *((dns_header_t*) buffer.content);
        if (be16toh(header.q_count) == 1)
        {
            auto job = new Job(endpoint, buffer);
            job->oid = header.id;
            job->duration = current_ms();
            push(job);
            cond.notify_all();
        }
        else
            send_error(endpoint, buffer, DNS_RCODE_REFUSED);
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