#include "nodes.hh"
#include <cstring>
#include <fstream>
#include "log.hh"


Node::Node()
{
    memset(slots, 0, sizeof(slots));
    #ifdef NODE_ENABLE_ID
    id = ++Node::counter;
    #endif
    flags = 0;
}


Node::~Node()
{
    for (size_t i = 0; i < SLOTS; ++i)
        delete slots[i];
}


int Node::index( char c ) const
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A'; // 0..25
    if (c >= 'a' && c <= 'z')
        return c - 'a'; // 0..25
    if (c >= '0' && c <= '9')
        return c - '0' + 26; // 26..35
    if (c == '-')
        return 36;
    if (c == '.')
        return 37;
    return -1;
}

char Node::text( int index )
{
    if (index >= 0 && index <= 25) return (char)('A' + index);
    if (index >= 26 && index <= 35) return (char)('0' + index);
    if (index == 36) return '-';
    if (index == 37) return '.';
    return '?';
}

char *Node::prepare( char *host ) const
{
    if (host == nullptr) return nullptr;
    char *ptr = host;

    // remove leading and trailing unused characters
    while (*ptr == ' ' || *ptr == '*') ++ptr;
    if (*ptr == 0) return nullptr;
    for (size_t i = strlen(ptr) - 1; ptr[i] == ' '; --i) *ptr = 0;
    // validate the host characters
    for (char *p = ptr; *p != 0; ++p)
        if (index(*p) < 0) return nullptr;
    // reverse the symbols
    for (size_t i = 0, t = strlen(ptr); i < t / 2; i++)
        std::swap(ptr[i],  ptr[t - i - 1]);

    if (*ptr == '.') return nullptr;

    return ptr;
}

bool Node::add( const std::string &host, uint32_t id, size_t *allocated )
{
    if (host.empty() || host.length() > MAX_HOST_LENGTH) return false;

    char temp[MAX_HOST_LENGTH + 1] = { 0 };
    strcpy(temp, host.c_str());

    bool isWildcard = false;
    // '*' and '**' must precede a period
    if (temp[0] == '*')
    {
        isWildcard = true;

        // if we have a 'double star', add the domain itself
        if (temp[1] == '*' && temp[2] == '.')
            add(temp + 3, id, allocated);
        else
        if (temp[1] != '.')
            return false;
    }

    // preprocess the host name
    char *ptr = prepare(temp);
    if (ptr == nullptr) return false;

    Node *next = this;
    for (;*ptr != 0; ++ptr)
    {
        int idx = index(*ptr);
        if (next->slots[idx] == nullptr)
        {
            next = next->slots[idx] = new Node();
            if (allocated != nullptr) *allocated += sizeof(Node);
        }
        else
        {
            next = next->slots[idx];
            if (next->flags & Node::WILDCARD) return true;
        }
    }
    next->flags |= Node::TERMINAL;
    if (isWildcard) next->flags |= Node::WILDCARD;

    return true;
}

bool Node::match( const std::string &host ) const
{
    if (host.empty() || host.length() > MAX_HOST_LENGTH) return false;

    char temp[MAX_HOST_LENGTH + 1] = { 0 };
    strcpy(temp, host.c_str());

    // preprocess the host name
    char *ptr = prepare(temp);
    if (ptr == nullptr) return false;

    const Node *next = this;
    for (;*ptr != 0; ++ptr)
    {
        if (next->flags & Node::WILDCARD) return true;

        int idx = index(*ptr);
        if (next->slots[idx] == nullptr)
            return false;
        else
            next = next->slots[idx];
    }

    return (next->flags & Node::TERMINAL) != 0;
}

#ifdef NODE_ENABLE_ID
void Node::print( std::ostream &out )
{
    if (this->flags & Node::WILDCARD)
        out << this->id << " [color=blue]" << std::endl;
    else
    if (this->flags & Node::TERMINAL)
        out << this->id << " [color=red]" << std::endl;

    for (int i = 0; i < Node::SLOTS; ++i)
    {
        if (slots[i] == nullptr) continue;
        out << this->id << " -> " << slots[i]->id << " [label=\"" << text(i) << "\"]" << std::endl;
        slots[i]->print(out);
    }
}
#endif


Tree::Tree() : counter(0), allocated(0)
{
}

Tree::~Tree()
{
}

bool Tree::load(
    const std::string &fileName )
{
    std::ifstream rules(fileName.c_str());
    if (rules.good())
    {
        std::string line;

        while (!rules.eof())
        {
            std::getline(rules, line);
            if (line.empty()) continue;

            // we have a comment?
            const char *ptr = line.c_str();
            while (*ptr == ' ') ++ptr;
            if (*ptr == '#') continue;

            if (root.add(line, ++counter, &allocated))
            {
                LOG_MESSAGE("  Added '%s'\n", line.c_str());
            }
            else
                LOG_MESSAGE("  Invalid rule '%s'\n", line.c_str());
        }

        rules.close();
        return true;
    }

    return false;
}

uint32_t Tree::size() const
{
    return counter;
}

size_t Tree::memory() const
{
    return allocated;
}


bool Tree::add( const std::string &host, uint32_t id )
{
    return root.add(host, id);
}

bool Tree::match( const std::string &host ) const
{
    return root.match(host);
}