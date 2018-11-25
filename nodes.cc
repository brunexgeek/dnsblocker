#include "nodes.hh"
#include <cstring>
#include <fstream>


extern FILE *LOG_FILE;
size_t Node::allocated = 0;
int Node::counter = 0;

Node::Node()
{
    memset(slots, 0, sizeof(slots));
    id = nextId();
    flags = 0;
    allocated += sizeof(Node);
}

int Node::nextId()
{
    return ++counter;
}

int Node::index( char c )
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a';
    if (c >= '0' && c <= '9')
        return c - '0' + 26;
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

bool Node::convert( const std::string &host, std::string &entry )
{
    for (int i = (int) host.length() - 1; i >= 0; --i)
    {
        if (host[i] == '*') continue;
        int c = index(host[i]);
        if (c < 0) return false;
        entry += (char) c;
    }

    return true;
}

bool Node::add( const std::string &host )
{
    if (host.empty()) return false;
    const char *ptr = host.c_str();

    bool isWildcard = false;
    // '*' and '**' must precede a dot
    if (ptr[0] == '*')
    {
        isWildcard = true;

        // if we have a 'double star', add the domain itself
        if (ptr[1] == '*' && ptr[2] == '.')
            add(ptr + 3);
        else
        if (ptr[1] != '.')
            return false;
    }

    std::string temp;
    if (!convert(host, temp)) return false;

    Node *next = this;
    for (size_t i = 0, t = temp.length(); i < t; ++i)
    {
        if (next->slots[(int)temp[i]] == nullptr)
            next = next->slots[(int)temp[i]] = new Node();
        else
        {
            next = next->slots[(int)temp[i]];
            if (next->flags & Node::WILDCARD) return true;
        }
    }
    next->flags |= Node::TERMINAL;
    if (isWildcard) next->flags |= Node::WILDCARD;

    return true;
}

bool Node::match( const std::string &host )
{
    std::string temp;
    if (!convert(host, temp)) return false;

    Node *next = this;
    for (size_t i = 0, t = temp.length(); i < t; ++i)
    {
        if (next->flags & Node::WILDCARD) return true;

        if (next->slots[(int)temp[i]] == nullptr)
            return false;
        else
            next = next->slots[(int)temp[i]];
    }

    return (next->flags & Node::TERMINAL) != 0;
}

void Node::print( std::ostream &out )
{
    if (this->flags & Node::WILDCARD)
        out << this->id << " [color=blue]" << std::endl;
    else
    if (this->flags & Node::TERMINAL)
        out << this->id << " [color=red]" << std::endl;

    for (int i = 0; i < 38; ++i)
    {
        if (slots[i] == nullptr) continue;
        out << this->id << " -> " << slots[i]->id << " [label=\"" << text(i) << "\"]" << std::endl;
        slots[i]->print(out);
    }

}

bool Node::load( const std::string &fileName, Node &root )
{
    std::ifstream rules(fileName.c_str());
    if (rules.good())
    {
        while (!rules.eof())
        {
            std::string line;
            std::getline(rules, line);
            if (line.empty()) continue;
            if (root.add(line))
                fprintf(LOG_FILE, "Added '%s'\n", line.c_str());
            else
                fprintf(LOG_FILE, "Invalid rule '%s'\n", line.c_str());
        }

        rules.close();
        return true;
    }

    return false;
}

int Node::count()
{
    return counter;
}