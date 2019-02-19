#ifndef DNSB_NODES_HH
#define DNSB_NODES_HH

#include <stdint.h>
#include <iostream>
#include <fstream>
#include <cstring>
#include "log.hh"


int charToIndex( char c );
char indexToChar( int index );
char *prepareHostname( char *host );

template<typename T>
struct Node
{
    static const int TERMINAL = 1; // this node is a terminal symbol
    static const int WILDCARD = 2; // denote a wildcard
    static const int SLOTS    = 38; // 26 letters, 10 digits, dash and dot
    static const int MAX_HOST_LENGTH = 512;

    Node<T> *slots[SLOTS];
    int flags = 0;
    T value;

    Node( T value = 0 );
    ~Node();
    bool add( const std::string &host, uint32_t value, size_t *allocated = nullptr );
    const Node<T> *match( const std::string &host ) const;
};


template<typename T>
class Tree
{
    public:
        Tree();
        ~Tree();
        Tree( const Tree &that ) = delete;
        Tree( Tree &&that ) = delete;
        bool load( const std::string &fileName );
        uint32_t size() const;
        size_t memory() const;
        bool add( const std::string &host, uint32_t value );
        const Node<T> *match( const std::string &host ) const;

    private:
        Node<T> root;
        uint32_t counter;
        size_t allocated;
};


template<typename T>
Node<T>::Node( T value )
{
    memset(slots, 0, sizeof(slots));
    this->value = value;
    flags = 0;
}


template<typename T>
Node<T>::~Node()
{
    for (size_t i = 0; i < SLOTS; ++i)
    delete slots[i];
}


template<typename T>
bool Node<T>::add( const std::string &host, uint32_t value, size_t *allocated )
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
            add(temp + 3, value, allocated);
        else
        if (temp[1] != '.')
            return false;
    }

    // preprocess the host name
    char *ptr = prepareHostname(temp);
    if (ptr == nullptr) return false;

    Node *next = this;
    for (;*ptr != 0; ++ptr)
    {
        int idx = charToIndex(*ptr);
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
    next->value = value;
    if (isWildcard) next->flags |= Node::WILDCARD;

    return true;
}


template<typename T>
const Node<T> *Node<T>::match( const std::string &host ) const
{
    if (host.empty() || host.length() > MAX_HOST_LENGTH) return nullptr;

    char temp[MAX_HOST_LENGTH + 1] = { 0 };
    strcpy(temp, host.c_str());

    // preprocess the host name
    char *ptr = prepareHostname(temp);
    if (ptr == nullptr) return nullptr;

    const Node *next = this;
    for (;*ptr != 0; ++ptr)
    {
        if (next->flags & Node::WILDCARD) return next;

        int idx = charToIndex(*ptr);
        if (next->slots[idx] == nullptr)
            return nullptr;
        else
            next = next->slots[idx];
    }

    if ((next->flags & Node::TERMINAL) != 0)
        return next;
    else
        return nullptr;
}


template<typename T>
Tree<T>::Tree() : counter(0), allocated(0)
{
}


template<typename T>
Tree<T>::~Tree()
{
}


template<typename T>
bool Tree<T>::load(
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


template<typename T>
uint32_t Tree<T>::size() const
{
    return counter;
}


template<typename T>
size_t Tree<T>::memory() const
{
    return allocated;
}


template<typename T>
bool Tree<T>::add( const std::string &host, uint32_t id )
{
    return root.add(host, id);
}


template<typename T>
const Node<T> *Tree<T>::match( const std::string &host ) const
{
    return root.match(host);
}


#endif // DNSB_NODES_HH