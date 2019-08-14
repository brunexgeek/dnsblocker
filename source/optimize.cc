#include "nodes.hh"


int main_usage()
{
    std::cerr << "Usage: optimize <target blacklist> <base blacklist>" << std::endl;
    std::cerr << "       optimize <target blacklist>" << std::endl;
    return 1;
}

void loadRules( const std::string &fileName, std::vector<std::string> &values )
{
    std::ifstream rules(fileName.c_str());
    if (!rules.good()) return;
    std::string line;

    while (!rules.eof())
    {
        std::getline(rules, line);
        values.push_back(line);
    }
}


int main( int argc, char **argv )
{
    if (argc < 2 || argc > 3) return main_usage();

    Tree<uint8_t> blacklist;
    std::vector<std::string> entries;

    if (argc == 3)
    {
        std::cerr << "-- Preloading '" << argv[2] << "'" << std::endl;
        loadRules(argv[2], entries);
        for (auto it = entries.begin(); it != entries.end(); ++it)
            blacklist.add(*it, 0);
        entries.clear();
    }

    loadRules(argv[1], entries);
    for (auto it = entries.begin(); it != entries.end(); ++it)
    {
        if (blacklist.add(*it, 0) == DNSBERR_OK)
            std::cout << *it << std::endl;
    }
}