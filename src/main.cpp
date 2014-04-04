#include <iostream>
//#include "crash_handler.h"
#include "util.h"

int main(int argc, char* argv[])
{
    util::path_composer pc;
    pc.clear();
    pc.append("C:\\Users\\pavel");
    pc.append("C:\\Windows");
    pc.append("C:\\Windows\\System32");
    pc.append("C:\\Program Files (x86)\\");

    std::cout << pc.path() << std::endl;

    int var;
    std::cin >> var;
    return 0;
}
