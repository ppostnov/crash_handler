#include "crash_handler.h"

int main(int argc, char* argv[])
{
    crash_handler::handler ch;

    throw "Hello";
    return 0;
}
