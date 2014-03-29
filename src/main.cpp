#include "crash_handler.h"

int main(int argc, char* argv[])
{
    crash_handler::handler ch;

    int* a = 0;
    *a = 2;
    return 0;
}
