#pragma once

#include <cstdint>

namespace process_monitor
{

typedef int32_t   proc_id_t;
typedef int32_t   thread_id_t;
typedef uint64_t  mem_addr_t;
typedef uint64_t  mem_size_t;

size_t const  MAX_FILENAME_LEN = 1023;
size_t const  MAX_FUNCTION_LEN = 1023;
size_t const  MAX_BASENAME_LEN = 127;
size_t const  MAX_FULLNAME_LEN = 1023;

struct stack_frame_t
{
    char        file[MAX_FILENAME_LEN + 1];
    uint32_t    line;
    char        function[MAX_FUNCTION_LEN + 1];
    mem_addr_t  address;
};
struct module
{
    char        basename[MAX_BASENAME_LEN + 1];
    char        fullname[MAX_FULLNAME_LEN + 1];
    uint64_t    mtime;
    mem_addr_t  address;
    mem_size_t  size;
};


inline proc_id_t current_process_id();
inline proc_id_t current_thread_id ();

} // namespace process_monitor

#include "process_monitor.hpp"

