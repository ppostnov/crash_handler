#pragma once
#ifdef _WIN32
#   include <Windows.h>
#elif __linux__

#else
#  error "Unsupported platform"
#endif


namespace process_monitor
{

#ifdef _WIN32

inline proc_id_t current_process_id()
{
    return proc_id_t(GetCurrentProcessId());
}

#elif __linux__

inline proc_id_t current_process_id()
{
    return proc_id_t(getpid());
}

#endif

} // namespace process_monitor
