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

inline proc_id_t current_thread_id ()
{
    return proc_id_t(GetCurrentThreadId());
}

#elif __linux__

inline proc_id_t current_process_id()
{
    return proc_id_t(getpid());
}


inline proc_id_t current_thread_id ()
{
    return proc_id_t(gettid());
}
#endif

} // namespace process_monitor
