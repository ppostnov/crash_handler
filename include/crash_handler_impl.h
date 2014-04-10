#pragma once
#include <ctime>

#ifdef _WIN32
#   include <stdlib.h>
#   include <Windows.h>
#   include <Psapi.h>
#   pragma comment(lib, "Psapi.lib")
#   include <TlHelp32.h>
#   include <eh.h>
#   include "stack_explorer.h"
#endif

namespace crash_handler
{
struct handler::impl
{
    impl(primary_handler_f const* ph);
    virtual ~impl();

    void report_and_exit();

protected:
    virtual void install_handlers() = 0;
    virtual void remove_handlers () = 0;

protected:
    static uint16_t const  DUMP_FILENAME_SIZE = 1024;
    static uint16_t const  TIME_BUF_SIZE      =   20;

    util::fixed_string<DUMP_FILENAME_SIZE>  dumpfile;

    crash_info  info;

    time_t      time_t_buf;
    struct tm   tm_buf;
    char        time_buf[TIME_BUF_SIZE];

    primary_handler_f   ph_;
};


//#ifdef _WIN32
struct win_impl : handler::impl
{
    win_impl(primary_handler_f const* ph);
    ~win_impl();

    void install_handlers() override;
    void remove_handlers () override;


    typedef void (*signal_handler_function_t)(int);

protected:
    int                           prev_crt_assert;
    int                           prev_crt_error;
    _purecall_handler             prev_purecall_handler;
    LPTOP_LEVEL_EXCEPTION_FILTER  prev_exception_filter;
    _invalid_parameter_handler    prev_invalid_param_handler;
    terminate_function            prev_terminate_func;
    signal_handler_function_t     prev_signal_handler;


    HANDLE            hSnapshot;
    THREADENTRY32     te;
    CONTEXT*          cntx;
    MODULEENTRY32     mod_entry;

    char              stexp_place[sizeof(stack_explorer)];
};

/*#elif __linux__
struct linux_impl : handler::impl
{
    linux_impl(primary_handler_f const* ph);
    ~linux_impl();

    void install_handlers() override;
    void remove_handlers () override;
};

#elif
#   error "Unsupported platform"
#endif*/
} // namespace crash_handler
