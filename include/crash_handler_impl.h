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

private:
    void dumpfile_append_date();

protected:
    virtual void install_handlers() = 0;
    virtual void remove_handlers () = 0;
    virtual void get_context     () = 0;
    virtual void get_stack       () = 0;

protected:
    static uint16_t const  DUMP_FILENAME_SIZE = 1024;

    util::fixed_string<DUMP_FILENAME_SIZE>  dumpfile;

    crash_info  info;

    time_t      time_t_buf;
    struct tm   tm_buf;

    primary_handler_f   ph_;
};


//#ifdef _WIN32
struct win_impl : handler::impl
{
    win_impl(primary_handler_f const* ph);
    ~win_impl();

protected:
    void install_handlers() override;
    void remove_handlers () override;
    void get_context     () override;
    void get_stack       () override;

protected:
    typedef void (*signal_handler_function_t)(int);

    int                           prev_crt_assert;
    int                           prev_crt_error;
    _purecall_handler             prev_purecall_handler;
    LPTOP_LEVEL_EXCEPTION_FILTER  prev_exception_filter;
    _invalid_parameter_handler    prev_invalid_param_handler;
    terminate_function            prev_terminate_func;
    signal_handler_function_t     prev_signal_handler;


    HANDLE            hSnapshot;
    HANDLE            hProc;
    HANDLE            hThread;
    THREADENTRY32     te;
    CONTEXT           cntx;
    MODULEENTRY32     mod_entry;

    STACKFRAME64      stack_frame;
    DWORD             image_type;
    stack_frame_t*    s_entry;
    IMAGEHLP_LINE64   line;
    DWORD             displacement;
};

/*#elif __linux__
struct linux_impl : handler::impl
{
    linux_impl(primary_handler_f const* ph);
    ~linux_impl();

protected:
    void install_handlers() override;
    void remove_handlers () override;
    void get_context     () override;
    void get_stack       () override;
};

#elif
#   error "Unsupported platform"
#endif*/
} // namespace crash_handler
