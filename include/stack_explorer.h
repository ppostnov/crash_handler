#pragma once
#ifndef _WIN32
#  error "Stack explorer is for Windows only!!"
#endif

#include "process_monitor.h"

using namespace process_monitor;

struct stack_explorer
{
    stack_explorer(DWORD dw_process_id = GetCurrentProcessId(), char const* sympath = 0);
    ~stack_explorer();

    void thread_stack(DWORD thread_id, stack_frame_t* frames, size_t num_frames,
                      CONTEXT* cntx = NULL);

private:
    stack_explorer(const stack_explorer& other);
    stack_explorer& operator=(const stack_explorer& other);

    void sym_init();

    DWORD   dwProcId_;
    HANDLE  hProc_;

    static size_t const SYM_PATH_LEN = 2048;
    static size_t const SYM_NAME_LEN = 256;

    char sym_path_[SYM_PATH_LEN];
    char sym_name_[SYM_NAME_LEN];
};
