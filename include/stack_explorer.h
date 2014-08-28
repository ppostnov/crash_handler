#pragma once
#include <DbgHelp.h>
#ifndef _WIN32
#  error "Stack explorer is for Windows only!!"
#endif

#include "util.h"
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

    DWORD   dw_proc_id_;
    HANDLE  h_proc_;

    static size_t const  SYM_NAME_LEN = 256;

    char  sym_name_[SYM_NAME_LEN];

    // auxiliary variables
    util::path_composer pc_;
    size_t  len_;

    static size_t const  PATH_BUF_LEN = 1024;

    char           path_buf_[PATH_BUF_LEN];
    size_t         written_;
    HRESULT        res_;
    DWORD          sym_options_;
    MODULEENTRY32  mod_entry_;
    HANDLE         h_snap_;

    HANDLE              h_thread_;
    CONTEXT             context_;
    STACKFRAME64        stack_frame_;
    DWORD               image_type_;
    char                p_sym_buf_[sizeof(IMAGEHLP_SYMBOL64) + SYM_NAME_LEN * sizeof(CHAR)];
    PIMAGEHLP_SYMBOL64  p_sym_;
    stack_frame_t*      s_entry_;
    IMAGEHLP_LINE64     line_;
    DWORD               displacement_;
};

