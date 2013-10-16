#pragma once
#ifndef _WIN32
#  error "Stack explorer is for Windows only!!"
#endif

struct stack_explorer
{
    stack_explorer(DWORD dw_process_id = GetCurrentProcessId(), char const* sympath = 0);
    ~stack_explorer();

    void thread_stack(thread_stack_t* frames, size_t num_frames,
                      HANDLE hThread, CONTEXT* context = NULL);

private:
    stack_explorer(const stack_explorer& other);
    stack_explorer& operator=(const stack_explorer& other);

    void sym_init();

    DWORD   dwProcId_;
    HANDLE  hProc_;

    size_t const SYM_PATH_LEN;
    char sym_path_[SYM_PATH_LEN];
};
