#include <Windows.h>
#include <Shlwapi.h>
#include <TlHelp32.h>
#pragma comment(lib, "DbgHelp.lib")
#pragma comment(lib, "Shlwapi.lib")

#include "stack_explorer.h"



stack_explorer::stack_explorer(DWORD dw_process_id, char const* sympath)
    : dw_proc_id_(dw_process_id)
{
    h_proc_ = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dw_proc_id_);
    sym_init();

    // load_modules();
}

stack_explorer::~stack_explorer()
{
    SymCleanup(h_proc_);
    if (h_proc_)
        CloseHandle(h_proc_);
}

void stack_explorer::sym_init()
{
    pc_.clear();
    len_ = 0;
    len_ += pc_.append(".", 1);

    written_ = GetCurrentDirectoryA(PATH_BUF_LEN, path_buf_);
    len_ += pc_.append(path_buf_, PATH_BUF_LEN);

    written_ += GetModuleFileNameA(NULL, path_buf_, 1024);
    if (written_ > 0)
    {
        res_ = PathRemoveFileSpecA(path_buf_);
        if (S_OK == res_ || S_FALSE == res_)
        {
            written_ = strlen(path_buf_);
            len_ += pc_.append(path_buf_, written_);
        }
    }

    written_ = GetEnvironmentVariableA("_NT_SYMBOL_PATH", path_buf_, PATH_BUF_LEN);
    len_ += pc_.append(path_buf_, written_);

    written_ = GetEnvironmentVariableA("_NT_ALTERNATE_SYMBOL_PATH", path_buf_, PATH_BUF_LEN);
    len_ += pc_.append(path_buf_, written_);

    written_ = GetEnvironmentVariableA("SYSTEMROOT", path_buf_, PATH_BUF_LEN);
    len_ += pc_.append(path_buf_, written_);
    strncat(path_buf_, "\\system32;", PATH_BUF_LEN - strlen(path_buf_));
    len_ += pc_.append(path_buf_, written_);

    SymInitialize(h_proc_, pc_.path(), FALSE); // can't do much with return value

    sym_options_ = SymGetOptions();
    sym_options_ |= SYMOPT_LOAD_LINES; // Loads line number information.
    sym_options_ |= SYMOPT_FAIL_CRITICAL_ERRORS; // Do not display system dialog boxes
    // when there is a media failure such as
    // no media in a drive. Instead,
    // the failure happens silently.
    sym_options_ |= SYMOPT_INCLUDE_32BIT_MODULES; // When debugging on 64-bit Windows,
    // include any 32-bit modules.
    sym_options_ |= SYMOPT_UNDNAME; // All symbols are presented in undecorated form.
    // This option has no effect on global or local symbols
    // because they are stored undecorated.
    // This option applies only to public symbols.
    sym_options_ = SymSetOptions(sym_options_);

    // load modules symbols
    mod_entry_.dwSize = sizeof(mod_entry_);
    h_snap_ = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dw_proc_id_);
    if (h_snap_ == INVALID_HANDLE_VALUE)
        return;

    Module32First(h_snap_, &mod_entry_);
    do
    {
        if (0 == SymLoadModule64(h_proc_, 0, mod_entry_.szExePath, mod_entry_.szModule,
                                 DWORD64(mod_entry_.modBaseAddr), mod_entry_.modBaseSize)
                && ERROR_SUCCESS != GetLastError())
            continue;
    }
    while (Module32Next(h_snap_, &mod_entry_));
    CloseHandle(h_snap_);
}

void stack_explorer::thread_stack(DWORD thread_id, stack_frame_t* frames, size_t num_frames,
                                  CONTEXT* cntx)
{
    memset(frames, '\0', num_frames * sizeof(stack_frame_t));

    h_thread_ = OpenThread(THREAD_SUSPEND_RESUME
                          | THREAD_GET_CONTEXT
                          | THREAD_QUERY_INFORMATION,
                            FALSE, thread_id);
    if (h_thread_ == NULL)
        return;

    if (dw_proc_id_ != GetCurrentProcessId() || thread_id != GetCurrentThreadId())
    {
        if (SuspendThread(h_thread_) == -1)
            return;
    }

    if (cntx == NULL)
    {
        memset(&cntx, 0, sizeof(cntx));
        if (dw_proc_id_ == GetCurrentProcessId() && thread_id == GetCurrentThreadId())
        {
            context_.ContextFlags = CONTEXT_FULL;
            RtlCaptureContext(&context_);
        }
        else
        {
            context_.ContextFlags = CONTEXT_FULL;
            if (!GetThreadContext(h_thread_, &context_)) // this function doesn't work for current thread
                return;
        }
    }
    else
        context_ = *cntx;

    memset(&stack_frame_, 0, sizeof(stack_frame_));
#ifdef _M_IX86
    // normally, call ImageNtHeader() and use machine info from PE header
    image_type_ = IMAGE_FILE_MACHINE_I386;
    stack_frame_.AddrPC.Offset    = context_.Eip;
    stack_frame_.AddrPC.Mode      = AddrModeFlat;
    stack_frame_.AddrFrame.Offset = context_.Ebp;
    stack_frame_.AddrFrame.Mode   = AddrModeFlat;
    stack_frame_.AddrStack.Offset = context_.Esp;
    stack_frame_.AddrStack.Mode   = AddrModeFlat;
#elif _M_X64
    image_type_ = IMAGE_FILE_MACHINE_AMD64;
    stack_frame_.AddrPC.Offset    = context_.Rip;
    stack_frame_.AddrPC.Mode      = AddrModeFlat;
    stack_frame_.AddrFrame.Offset = context_.Rsp;
    stack_frame_.AddrFrame.Mode   = AddrModeFlat;
    stack_frame_.AddrStack.Offset = context_.Rsp;
    stack_frame_.AddrStack.Mode   = AddrModeFlat;
#elif _M_IA64
    image_type_ = IMAGE_FILE_MACHINE_IA64;
    stack_frame_.AddrPC.Offset     = context_.StIIP;
    stack_frame_.AddrPC.Mode       = AddrModeFlat;
    stack_frame_.AddrFrame.Offset  = context_.IntSp;
    stack_frame_.AddrFrame.Mode    = AddrModeFlat;
    stack_frame_.AddrBStore.Offset = context_.RsBSP;
    stack_frame_.AddrBStore.Mode   = AddrModeFlat;
    stack_frame_.AddrStack.Offset  = context_.IntSp;
    stack_frame_.AddrStack.Mode    = AddrModeFlat;
#else
#   error "Platform not supported!"
#endif

    p_sym_ = (PIMAGEHLP_SYMBOL64)p_sym_buf_;
    memset(p_sym_, 0, sizeof(IMAGEHLP_SYMBOL64) + SYM_NAME_LEN * sizeof(CHAR));
    p_sym_->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
    p_sym_->MaxNameLength = SYM_NAME_LEN;

    for (static size_t frame_num = 0; frame_num < num_frames; ++frame_num)
    {
        // get next stack frame (StackWalk64(), SymFunctionTableAccess64(), SymGetModuleBase64())
        // if this returns ERROR_INVALID_ADDRESS (487) or ERROR_NOACCESS (998), you can
        // assume that either you are done, or that the stack is so hosed that the next
        // deeper frame could not be found.
        // CONTEXT need not to be supplied if image_type_ is IMAGE_FILE_MACHINE_I386!
        if (!StackWalk64(image_type_, h_proc_, h_thread_, &stack_frame_, &cntx, NULL,
                          &SymFunctionTableAccess64, &SymGetModuleBase64, NULL))
            break;

        if (stack_frame_.AddrPC.Offset != 0)
        {
            s_entry_ = &frames[frame_num];

            if (SymGetSymFromAddr64(h_proc_, stack_frame_.AddrPC.Offset, 0, p_sym_))
            {
                DWORD64 module_start_address = SymGetModuleBase64(h_proc_, stack_frame_.AddrPC.Offset);
                if (module_start_address != 0)
                    s_entry_->address = stack_frame_.AddrPC.Offset - module_start_address; // current instruction of the function
                else
                    s_entry_->address = 0;
//                s_entry_->address = p_sym_->Address; // starting instruction of the function
                if (UnDecorateSymbolName(p_sym_->Name, sym_name_, SYM_NAME_LEN, UNDNAME_COMPLETE)
                    || UnDecorateSymbolName(p_sym_->Name, sym_name_, SYM_NAME_LEN, UNDNAME_NAME_ONLY))
                {
                    strncpy(s_entry_->function, sym_name_, MAX_FUNCTION_LEN);
                }
                else
                {
                    strncpy(s_entry_->function, p_sym_->Name, MAX_FUNCTION_LEN);
                }
            }
            else
            {
                strncpy(s_entry_->function, "??", MAX_FUNCTION_LEN);
            }

            memset(&line_, 0, sizeof(line_));
            line_.SizeOfStruct = sizeof(line_);
            if (SymGetLineFromAddr64(h_proc_, stack_frame_.AddrPC.Offset, &displacement_, &line_) != FALSE)
            {
                s_entry_->line = line_.LineNumber;
                strncpy(s_entry_->function, line_.FileName, MAX_FILENAME_LEN);
            }
            else
            {
                s_entry_->line = 0;
                strncpy(s_entry_->function, "??", MAX_FILENAME_LEN);
            }
        }
    }

    if (thread_id != GetCurrentThreadId())
        ResumeThread(h_thread_);
    CloseHandle(h_thread_);
}

