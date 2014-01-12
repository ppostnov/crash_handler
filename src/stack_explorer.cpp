#include <Windows.h>
#include <DbgHelp.h>
#include <Shlwapi.h>
#include <TlHelp32.h>
#pragma comment(lib, "DbgHelp.lib")
#pragma comment(lib, "Shlwapi.lib")

#include "stack_explorer.h"
#include "util.h"


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
    buf_    = sym_path_;
    buflen_ = SYM_PATH_LEN;

    memset(buf_, '\0', buflen_);

    buflen_ -= 1; // for zero ending
    len_ = 0;
    len_ += append_path(buf_, buflen_, ".", 1);

    written_ = GetCurrentDirectoryA(PATH_BUF_LEN, path_buf_);
    len_ += append_path(buf_ + len_, buflen_ - len_, path_buf_, PATH_BUF_LEN);

    written_ += GetModuleFileNameA(NULL, path_buf_, 1024);
    if (written_ > 0)
    {
        res_ = PathRemoveFileSpecA(path_buf_);
        if (S_OK == res_ || S_FALSE == res_)
        {
            written_ = strlen(path_buf_);
            len_ += append_path(buf_ + len_, buflen_ - len_, path_buf_, written_);
        }
    }

    written_ = GetEnvironmentVariableA("_NT_SYMBOL_PATH", path_buf_, PATH_BUF_LEN);
    len_ += append_path(buf_ + len_, buflen_ - len_, path_buf_, written_);

    GetEnvironmentVariableA("_NT_ALTERNATE_SYMBOL_PATH", path_buf_, PATH_BUF_LEN);
    len_ += append_path(buf_ + len_, buflen_ - len_, path_buf_, written_);

    GetEnvironmentVariableA("SYSTEMROOT", path_buf_, PATH_BUF_LEN);
    len_ += append_path(buf_ + len_, buflen_ - len_, path_buf_, written_);
    strncat(path_buf_, "\\system32;", PATH_BUF_LEN - strlen(path_buf_));
    len_ += append_path(buf_ + len_, buflen_ - len_, path_buf_, written_);

    SymInitialize(h_proc_, sym_path_, FALSE); // can't do much with return value

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

    static HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME
                                     | THREAD_GET_CONTEXT
                                     | THREAD_QUERY_INFORMATION,
                                       FALSE, thread_id);
    if (hThread == NULL)
        return;

    if (dw_proc_id_ != GetCurrentProcessId() || thread_id != GetCurrentThreadId())
    {
        if (SuspendThread(hThread) == -1)
            return;
    }

    static CONTEXT context;
    if (cntx == NULL)
    {
        memset(&cntx, 0, sizeof(cntx));
        if (dw_proc_id_ == GetCurrentProcessId() && thread_id == GetCurrentThreadId())
        {
            context.ContextFlags = CONTEXT_FULL;
            RtlCaptureContext(&context);
        }
        else
        {
            context.ContextFlags = CONTEXT_FULL;
            if (!GetThreadContext(hThread, &context)) // this function doesn't work for current thread
                return;
        }
    }
    else
        context = *cntx;

    static STACKFRAME64 stack_frame;
    memset(&stack_frame, 0, sizeof(stack_frame));
    static DWORD imageType;
#ifdef _M_IX86
    // normally, call ImageNtHeader() and use machine info from PE header
    imageType = IMAGE_FILE_MACHINE_I386;
    stack_frame.AddrPC.Offset    = context.Eip;
    stack_frame.AddrPC.Mode      = AddrModeFlat;
    stack_frame.AddrFrame.Offset = context.Ebp;
    stack_frame.AddrFrame.Mode   = AddrModeFlat;
    stack_frame.AddrStack.Offset = context.Esp;
    stack_frame.AddrStack.Mode   = AddrModeFlat;
#elif _M_X64
    imageType = IMAGE_FILE_MACHINE_AMD64;
    stack_frame.AddrPC.Offset    = context.Rip;
    stack_frame.AddrPC.Mode      = AddrModeFlat;
    stack_frame.AddrFrame.Offset = context.Rsp;
    stack_frame.AddrFrame.Mode   = AddrModeFlat;
    stack_frame.AddrStack.Offset = context.Rsp;
    stack_frame.AddrStack.Mode   = AddrModeFlat;
#elif _M_IA64
    imageType = IMAGE_FILE_MACHINE_IA64;
    stack_frame.AddrPC.Offset     = context.StIIP;
    stack_frame.AddrPC.Mode       = AddrModeFlat;
    stack_frame.AddrFrame.Offset  = context.IntSp;
    stack_frame.AddrFrame.Mode    = AddrModeFlat;
    stack_frame.AddrBStore.Offset = context.RsBSP;
    stack_frame.AddrBStore.Mode   = AddrModeFlat;
    stack_frame.AddrStack.Offset  = context.IntSp;
    stack_frame.AddrStack.Mode    = AddrModeFlat;
#else
#   error "Platform not supported!"
#endif

    static char pSymBuf[sizeof(IMAGEHLP_SYMBOL64) + SYM_NAME_LEN * sizeof(CHAR)];
    static PIMAGEHLP_SYMBOL64 pSym = (PIMAGEHLP_SYMBOL64)pSymBuf;
    memset(pSym, 0, sizeof(IMAGEHLP_SYMBOL64) + SYM_NAME_LEN * sizeof(CHAR));
    pSym->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
    pSym->MaxNameLength = SYM_NAME_LEN;

    for (size_t frameNum = 0; frameNum < num_frames; ++frameNum)
    {
        // get next stack frame (StackWalk64(), SymFunctionTableAccess64(), SymGetModuleBase64())
        // if this returns ERROR_INVALID_ADDRESS (487) or ERROR_NOACCESS (998), you can
        // assume that either you are done, or that the stack is so hosed that the next
        // deeper frame could not be found.
        // CONTEXT need not to be supplied if imageType is IMAGE_FILE_MACHINE_I386!
        if (!StackWalk64(imageType, h_proc_, hThread, &stack_frame, &cntx, NULL,
                          &SymFunctionTableAccess64, &SymGetModuleBase64, NULL))
            break;

        if (stack_frame.AddrPC.Offset != 0)
        {
            stack_frame_t& s_entry = frames[frameNum];

            if (SymGetSymFromAddr64(h_proc_, stack_frame.AddrPC.Offset, 0, pSym))
            {
                DWORD64 module_start_address = SymGetModuleBase64(h_proc_, stack_frame.AddrPC.Offset);
                if (module_start_address != 0)
                    s_entry.address = stack_frame.AddrPC.Offset - module_start_address; // current instruction of the function
                else
                    s_entry.address = 0;
//                s_entry.address = pSym->Address; // starting instruction of the function
                static char sym_name_[SYM_NAME_LEN];
                if (UnDecorateSymbolName(pSym->Name, sym_name_, SYM_NAME_LEN, UNDNAME_COMPLETE)
                    || UnDecorateSymbolName(pSym->Name, sym_name_, SYM_NAME_LEN, UNDNAME_NAME_ONLY))
                {
                    strncpy(s_entry.function, sym_name_, MAX_FUNCTION_LEN);
                }
                else
                {
                    strncpy(s_entry.function, pSym->Name, MAX_FUNCTION_LEN);
                }
            }
            else
            {
                strncpy(s_entry.function, "??", MAX_FUNCTION_LEN);
            }

            static IMAGEHLP_LINE64 line;
            memset(&line, 0, sizeof(line));
            line.SizeOfStruct = sizeof(line);
            static DWORD displacement;
            if (SymGetLineFromAddr64(h_proc_, stack_frame.AddrPC.Offset, &displacement, &line) != FALSE)
            {
                s_entry.line = line.LineNumber;
                strncpy(s_entry.function, line.FileName, MAX_FILENAME_LEN);
            }
            else
            {
                s_entry.line = 0;
                strncpy(s_entry.function, "??", MAX_FILENAME_LEN);
            }
        }
    }

    if (thread_id != GetCurrentThreadId())
        ResumeThread(hThread);
    CloseHandle(hThread);
}

