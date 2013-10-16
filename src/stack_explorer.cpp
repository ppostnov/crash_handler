#pragma comment(lib, "DbgHelp.lib")
#pragma comment(lib, "Shlwapi.lib")

#include "stack_explorer.h"


stack_explorer::stack_explorer(DWORD dw_process_id = GetCurrentProcessId(), char const* sympath = 0)
    : dwProcId_   (dw_process_id)
    , SYM_PATH_LEN(2048)
{
    hProc_ = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcId_);
    sym_init();

    // load_modules();
}

stack_explorer::~stack_explorer()
{
    SymCleanup(hProc_);
    if (hProc_)
        CloseHandle(hProc_);
}

void stack_explorer::sym_init()
{
    char*  buf    = sym_path_;
    size_t buflen = SYM_PATH_LEN;

    memset(buf, '\0', buflen);

    buflen -= 1; // for zero ending
    size_t len = 0;
    len += append_path(buf, buflen, ".", 1);

    static size_t const path_buf_len = 1024;
    static char path_buf[path_buf_len];

    size_t written = GetCurrentDirectoryA(path_buf, path_buf_len);
    len += append_path(buf + len, buflen - len, path_buf, path_buf_len);

    written += GetModuleFileNameA(NULL, path_buf, 1024);
    if (written > 0)
    {
        HRESULT res = PathCchRemoveFileSpec(path_buf);
        if (S_OK == res || S_FALSE == res)
        {
            written = strlen(path_buf);
            len += append_path(buf + len, buflen - len, path_buf, written);
        }
    }

    written = GetEnvironmentVariableA("_NT_SYMBOL_PATH", path_buf, path_buf_len);
    len += append_path(buf + len, buflen - len, path_buf, written);

    GetEnvironmentVariableA("_NT_ALTERNATE_SYMBOL_PATH", path_buf, path_buf_len);
    len += append_path(buf + len, buflen - len, path_buf, written);

    GetEnvironmentVariableA("SYSTEMROOT", path_buf, path_buf_len);
    len += append_path(buf + len, buflen - len, path_buf, written);
    strcat_s(path_buf, "\\system32;", path_buf_len - strlen(path_buf));
    len += append_path(buf + len, buflen - len, path_buf, written);

    SymInitialize(hProc, sympath_, FALSE); // can't do much with return value

    DWORD symOptions = SymGetOptions();
    symOptions |= SYMOPT_LOAD_LINES; // Loads line number information.
    symOptions |= SYMOPT_FAIL_CRITICAL_ERRORS; // Do not display system dialog boxes
    // when there is a media failure such as
    // no media in a drive. Instead,
    // the failure happens silently.
    symOptions |= SYMOPT_INCLUDE_32BIT_MODULES; // When debugging on 64-bit Windows,
    // include any 32-bit modules.
    symOptions |= SYMOPT_UNDNAME; // All symbols are presented in undecorated form.
    // This option has no effect on global or local symbols
    // because they are stored undecorated.
    // This option applies only to public symbols.
    symOptions = SymSetOptions(symOptions);

    // load modules symbols
    static MODULEENTRY32 mod_entry;
    mod_entry.dwSize = sizeof(mod_entry);
    static HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcId_);
    if (hSnap == INVALID_HANDLE_VALUE)
        return;

    Module32First(hSnap, &mod_entry);
    do
    {
        if (0 == SymLoadModule64(hProc_, 0, mod_entry.szExePath, mod_entry.szModule,
                                 mod_entry.modBaseAddr, mod_entry.modBaseSize)
                && ERROR_SUCCESS != GetLastError())
            continue;
    }
    while (Module32Next(hSnap, &mod_entry));
    CloseHandle(hSnap);
}

void stack_explorer::thread_stack(DWORD thread_id, thread_stack_t* frames, size_t num_frames,
                                  CONTEXT* cntx = NULL)
{
    memset(frames, '\0', num_frames * sizeof(thread_stack_t));

    static HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME
                                     | THREAD_GET_CONTEXT
                                     | THREAD_QUERY_INFORMATION,
                                       FALSE, thread_id);
    if (hThread == NULL)
        return;

    if (dwProcId_ != GetCurrentProcessId() || thread_id != GetCurrentThreadId())
    {
        if (SuspendThread(hThread) == -1)
            return;
    }

    static CONTEXT context;
    if (cntx == NULL)
    {
        memset(&cntx, 0, sizeof(cntx));
        if (dwProcId_ == GetCurrentProcessId() && thread_id == GetCurrentThreadId())
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

    static char pSymBuf[sizeof(IMAGEHLP_SYMBOL64) + SYMBOLS_NAMELEN_MAX * sizeof(CHAR)];
    static PIMAGEHLP_SYMBOL64 pSym = (PIMAGEHLP_SYMBOL64)pSymBuf;
    memset(pSym, 0, sizeof(IMAGEHLP_SYMBOL64) + SYMBOLS_NAMELEN_MAX * sizeof(CHAR));
    pSym->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
    pSym->MaxNameLength = SYMBOLS_NAMELEN_MAX;

    for (size_t frameNum = 0; frameNum < num_frames; ++frameNum)
    {
        // get next stack frame (StackWalk64(), SymFunctionTableAccess64(), SymGetModuleBase64())
        // if this returns ERROR_INVALID_ADDRESS (487) or ERROR_NOACCESS (998), you can
        // assume that either you are done, or that the stack is so hosed that the next
        // deeper frame could not be found.
        // CONTEXT need not to be supplied if imageType is IMAGE_FILE_MACHINE_I386!
        if (!StackWalk64(imageType, hProc_, hThread, &stack_frame, &cntx, NULL,
                          &SymFunctionTableAccess64, &SymGetModuleBase64, NULL))
            break;

        if (stack_frame.AddrPC.Offset != 0)
        {
            stack_entry& s_entry = frames[frameNum];

            if (SymGetSymFromAddr64(hProc_, stack_frame.AddrPC.Offset, 0, pSym))
            {
                DWORD64 module_start_address = SymGetModuleBase64(hProc_, stack_frame.AddrPC.Offset);
                if (module_start_address != 0)
                    s_entry.address = stack_frame.AddrPC.Offset - module_start_address; // current instruction of the function
                else
                    s_entry.address = 0;
//                s_entry.address = pSym->Address; // starting instruction of the function
                static char undName[SYMBOLS_NAMELEN_MAX];
                if (UnDecorateSymbolName(pSym->Name, undName, SYMBOLS_NAMELEN_MAX, UNDNAME_COMPLETE)
                    || UnDecorateSymbolName(pSym->Name, undName, SYMBOLS_NAMELEN_MAX, UNDNAME_NAME_ONLY))
                {
                    s_entry.function.assign(undName);
                }
                else
                {
                    s_entry.function.assign(pSym->Name);
                }
            }
            else
            {
                s_entry.function.assign("??");
            }

            static IMAGEHLP_LINE64 line;
            memset(&line, 0, sizeof(line));
            line.SizeOfStruct = sizeof(line);
            static DWORD displacement;
            if (SymGetLineFromAddr64(hProc_, stack_frame.AddrPC.Offset, &displacement, &line) != FALSE)
            {
                s_entry.line = line.LineNumber;
                s_entry.file.assign(line.FileName);
            }
            else
            {
                s_entry.line = 0;
                s_entry.file.assign("??");
            }
        }
    }

    if (thread_id != GetCurrentThreadId())
        ResumeThread(hThread);
    CloseHandle(hThread);
}

