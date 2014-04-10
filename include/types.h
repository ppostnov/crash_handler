#pragma once
#include <array>
#include "util.h"


namespace crash_handler
{
enum error_code
{
    err_access_violation,
    err_out_of_range,
    err_breakpoint,
    err_misalignment,
    err_denormal_operand,
    err_division_by_zero,
    err_inexact_result,
    err_invalid_operation,
    err_overflow,
    err_stack_check,
    err_underflow,
    err_illegal_instruction,
    err_page_error,
    err_int_division_by_zero,
    err_int_overflow,
    err_invalid_disposition,
    err_noncontinueable_exception,
    err_private_instruction,
    err_single_step,
    err_stack_overflow,
    err_unknown_exception_code,
    err_invalid_crt_parameter,
    err_terminate_unexpected_pure_virt_call,
    err_signal,

    err_num
};

typedef int32_t   proc_id_t;
typedef int32_t   thread_id_t;
typedef uint64_t  mem_addr_t;
typedef uint64_t  mem_size_t;


static uint16_t const  MAX_FILENAME_LEN = 1023;
static uint16_t const  MAX_FUNCTION_LEN = 1023;

struct stack_frame_t
{
    util::fixed_string<MAX_FILENAME_LEN>  file;
    util::fixed_string<MAX_FUNCTION_LEN>  function;

    uint16_t    line;
    mem_addr_t  address;

    stack_frame_t() : line(0), address(0) { }
};

static uint16_t const  STACK_SIZE  = 128;
static uint16_t const  THREADS_NUM = 128;
typedef std::array<stack_frame_t, STACK_SIZE>  thread_stack_t;

struct crash_info
{
    proc_id_t      pid;
    thread_id_t    crashed_tid;
    error_code     code;

    std::array<thread_stack_t, THREADS_NUM>  stack;

    crash_info(): pid(0), crashed_tid(0), code((error_code)-1) { }
};

typedef bool (*primary_handler_f)(crash_info const&);

char const* const ERROR_MESSAGES[] = {
    "Access violation",             // 0
    "Array bounds exceeded",
    "Breakpoint was encountered",
    "Datatype misalignment",
    "Float: Denormal operand",
    "Float: Divide by zero",        // 5
    "Float: Inexact result",
    "Float: Invalid operation",
    "Float: Overflow",
    "Float: Stack check",
    "Float: Underflow",             // 10
    "Illegal instruction",
    "Page error",
    "Integer: Divide by zero",
    "Integer: Overflow",
    "Invalid disposition",          // 15
    "Noncontinuable exception",
    "Private Instruction",
    "Single step",
    "Stack overflow",
    "Unknown exception code",       // 20
    "Invalid CRT parameter",
    "A call to terminate()/unexpected() or pure virtual call",
    "SIGABRT caught"
    };
} // namespace crash_handler
