#pragma once
#include <stdint.h>
#include "export.h"

// Handling application crashes.
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

struct context_t
{
    error_code   code;
    thread_id_t  crashed_tid;
    proc_id_t    pid;
};

static uint16_t const  MAX_FILENAME_LEN = 1023;
static uint16_t const  MAX_FUNCTION_LEN = 1023;

struct stack_frame_t
{
    char        file[MAX_FILENAME_LEN + 1];
    uint16_t    line;
    char        function[MAX_FUNCTION_LEN + 1];
    mem_addr_t  address;
};

// used to provide users callbacks in crash handling process
struct callbacks
{
typedef bool (*primary_handler_f     )(context_t const*);
typedef bool (*stack_handler_f       )(stack_frame_t const*, uint16_t);
typedef bool (*pretty_stack_handler_f)(stack_frame_t const*, uint16_t);

primary_handler_f       primary_cb;         // called on any crash
stack_handler_f         stack_cb;           // called when stack is ready
pretty_stack_handler_f  pretty_stack_cb;    // called when stack has pretty names
};


struct CRASH_HANDLER_API handler
{
    handler(callbacks const* cbs = nullptr);
    ~handler();
};


} // namespace crash_handler
