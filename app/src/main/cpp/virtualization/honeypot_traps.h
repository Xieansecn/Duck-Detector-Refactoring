#pragma once

#include <string>
#include <vector>

namespace duckdetector::virtualization {

    struct TrapAttempt {
        bool suspicious = false;
        std::string detail;
    };

    struct TrapResult {
        bool available = false;
        bool supported = false;
        int completedAttempts = 0;
        int suspiciousAttempts = 0;
        std::string detail;
        std::vector<TrapAttempt> attempts;
    };

    TrapResult run_timing_trap();

    TrapResult run_syscall_parity_trap();

    TrapResult run_asm_counter_trap();

    TrapResult run_asm_raw_syscall_trap();

    std::string encode_trap(const TrapResult &result);

    std::string run_sacrificial_syscall_pack();

}  // namespace duckdetector::virtualization
