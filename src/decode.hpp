#pragma once

#include <cstdint>
#include <cstddef>

enum class mnem : uint8_t
{
    unk,
    mov,
    lea,
    cmp,
    test,
    jz,
    jnz,
    jnbe,
    jnb,
    jb,
    jbe,
    js,
};

enum class opk : uint8_t { none, reg, mem, imm };

struct operand
{
    opk kind{ opk::none };
    uint8_t reg{};
    uint8_t base{};
    bool rip{};
    int64_t disp{};
    uint64_t imm{};
    uint8_t bits{};
};

struct insn
{
    mnem id{ mnem::unk };
    uint8_t len{};
    operand ops[2]{};
};

auto decode_one( const uint8_t* p, size_t n, insn& out ) -> bool;

inline auto is_jcc( mnem id ) -> bool
{
    return id == mnem::jz || id == mnem::jnz || id == mnem::jnbe
        || id == mnem::jnb || id == mnem::jb || id == mnem::jbe || id == mnem::js;
}
