#include "opaque.hpp"
#include "decode.hpp"
#include "pe.hpp"

#include <cstdio>

namespace
{

constexpr uint8_t k_rsp = 4;
constexpr uint8_t k_rbp = 5;

struct state
{
    int step{};
    insn mov_stk{};
    insn lea{};
    insn mov_reg{};
    insn cmp{};
    insn jcc{};
    int64_t stk_off{};
    uint64_t stk_val{};
    uint64_t cmp_val{};
    uint8_t first_reg{ 0xFF };
    uint8_t second_reg{ 0xFF };
    size_t jcc_off{};
    uint32_t hits{};
};

auto is_stk_base( uint8_t b ) -> bool
{
    return b == k_rsp || b == k_rbp;
}

auto mov_imm_to_stack( const insn& i ) -> bool
{
    return i.id == mnem::mov
        && i.ops[0].kind == opk::mem
        && is_stk_base( i.ops[0].base )
        && !i.ops[0].rip
        && i.ops[0].disp != 0
        && i.ops[1].kind == opk::imm;
}

auto lea_rip( const insn& i ) -> bool
{
    return i.id == mnem::lea
        && i.ops[0].kind == opk::reg
        && i.ops[1].kind == opk::mem
        && i.ops[1].rip
        && i.ops[1].disp != 0;
}

auto mov_stack_to_reg( const insn& i, const state& s ) -> bool
{
    return i.id == mnem::mov
        && i.ops[0].kind == opk::reg
        && i.ops[1].kind == opk::mem
        && is_stk_base( i.ops[1].base )
        && i.ops[1].disp == s.stk_off;
}

auto test_stack_imm( const insn& i, const state& s ) -> bool
{
    return i.id == mnem::test
        && i.ops[0].kind == opk::mem
        && i.ops[0].base == s.mov_stk.ops[0].base
        && i.ops[0].disp != 0
        && i.ops[1].kind == opk::imm;
}

auto cmp_stack_imm( const insn& i, const state& s ) -> bool
{
    return i.id == mnem::cmp
        && i.ops[0].kind == opk::mem
        && i.ops[0].base == s.mov_stk.ops[0].base
        && i.ops[0].disp == s.stk_off
        && i.ops[1].kind == opk::imm;
}

auto mov_imm_reg( const insn& i ) -> bool
{
    return i.id == mnem::mov
        && i.ops[0].kind == opk::reg
        && i.ops[1].kind == opk::imm;
}

auto cmp_reg_imm( const insn& i, const state& s ) -> bool
{
    return i.id == mnem::cmp
        && i.ops[0].kind == opk::reg
        && i.ops[0].reg == s.first_reg
        && i.ops[1].kind == opk::imm;
}

auto cmp_two_regs( const insn& i, const state& s ) -> bool
{
    return i.id == mnem::cmp
        && i.ops[0].kind == opk::reg
        && i.ops[1].kind == opk::reg
        && i.ops[0].reg == s.first_reg
        && i.ops[1].reg == s.second_reg;
}

auto will_jump( const state& s ) -> bool
{
    const uint64_t a = s.stk_val;
    const uint64_t b = s.cmp_val;
    switch ( s.jcc.id )
    {
    case mnem::jz:
        if ( s.cmp.id == mnem::test )
            return ( a & b ) == 0;
        return a == b;
    case mnem::jnz:
        if ( s.cmp.id == mnem::test )
            return ( a & b ) != 0;
        return a != b;
    case mnem::jnbe: return a > b;
    case mnem::jnb:  return a >= b;
    case mnem::jb:   return a < b;
    case mnem::jbe:  return a <= b;
    case mnem::js:   return ( int64_t )a < 0;
    default:        return false;
    }
}

auto patch_jcc( dump_image& img, state& s ) -> void
{
    uint8_t* buf = img.buf.get( ) + s.jcc_off;
    const uint8_t orig = s.jcc.len;
    if ( !orig || s.jcc_off + orig > img.size )
        return;

    if ( !will_jump( s ) )
    {
        for ( uint8_t i = 0; i < orig; ++i )
            buf[i] = 0x90;
        ++s.hits;
        return;
    }

    const int64_t rel = ( int64_t )s.jcc.ops[0].imm;
    for ( uint8_t i = 0; i < orig; ++i )
        buf[i] = 0x90;

    if ( s.jcc.ops[0].bits == 8 )
    {
        buf[0] = 0xEB;
        buf[1] = ( uint8_t )rel;
    }
    else
    {
        const int32_t adj = ( int32_t )( rel + ( orig - 5 ) );
        buf[0] = 0xE9;
        buf[1] = ( uint8_t )( adj );
        buf[2] = ( uint8_t )( adj >> 8 );
        buf[3] = ( uint8_t )( adj >> 16 );
        buf[4] = ( uint8_t )( adj >> 24 );
    }
    ++s.hits;
}

}

auto resolve_opaque( dump_image& img ) -> uint32_t
{
    if ( !img.buf || !img.code_size )
        return 0;

    uint8_t* code = img.buf.get( ) + img.code_off;
    state s{};
    size_t off = 0;

    while ( off < img.code_size )
    {
        insn i{};
        if ( !decode_one( code + off, img.code_size - off, i ) )
        {
            ++off;
            s.step = 0;
            continue;
        }

        bool hit = false;

        if ( s.step == 0 )
        {
            if ( mov_imm_to_stack( i ) )
            {
                s = {};
                s.mov_stk = i;
                s.stk_off = i.ops[0].disp;
                s.stk_val = i.ops[1].imm;
                s.step = 1;
                hit = true;
            }
            else if ( lea_rip( i ) )
            {
                s = {};
                s.lea = i;
                s.first_reg = i.ops[0].reg;
                s.stk_val = img.base + img.code_off + off + i.len + i.ops[1].disp;
                s.step = 1;
                hit = true;
            }
        }
        else if ( s.step == 1 )
        {
            if ( mov_stack_to_reg( i, s ) )
            {
                s.mov_reg = i;
                s.first_reg = i.ops[0].reg;
                s.step = 2;
                hit = true;
            }
            else if ( test_stack_imm( i, s ) || cmp_stack_imm( i, s ) )
            {
                s.cmp = i;
                s.cmp_val = i.ops[1].imm;
                s.step = 3;
                hit = true;
            }
            else if ( mov_imm_reg( i ) )
            {
                s.cmp_val = i.ops[1].imm;
                s.second_reg = i.ops[0].reg;
                s.step = 2;
                hit = true;
            }
        }
        else if ( s.step == 2 )
        {
            if ( cmp_reg_imm( i, s ) )
            {
                s.cmp = i;
                s.cmp_val = i.ops[1].imm;
                s.step = 3;
                hit = true;
            }
            else if ( cmp_two_regs( i, s ) )
            {
                s.cmp = i;
                s.step = 3;
                hit = true;
            }
        }
        else if ( s.step == 3 )
        {
            if ( is_jcc( i.id ) )
            {
                s.jcc = i;
                s.jcc_off = img.code_off + off;
                patch_jcc( img, s );
                s.step = 0;
                hit = true;
            }
        }

        if ( !hit )
        {
            s.step = 0;
            if ( mov_imm_to_stack( i ) )
            {
                s.mov_stk = i;
                s.stk_off = i.ops[0].disp;
                s.stk_val = i.ops[1].imm;
                s.step = 1;
            }
            else if ( lea_rip( i ) )
            {
                s.lea = i;
                s.first_reg = i.ops[0].reg;
                s.stk_val = img.base + img.code_off + off + i.len + i.ops[1].disp;
                s.step = 1;
            }
        }

        off += i.len ? i.len : 1;
    }

    return s.hits;
}
