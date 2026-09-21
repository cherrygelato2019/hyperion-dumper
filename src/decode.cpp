#include "decode.hpp"

namespace
{

auto read_i8( const uint8_t*& p, const uint8_t* e, int64_t& v ) -> bool
{
    if ( p + 1 > e )
        return false;
    v = ( int8_t )*p++;
    return true;
}

auto read_i32( const uint8_t*& p, const uint8_t* e, int64_t& v ) -> bool
{
    if ( p + 4 > e )
        return false;
    v = ( int32_t )( uint32_t )( p[0] | ( p[1] << 8 ) | ( p[2] << 16 ) | ( p[3] << 24 ) );
    p += 4;
    return true;
}

auto read_u32( const uint8_t*& p, const uint8_t* e, uint64_t& v ) -> bool
{
    if ( p + 4 > e )
        return false;
    v = ( uint32_t )( p[0] | ( p[1] << 8 ) | ( p[2] << 16 ) | ( p[3] << 24 ) );
    p += 4;
    return true;
}

auto read_u64( const uint8_t*& p, const uint8_t* e, uint64_t& v ) -> bool
{
    if ( p + 8 > e )
        return false;
    v = 0;
    for ( int i = 0; i < 8; ++i )
        v |= ( uint64_t )p[i] << ( 8 * i );
    p += 8;
    return true;
}

auto parse_modrm( const uint8_t*& p, const uint8_t* e, uint8_t rex, bool addr64, operand& rm, uint8_t& reg ) -> bool
{
    if ( p >= e )
        return false;

    const uint8_t modrm = *p++;
    const uint8_t mod = modrm >> 6;
    const uint8_t r = ( modrm >> 3 ) & 7;
    const uint8_t m = modrm & 7;
    reg = ( uint8_t )( r | ( ( rex & 4 ) ? 8 : 0 ) );

    if ( mod == 3 )
    {
        rm.kind = opk::reg;
        rm.reg = ( uint8_t )( m | ( ( rex & 1 ) ? 8 : 0 ) );
        rm.bits = ( rex & 8 ) ? 64 : 32;
        return true;
    }

    rm.kind = opk::mem;
    rm.rip = false;
    rm.disp = 0;
    rm.base = 0xFF;

    int disp_bytes = 0;
    if ( m == 4 )
    {
        if ( p >= e )
            return false;
        const uint8_t sib = *p++;
        const uint8_t base = sib & 7;
        rm.base = ( uint8_t )( base | ( ( rex & 1 ) ? 8 : 0 ) );
        if ( mod == 0 && base == 5 )
        {
            disp_bytes = 4;
            rm.base = 0xFF;
        }
        else if ( mod == 1 )
            disp_bytes = 1;
        else if ( mod == 2 )
            disp_bytes = 4;
    }
    else if ( mod == 0 && m == 5 && addr64 )
    {
        rm.rip = true;
        disp_bytes = 4;
    }
    else
    {
        rm.base = ( uint8_t )( m | ( ( rex & 1 ) ? 8 : 0 ) );
        if ( mod == 1 )
            disp_bytes = 1;
        else if ( mod == 2 )
            disp_bytes = 4;
    }

    if ( disp_bytes == 1 )
        return read_i8( p, e, rm.disp );
    if ( disp_bytes == 4 )
        return read_i32( p, e, rm.disp );
    return true;
}

auto jcc_from( uint8_t cc ) -> mnem
{
    switch ( cc )
    {
    case 0x2: return mnem::jb;
    case 0x3: return mnem::jnb;
    case 0x4: return mnem::jz;
    case 0x5: return mnem::jnz;
    case 0x6: return mnem::jbe;
    case 0x7: return mnem::jnbe;
    case 0x8: return mnem::js;
    default:  return mnem::unk;
    }
}

}

auto decode_one( const uint8_t* p, size_t n, insn& out ) -> bool
{
    out = {};
    if ( !p || n == 0 )
        return false;

    const uint8_t* s = p;
    const uint8_t* e = p + n;

    uint8_t rex = 0;
    while ( p < e )
    {
        const uint8_t b = *p;
        if ( b == 0x66 || b == 0x67 || b == 0xF2 || b == 0xF3 || b == 0x2E || b == 0x3E || b == 0x26 || b == 0x36 || b == 0x64 || b == 0x65 )
        {
            ++p;
            continue;
        }
        if ( ( b & 0xF0 ) == 0x40 )
        {
            rex = b;
            ++p;
            continue;
        }
        break;
    }

    if ( p >= e )
        return false;

    const bool w = ( rex & 8 ) != 0;
    uint8_t op = *p++;
    uint8_t extra = 0;
    bool two = false;
    if ( op == 0x0F )
    {
        if ( p >= e )
            return false;
        extra = *p++;
        two = true;
    }

    auto finish = [&]( ) -> bool
    {
        out.len = ( uint8_t )( p - s );
        return out.len != 0 && out.len <= n;
    };

    if ( !two && op >= 0x70 && op <= 0x7F )
    {
        out.id = jcc_from( ( uint8_t )( op & 0x0F ) );
        if ( out.id == mnem::unk )
            return false;
        int64_t rel = 0;
        if ( !read_i8( p, e, rel ) )
            return false;
        out.ops[0].kind = opk::imm;
        out.ops[0].imm = ( uint64_t )rel;
        out.ops[0].bits = 8;
        return finish( );
    }

    if ( two && extra >= 0x80 && extra <= 0x8F )
    {
        out.id = jcc_from( ( uint8_t )( extra & 0x0F ) );
        if ( out.id == mnem::unk )
            return false;
        int64_t rel = 0;
        if ( !read_i32( p, e, rel ) )
            return false;
        out.ops[0].kind = opk::imm;
        out.ops[0].imm = ( uint64_t )( int64_t )rel;
        out.ops[0].bits = 32;
        return finish( );
    }

    if ( !two && op >= 0xB8 && op <= 0xBF )
    {
        out.id = mnem::mov;
        out.ops[0].kind = opk::reg;
        out.ops[0].reg = ( uint8_t )( ( op - 0xB8 ) | ( ( rex & 1 ) ? 8 : 0 ) );
        out.ops[0].bits = w ? 64 : 32;
        uint64_t imm = 0;
        if ( w )
        {
            if ( !read_u64( p, e, imm ) )
                return false;
            out.ops[1].bits = 64;
        }
        else
        {
            if ( !read_u32( p, e, imm ) )
                return false;
            out.ops[1].bits = 32;
        }
        out.ops[1].kind = opk::imm;
        out.ops[1].imm = imm;
        return finish( );
    }

    uint8_t reg = 0;
    operand rm{};

    if ( !two && ( op == 0x89 || op == 0x8B || op == 0x8D || op == 0x3B || op == 0x39 || op == 0x85 ) )
    {
        if ( !parse_modrm( p, e, rex, true, rm, reg ) )
            return false;

        operand r{};
        r.kind = opk::reg;
        r.reg = reg;
        r.bits = w ? 64 : 32;

        if ( op == 0x8D )
        {
            out.id = mnem::lea;
            out.ops[0] = r;
            out.ops[1] = rm;
        }
        else if ( op == 0x8B || op == 0x3B )
        {
            out.id = ( op == 0x8B ) ? mnem::mov : mnem::cmp;
            out.ops[0] = r;
            out.ops[1] = rm;
        }
        else
        {
            out.id = ( op == 0x85 ) ? mnem::test : ( op == 0x39 ) ? mnem::cmp : mnem::mov;
            out.ops[0] = rm;
            out.ops[1] = r;
        }
        return finish( );
    }

    if ( !two && ( op == 0xC7 || op == 0x81 || op == 0x83 || op == 0xF7 ) )
    {
        if ( p >= e )
            return false;
        const uint8_t modrm = *p;
        const uint8_t grp = ( modrm >> 3 ) & 7;
        if ( !parse_modrm( p, e, rex, true, rm, reg ) )
            return false;

        if ( op == 0xC7 && grp == 0 )
        {
            out.id = mnem::mov;
            out.ops[0] = rm;
            uint64_t imm = 0;
            if ( !read_u32( p, e, imm ) )
                return false;
            out.ops[1].kind = opk::imm;
            out.ops[1].imm = imm;
            out.ops[1].bits = 32;
            return finish( );
        }

        if ( ( op == 0x81 || op == 0x83 ) && grp == 7 )
        {
            out.id = mnem::cmp;
            out.ops[0] = rm;
            int64_t v = 0;
            if ( op == 0x83 )
            {
                if ( !read_i8( p, e, v ) )
                    return false;
                out.ops[1].bits = 8;
            }
            else
            {
                if ( !read_i32( p, e, v ) )
                    return false;
                out.ops[1].bits = 32;
            }
            out.ops[1].kind = opk::imm;
            out.ops[1].imm = ( uint64_t )v;
            return finish( );
        }

        if ( op == 0xF7 && grp == 0 )
        {
            out.id = mnem::test;
            out.ops[0] = rm;
            uint64_t imm = 0;
            if ( !read_u32( p, e, imm ) )
                return false;
            out.ops[1].kind = opk::imm;
            out.ops[1].imm = imm;
            out.ops[1].bits = 32;
            return finish( );
        }
    }

    return false;
}
