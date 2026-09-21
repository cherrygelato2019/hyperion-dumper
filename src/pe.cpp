#include "pe.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <psapi.h>
#include <shellapi.h>
#include <winnt.h>

extern "C" long NtReadVirtualMemory_Sys( HANDLE, void*, void*, SIZE_T, SIZE_T* );

namespace
{

constexpr size_t k_page = 0x1000;

auto rpm( HANDLE proc, uintptr_t va, void* dst, size_t n ) -> bool
{
    SIZE_T got = 0;
    return NtReadVirtualMemory_Sys( proc, ( void* )va, dst, n, &got ) >= 0 && got == n;
}

auto find_dll( HANDLE proc, uintptr_t* base, size_t* size ) -> bool
{
    HMODULE mods[1024]{};
    DWORD needed = 0;
    if ( !EnumProcessModulesEx( proc, mods, sizeof( mods ), &needed, LIST_MODULES_ALL ) )
        return false;

    const DWORD count = needed / sizeof( HMODULE );
    for ( DWORD i = 0; i < count; ++i )
    {
        char path[MAX_PATH]{};
        if ( !GetModuleFileNameExA( proc, mods[i], path, MAX_PATH ) )
            continue;
        if ( !std::strstr( path, "RobloxPlayerBeta.dll" ) )
            continue;

        MODULEINFO mi{};
        if ( !GetModuleInformation( proc, mods[i], &mi, sizeof( mi ) ) )
            return false;
        *base = ( uintptr_t )mi.lpBaseOfDll;
        *size = mi.SizeOfImage;
        return true;
    }
    return false;
}

}

auto dump_from_base( HANDLE proc, uintptr_t base, size_t size_hint, bool skip_runtime, dump_image& out ) -> bool
{
    out = {};
    out.base = base;

    uint8_t hdr[k_page]{};
    if ( !rpm( proc, base, hdr, k_page ) )
        return false;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>( hdr );
    if ( dos->e_magic != IMAGE_DOS_SIGNATURE )
        return false;
    if ( ( size_t )dos->e_lfanew + sizeof( IMAGE_NT_HEADERS64 ) > k_page )
        return false;

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>( hdr + dos->e_lfanew );
    if ( nt->Signature != IMAGE_NT_SIGNATURE )
        return false;

    out.size = nt->OptionalHeader.SizeOfImage;
    if ( !out.size || out.size > 0x40000000 )
        out.size = size_hint;
    if ( !out.size )
        return false;

    out.buf = std::shared_ptr<uint8_t[]>( new uint8_t[out.size]{} );

    auto* sec = IMAGE_FIRST_SECTION( nt );
    for ( WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec )
    {
        sec->PointerToRawData = sec->VirtualAddress;
        sec->SizeOfRawData = sec->Misc.VirtualSize;

        section_info s{};
        std::memcpy( s.name, sec->Name, 8 );
        s.va = sec->VirtualAddress;
        s.vsize = sec->Misc.VirtualSize;
        s.raw = sec->SizeOfRawData;
        s.chars = sec->Characteristics;
        if ( !s.vsize )
        {
            out.sections.push_back( s );
            continue;
        }

        const uintptr_t start = out.base + sec->VirtualAddress;
        const size_t off = sec->VirtualAddress;
        const char* name = s.name;

        const bool skip = skip_runtime && ( std::strstr( name, ".data" ) || std::strstr( name, ".reloc" ) || std::strstr( name, ".rsrc" ) );
        if ( skip )
        {
            std::memset( out.buf.get( ) + off, 0xCC, ( std::min )( ( size_t )s.vsize, out.size - off ) );
            s.pages_cc = ( s.vsize + ( uint32_t )k_page - 1 ) / ( uint32_t )k_page;
            out.sections.push_back( s );
            continue;
        }

        if ( !std::strcmp( name, ".byfron" ) || ( out.code_name.empty( ) && ( sec->Characteristics & IMAGE_SCN_MEM_EXECUTE ) ) )
        {
            out.code_off = ( uint32_t )off;
            out.code_size = s.vsize;
            out.code_name = name;
        }

        for ( uint32_t cur = 0; cur < s.vsize; )
        {
            const uint32_t chunk = ( std::min )( ( uint32_t )k_page, s.vsize - cur );
            if ( off + cur + chunk > out.size )
                break;
            if ( rpm( proc, start + cur, out.buf.get( ) + off + cur, chunk ) )
                ++s.pages_ok;
            else
            {
                std::memset( out.buf.get( ) + off + cur, 0xCC, chunk );
                ++s.pages_cc;
            }
            cur += chunk;
        }
        out.sections.push_back( s );
    }

    std::memcpy( out.buf.get( ), hdr, k_page );
    return !out.sections.empty( );
}

auto dump_hyperion( HANDLE proc, dump_image& out ) -> bool
{
    uintptr_t base = 0;
    size_t size = 0;
    if ( !find_dll( proc, &base, &size ) )
        return false;
    return dump_from_base( proc, base, size, true, out );
}

auto dump_client( HANDLE proc, uintptr_t hyperion_base, dump_image& out ) -> bool
{
    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = 0;
    uintptr_t best = 0;
    uint32_t best_size = 0;

    while ( addr < 0x7FFFFFFEFFFF )
    {
        if ( VirtualQueryEx( proc, ( LPCVOID )addr, &mbi, sizeof( mbi ) ) != sizeof( mbi ) )
            break;
        const size_t region = mbi.RegionSize ? mbi.RegionSize : k_page;
        const uintptr_t va = ( uintptr_t )mbi.BaseAddress;
        if ( mbi.State == MEM_COMMIT && va != hyperion_base )
        {
            uint8_t mz[2]{};
            if ( rpm( proc, va, mz, 2 ) && mz[0] == 'M' && mz[1] == 'Z' )
            {
                IMAGE_DOS_HEADER dos{};
                IMAGE_NT_HEADERS64 nt{};
                if ( rpm( proc, va, &dos, sizeof( dos ) ) && dos.e_magic == IMAGE_DOS_SIGNATURE
                    && rpm( proc, va + dos.e_lfanew, &nt, sizeof( nt ) )
                    && nt.Signature == IMAGE_NT_SIGNATURE
                    && nt.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC )
                {
                    const uint32_t sz = nt.OptionalHeader.SizeOfImage;
                    if ( sz >= 40u * 1024u * 1024u && sz > best_size )
                    {
                        best = va;
                        best_size = sz;
                    }
                }
            }
        }
        const uintptr_t next = va + region;
        if ( next <= addr )
            break;
        addr = next;
    }

    if ( !best )
        return false;
    return dump_from_base( proc, best, best_size, false, out );
}

auto write_dump_bin( const dump_image& img, const char* path ) -> bool
{
    if ( !img.buf || !img.size )
        return false;
    std::ofstream f( path, std::ios::binary | std::ios::trunc );
    if ( !f )
        return false;
    f.write( reinterpret_cast<const char*>( img.buf.get( ) ), ( std::streamsize )img.size );
    return ( bool )f;
}

auto write_dump_map( const dump_image& img, const char* path, uint32_t predicates, const char* title ) -> bool
{
    std::ofstream f( path, std::ios::trunc );
    if ( !f )
        return false;

    f << ( title ? title : "DUMP" ) << "\n";
    f << "module     memory image\n";
    f << "base       0x" << std::hex << img.base << std::dec << "\n";
    f << "size       0x" << std::hex << img.size << std::dec << "\n";
    f << "code       " << img.code_name << "  off=0x" << std::hex << img.code_off
      << "  size=0x" << img.code_size << std::dec << "\n";
    f << "predicates " << predicates << "\n\n";
    f << "SECTIONS\n";
    for ( const auto& s : img.sections )
    {
        f << "  " << s.name
          << "  va=0x" << std::hex << s.va
          << "  vsize=0x" << s.vsize
          << "  ch=0x" << s.chars
          << std::dec
          << "  ok=" << s.pages_ok
          << "  cc=" << s.pages_cc
          << "\n";
    }
    f << "\nPointerToRawData = VA so Binary Ninja maps it as a memory dump.\n";
    f << "unread pages filled 0xCC. Mouse.Hit lives in the client image (roblox.bin).\n";
    return true;
}

auto launch_binary_ninja( const char* file ) -> bool
{
    if ( !file || !file[0] )
        return false;

    char bn[MAX_PATH]{};
    char home[MAX_PATH]{};
    if ( GetEnvironmentVariableA( "LOCALAPPDATA", home, MAX_PATH ) )
        std::snprintf( bn, sizeof( bn ), "%s\\Programs\\Vector35\\BinaryNinja\\binaryninja.exe", home );
    if ( !bn[0] || GetFileAttributesA( bn ) == INVALID_FILE_ATTRIBUTES )
        std::snprintf( bn, sizeof( bn ), "%s", "binaryninja.exe" );

    char abs[MAX_PATH]{};
    if ( !GetFullPathNameA( file, MAX_PATH, abs, nullptr ) )
        return false;

    const HINSTANCE r = ShellExecuteA( nullptr, "open", bn, abs, nullptr, SW_SHOWNORMAL );
    return ( INT_PTR )r > 32;
}
