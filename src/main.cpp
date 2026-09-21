#include "pe.hpp"
#include "opaque.hpp"

#include <cstdio>
#include <direct.h>
#include <tlhelp32.h>
#include <windows.h>

#pragma comment( lib, "psapi.lib" )
#pragma comment( lib, "shell32.lib" )

namespace
{

auto open_roblox( ) -> HANDLE
{
    HANDLE snap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
    if ( snap == INVALID_HANDLE_VALUE )
        return nullptr;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof( pe );
    HANDLE proc = nullptr;

    if ( Process32FirstW( snap, &pe ) )
    {
        do
        {
            if ( !_wcsicmp( pe.szExeFile, L"RobloxPlayerBeta.exe" ) )
            {
                proc = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID );
                break;
            }
        } while ( Process32NextW( snap, &pe ) );
    }

    CloseHandle( snap );
    return proc;
}

auto wait_roblox( ) -> HANDLE
{
    HANDLE proc = open_roblox( );
    if ( proc )
        return proc;

    std::printf( "[hyperion-dump] waiting for RobloxPlayerBeta.exe — open roblox\n" );
    for ( ;; )
    {
        Sleep( 1000 );
        proc = open_roblox( );
        if ( proc )
            return proc;
    }
}

}

int main( )
{
    HANDLE proc = wait_roblox( );
    std::printf( "[hyperion-dump] attached\n" );

    _mkdir( "dumps" );

    dump_image hyp{};
    if ( !dump_hyperion( proc, hyp ) )
    {
        std::printf( "[hyperion-dump] RobloxPlayerBeta.dll miss — still trying client\n" );
    }
    else
    {
        const uint32_t n = resolve_opaque( hyp );
        write_dump_bin( hyp, "dumps\\hyperion.bin" );
        write_dump_map( hyp, "dumps\\hyperion.map.txt", n, "HYPERION RobloxPlayerBeta.dll" );
        std::printf( "[hyperion-dump] hyperion.bin  base=0x%llx size=0x%zx code=%s predicates=%u\n",
            ( unsigned long long )hyp.base, hyp.size, hyp.code_name.c_str( ), n );
        for ( const auto& s : hyp.sections )
            std::printf( "  %-8s va=0x%08x v=0x%08x ok=%u cc=%u\n",
                s.name, s.va, s.vsize, s.pages_ok, s.pages_cc );
    }

    dump_image client{};
    if ( !dump_client( proc, hyp.base, client ) )
    {
        std::printf( "[hyperion-dump] mapped client miss\n" );
        CloseHandle( proc );
        if ( hyp.buf )
            launch_binary_ninja( "dumps\\hyperion.bin" );
        return hyp.buf ? 0 : 1;
    }

    write_dump_bin( client, "dumps\\roblox.bin" );
    write_dump_map( client, "dumps\\roblox.map.txt", 0, "ROBLOX CLIENT mapped PE" );
    std::printf( "[hyperion-dump] roblox.bin  base=0x%llx size=0x%zx code=%s\n",
        ( unsigned long long )client.base, client.size, client.code_name.c_str( ) );
    for ( const auto& s : client.sections )
        std::printf( "  %-8s va=0x%08x v=0x%08x ok=%u cc=%u\n",
            s.name, s.va, s.vsize, s.pages_ok, s.pages_cc );

    CloseHandle( proc );

    std::printf( "[hyperion-dump] loading roblox.bin in binary ninja\n" );
    if ( !launch_binary_ninja( "dumps\\roblox.bin" ) )
        std::printf( "[hyperion-dump] binary ninja launch failed — open dumps\\roblox.bin yourself\n" );

    return 0;
}
