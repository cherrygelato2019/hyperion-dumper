#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <windows.h>

struct section_info
{
    char name[16]{};
    uint32_t va{};
    uint32_t vsize{};
    uint32_t raw{};
    uint32_t chars{};
    uint32_t pages_ok{};
    uint32_t pages_cc{};
};

struct dump_image
{
    uintptr_t base{};
    size_t size{};
    std::shared_ptr<uint8_t[]> buf;
    uint32_t code_off{};
    size_t code_size{};
    std::string code_name;
    std::vector<section_info> sections;
};

auto dump_hyperion( HANDLE proc, dump_image& out ) -> bool;
auto dump_client( HANDLE proc, uintptr_t hyperion_base, dump_image& out ) -> bool;
auto write_dump_bin( const dump_image& img, const char* path ) -> bool;
auto write_dump_map( const dump_image& img, const char* path, uint32_t predicates, const char* title ) -> bool;
auto launch_binary_ninja( const char* file ) -> bool;
