// XCrypt.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <LIEF/LIEF.hpp>
#include <asmjit/asmjit.h>
#include <capstone/capstone.h>
#include "codegen.h"
#pragma comment(lib, "LIEF.lib")
#pragma comment(lib, "asmjit.lib")
#pragma comment(lib, "capstone.lib")
using namespace asmjit;

static std::string randomStrGen(int length) {
    static std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    std::string result;
    result.resize(length);

    for (int i = 0; i < length; i++)
        result[i] = charset[rand() % charset.length()];

    return result;
}
/*
void analizeProgram(const std::vector<uint8_t>& codeBuffer) {
    csh handle;
    cs_insn* insn = nullptr;
    size_t count = 0;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        std::cerr << "[xcrypt] Failed to initialize Capstone!" << std::endl;
        return;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    count = cs_disasm(handle, codeBuffer.data(), codeBuffer.size(), 0, 0, &insn);
    if (count == 0) {
        std::cerr << "[Error] Disassembly failed!" << std::endl;
        cs_close(&handle);
        return;
    }

    for (size_t i = 0; i < count; i++) {
        cs_detail* detail = insn[i].detail;
        switch (insn[i].id) { 
        case X86_INS_CALL: {
            auto x = insn[i].mnemonic;
            std::cout << x << " " << insn[i].op_str << std::endl;
        }
        default:
            break;
        }
    }

    cs_close(&handle);
}*/

int main(int argc, char** argv) {
    srand(time(0));
    std::cout << "[xcrypt]: Starting..." << std::endl;
    // PE
    auto pe = LIEF::PE::Parser::parse("MyCrackme.exe");

    // Get imports


    //const uint64_t originalEntryRVA = pe->entrypoint();
    auto imageBase = pe->optional_header().imagebase();
    auto entryPoint = pe->entrypoint() - imageBase;

    std::cout << "[xcrypt]: Entry point at: 0x" << std::hex << entryPoint << std::endl;

    auto sections = pe->sections();

    for (auto& section : sections) {
        section.name(randomStrGen(8));
    }

    LIEF::PE::Section& textSection = sections[0];
    uint64_t textRva = textSection.virtual_address();
    uint64_t textSize = textSection.virtual_size();
    std::cout << "[xcrypt]: .text section RVA: 0x" << std::hex << textRva
        << ", Size: 0x" << textSize << std::endl;

    textSection.add_characteristic(LIEF::PE::Section::CHARACTERISTICS::MEM_WRITE);

    std::vector<uint8_t> textContent = std::vector<uint8_t>(textSection.content().begin(), textSection.content().end());
    std::cout << "[xcrypt]: Analizing .text section..." << std::endl;
    //analizeProgram(textContent);
    std::cout << "[xcrypt]: Encrypting .text section using XOR key 0xAA..." << std::endl;
    for (auto& byte : textContent) {
        byte ^= 0xAA;
    }
    // Update the section content with the encrypted bytes
    textSection.content(textContent);

   
    std::cout << "[xcrypt]: Generating shellcode..."  << std::endl;

    auto codeBuffer = generate_bootcode(textRva, textSize, entryPoint);

    std::cout << "[xcrypt]: Shell code size: 0x" << std::hex << codeBuffer.size() << std::endl;
    std::cout << "[xcrypt]: Adding .boot section..." << std::endl;

    //Create new section
    LIEF::PE::Section newSection(randomStrGen(8));
    newSection.add_characteristic(LIEF::PE::Section::CHARACTERISTICS::MEM_READ);
    newSection.add_characteristic(LIEF::PE::Section::CHARACTERISTICS::MEM_WRITE);
    newSection.add_characteristic(LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE);

    //Copy generated code to new section
    newSection.content(codeBuffer);

    pe->add_section(newSection);
    std::cout << "[xcrypt]: Patching entry point..." << std::endl;
    pe->optional_header().addressof_entrypoint(0xa000);//newSection.virtual_address());
    pe->optional_header().major_linker_version(0);
    pe->optional_header().minor_linker_version(0);

    std::cout << "[xcrypt]: Saving..." << std::endl;

    pe->write("out.exe");

   
    return 0;
}