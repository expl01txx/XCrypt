// XCrypt.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <LIEF/LIEF.hpp>
#include <asmjit/asmjit.h>
#pragma comment(lib, "LIEF.lib")
#pragma comment(lib, "asmjit.lib")
#pragma comment(lib, "spdlog.lib")

using namespace asmjit;

static std::string randomStrGen(int length) {
    static std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    std::string result;
    result.resize(length);

    for (int i = 0; i < length; i++)
        result[i] = charset[rand() % charset.length()];

    return result;
}

int main(int argc, char** argv) {
    srand(time(0));
    std::cout << "[xcrypt]: Starting..." << std::endl;
    // PE
    auto pe = LIEF::PE::Parser::parse("MyCrackme.exe");

    //const uint64_t originalEntryRVA = pe->entrypoint();
    auto imageBase = pe->optional_header().imagebase();
    auto entryPoint = pe->entrypoint() - imageBase;

    std::cout << "[xcrypt]: Entry point at: 0x" << std::hex << entryPoint << std::endl;

    auto sections = pe->sections();

    for (auto& section : sections) {
        section.name(randomStrGen(8));
    }

    LIEF::PE::Section& text_section = sections[0];
    uint64_t text_rva = text_section.virtual_address();
    uint64_t text_size = text_section.virtual_size();
    std::cout << "[xcrypt]: .text section RVA: 0x" << std::hex << text_rva
        << ", Size: 0x" << text_size << std::endl;

    text_section.add_characteristic(LIEF::PE::Section::CHARACTERISTICS::MEM_WRITE);

    std::cout << "[xcrypt]: Encrypting .text section using XOR key 0xAA..." << std::endl;
    std::vector<uint8_t> textContent = std::vector<uint8_t>(text_section.content().begin(), text_section.content().end());
    for (auto& byte : textContent) {
        byte ^= 0xAA;
    }
    // Update the section content with the encrypted bytes
    text_section.content(textContent);

   
    std::cout << "[xcrypt]: Generating shellcode..."  << std::endl;

    //Shellcode generator
    JitRuntime rt;
    CodeHolder code;
    code.init(rt.environment());

    x86::Assembler a(&code);

    std::cout << "[xcrypt]: Generating shellcode..." << std::endl;
    auto PEB = x86::ptr_abs(0x60);
    PEB.setSegment(x86::gs);

    // --- Get module base from the PEB ---
    a.mov(x86::rax, PEB);   // rax = pointer to PEB
    a.mov(x86::rax, x86::qword_ptr(x86::rax, 0x10));    // rax = ImageBaseAddress

    // --- Compute address of .text section ---
    a.mov(x86::rbx, x86::rax);                         // rbx = module base
    a.add(x86::rbx, imm(text_rva));                    // rbx = module base + text_rva

    // --- Load .text section size and decryption key ---
    a.mov(x86::rcx, imm(text_size));                   // rcx = text_size (counter)
    a.mov(x86::rdx, imm(0xAA));                        // rdx = key (0xAA), we'll use dl

    // --- Decryption loop ---
    Label decrypt_loop = a.newLabel();
    a.bind(decrypt_loop);
    a.cmp(x86::rcx, 0);                              // if counter == 0, exit loop
    Label decrypt_done = a.newLabel();
    a.je(decrypt_done);
    a.xor_(x86::byte_ptr(x86::rbx), x86::dl);         // XOR byte at [rbx] with key (dl)
    a.inc(x86::rbx);                                 // move to next byte
    a.dec(x86::rcx);                                 // decrement counter
    a.jmp(decrypt_loop);
    a.bind(decrypt_done);

    // --- Jump at original EP ---
    a.mov(x86::rax, PEB);   // rax = pointer to PEB
    a.mov(x86::rax, x86::qword_ptr(x86::rax, 0x10));  
    a.add(x86::rax, entryPoint);
    a.jmp(x86::rax);                              

    size_t codeSize = code.codeSize();
    std::vector<unsigned char> codeBuffer(codeSize);
    code.copyFlattenedData(codeBuffer.data(), codeSize);

    std::cout << "[xcrypt]: Shell code size: 0x" << std::hex << codeSize << std::endl;
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
    pe->optional_header().addressof_entrypoint(0x21000);//newSection.virtual_address());
    pe->optional_header().major_linker_version(0);
    pe->optional_header().minor_linker_version(0);

    std::cout << "[xcrypt]: Saving..." << std::endl;

    pe->write("out.exe");

   
    return 0;
}