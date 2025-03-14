#pragma once;
#include <asmjit/asmjit.h>
#include "trashgen.h"
#include <vector>

using namespace asmjit;

std::vector<unsigned char> generate_bootcode(uint64_t text_rva, uint64_t text_size, uint64_t entry_point) {

    JitRuntime rt;
    CodeHolder code;
    code.init(rt.environment());

    x86::Assembler a(&code);

    auto PEB = x86::ptr_abs(0x60);
    PEB.setSegment(x86::gs);

    // --- Get module base from the PEB ---
    a.mov(x86::rax, PEB);   // rax = pointer to PEB
    a.mov(x86::rax, x86::qword_ptr(x86::rax, 0x10));    // rax = ImageBaseAddress
    generate_trash(a);
    // --- Compute address of .text section ---
    a.mov(x86::rbx, x86::rax);                         // rbx = module base
    a.add(x86::rbx, imm(text_rva));                    // rbx = module base + text_rva
    // --- Load .text section size and decryption key ---
    a.mov(x86::rcx, imm(text_size));                   // rcx = text_size (counter)
    a.mov(x86::rdx, imm(0xAA));                        // rdx = key (0xAA), we'll use dl
    generate_trash(a);
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
    generate_trash(a);
    // --- Jump at original EP ---
    a.mov(x86::rax, PEB);   // rax = pointer to PEB
    a.mov(x86::rax, x86::qword_ptr(x86::rax, 0x10));
    a.add(x86::rax, entry_point);
    generate_trash(a);
    a.jmp(x86::rax);

    size_t codeSize = code.codeSize();
    std::vector<unsigned char> codeBuffer(codeSize);
    code.copyFlattenedData(codeBuffer.data(), codeSize);
    return codeBuffer;
}