#pragma once
#include <asmjit/asmjit.h>

using namespace asmjit;
inline void generate_trash(x86::Assembler &a) {
	Label inf_loop = a.newLabel();
	Label end = a.newLabel();

	a.bind(inf_loop);
	a.cmp(x86::rax, 0);
	a.jnz(end);
	a.int3();
	a.mov(x86::qword_ptr(x86::rax), x86::rax);
	a.call(0x1000);
	a.syscall();
	a.vmcall();
	a.jmp(inf_loop);

	a.bind(end);
}