---
title: "crackmes.one - hell86"
date: 2019-01-13
tags: [reversing]
categories: [crackme]
---

This is a beautiful challenge by ttlhacker from [crackmes.one](https://crackmes.one).  

<!--more-->
#### Description

> x86_64 linux binary (tested on debian 9 and ubuntu 18.04, should run on any distro). Takes one command line argument and outputs "OK!" if it's correct, "Wrong" if it's not.  
> Partially written in C, actual verification routine is assembly.  
> Don't patch the binary, of course - find the correct input.  

Let's get started :-)

```x86asm
    ╭ (fcn) main 110
    │   int main (int argc, char **argv, char **envp);
    │           ; arg int argc @ rdi
    │           ; arg char **argv @ rsi
    │           ; DATA XREF from entry0 (0x107d)
    │           0x00000fc0      55             push rbp
    │           0x00000fc1      53             push rbx
    │           0x00000fc2      4889f5         mov rbp, rsi                ; argv
    │           0x00000fc5      89fb           mov ebx, edi                ; argc
    │           0x00000fc7      4883ec08       sub rsp, 8
    │           0x00000fcb      e8f6090000     call make_alt_stack
    │           0x00000fd0      84c0           test al, al
    │           0x00000fd2      ba01000000     mov edx, 1
    │       ╭─< 0x00000fd7      744f           je 0x1028
    │       │   0x00000fd9      e887090000     call register_sigill
    │       │   0x00000fde      84c0           test al, al
    │       │   0x00000fe0      ba02000000     mov edx, 2
    │      ╭──< 0x00000fe5      7441           je 0x1028
    │      ││   0x00000fe7      4863fb         movsxd rdi, ebx
    │      ││   0x00000fea      4889ee         mov rsi, rbp
    │      ││   0x00000fed      e89e010000     call verify_flag
    │      ││   0x00000ff2      4883f801       cmp rax, 1
    │      ││   0x00000ff6      488d3dda1000.  lea rdi, str.Wrong          ; 0x20d7 ; "Wrong"
    │     ╭───< 0x00000ffd      7422           je 0x1021
    │     │││   0x00000fff      4883f802       cmp rax, 2
    │     │││   0x00001003      488d3dd31000.  lea rdi, str.hell86_crackme__    ; 0x20dd
    │    ╭────< 0x0000100a      7415           je 0x1021
    │    ││││   0x0000100c      4885c0         test rax, rax
    │    ││││   0x0000100f      488d3dbd1000.  lea rdi, [0x000020d3]       ; "OK!"
    │    ││││   0x00001016      488d05021100.  lea rax, str.You_have__a_bug ; 0x211f ; "You have encountered a bug"
    │    ││││   0x0000101d      480f45f8       cmovne rdi, rax
    │    ││││   ; CODE XREFS from main (0xffd, 0x100a)
    │    ╰╰───> 0x00001021      e80affffff     call sym.imp.puts           ; int puts(const char *s)
    │      ││   0x00001026      31d2           xor edx, edx
    │      ││   ; CODE XREFS from main (0xfd7, 0xfe5)
    │      ╰╰─> 0x00001028      89d0           mov eax, edx
    │           0x0000102a      5a             pop rdx
    │           0x0000102b      5b             pop rbx
    │           0x0000102c      5d             pop rbp
    ╰           0x0000102d      c3             ret
```

**make_alt_stack** allocates 8192 bytes from the heap which will be used as a stack for the signal handler which has been registered with **SA_ONSTACK** (**sigaltstack** syscall)  

```x86asm
    [0x00000fc0]> pdf @register_sigill
    ╭ (fcn) register_sigill 97
    │   register_sigill ();
    │           ; var int local_8h @ rsp+0x8
    │           ; var int local_10h @ rsp+0x10
    │           ; var int local_90h @ rsp+0x90
    │           ; CALL XREF from main (0xfd9)
    │           0x00001965      53             push rbx
    │           0x00001966      31c0           xor eax, eax
    │           0x00001968      b926000000     mov ecx, 0x26
    │           0x0000196d      4881eca00000.  sub rsp, 0xa0
    │           0x00001974      488d7c2408     lea rdi, [local_8h]
    │           0x00001979      f3ab           rep stosd dword [rdi], eax
    │           0x0000197b      488d05c4ffff.  lea rax, [0x00001946]    ; SIGILL handler
    │           0x00001982      488d7c2410     lea rdi, [local_10h]
    │           0x00001987      c78424900000.  mov dword [local_90h], 0x8000004 ; SA_ONSTACK | SA_SIGINFO
    │           0x00001992      4889442408     mov qword [local_8h], rax
    │           0x00001997      e8c4f5ffff     call sym.imp.sigfillset
    │           0x0000199c      31d2           xor edx, edx
    │           0x0000199e      85c0           test eax, eax
    │       ╭─< 0x000019a0      7519           jne 0x19bb
    │       │   0x000019a2      488d5c2408     lea rbx, [local_8h]
    │       │   0x000019a7      31d2           xor edx, edx
    │       │   0x000019a9      bf04000000     mov edi, SIGILL
    │       │   0x000019ae      4889de         mov rsi, rbx
    │       │   0x000019b1      e8daf5ffff     call sym.imp.sigaction
    │       │   0x000019b6      85c0           test eax, eax
    │       │   0x000019b8      0f94c2         sete dl
    │       │   ; CODE XREF from register_sigill (0x19a0)
    │       ╰─> 0x000019bb      4881c4a00000.  add rsp, 0xa0
    │           0x000019c2      88d0           mov al, dl
    │           0x000019c4      5b             pop rbx
    ╰           0x000019c5      c3             ret
```

**register_sigill** registers a SIGILL handler using the flags **SA_ONSTACK** and **SA_SIGINFO**. So when the handler gets called, the alternate stack is used. And the handler has the following signature

```c
void handler(int sig, siginfo_t *info, void *ucontext);
```

Let's try to disassemble **verify_flag**

```x86asm
    [0x00000fc0]> pd 10 @ verify_flag
    ╭ (fcn) verify_flag 115
    │   verify_flag ();
    │           ; CALL XREF from main (0xfed)
    │           0x00001190      0f0b           ud2
    │           0x00001192      0200           add al, byte [rax]
    │           0x00001194      0000           add byte [rax], al
    │           0x00001196      0000           add byte [rax], al
    │           0x00001198      0000           add byte [rax], al
    │           0x0000119a      090d00000f0b   or dword [0x0b0f11a0], ecx
    │           0x000011a0      0200           add al, byte [rax]
    │           0x000011a2      0000           add byte [rax], al
    │           0x000011a4      0000           add byte [rax], al
    │           0x000011a6      0000           add byte [rax], al
```

> Woah! That's garbage ! How does the flag gets verified ??  

Well, the first instruction is **ud2**. This generates an Invalid Opcode Exception, ie., it triggers **SIGILL**.  
Let's dive into the sigill_handler routine.

```x86asm
    [0x00000fc0]> pd 6 @0x1946
                ; DATA XREF from register_sigill (0x197b)
                0x00001946      488b82a80000.  mov rax, qword [rdx + 0xa8] ; gp_regs.rip
                0x0000194d      488d7228       lea rsi, [rdx + 0x28]       ; & ucontext->gp_regs
                0x00001951      488d7802       lea rdi, [rax + 2]
                0x00001955      4883c00e       add rax, 0xe
                0x00001959      488982a80000.  mov qword [rdx + 0xa8], rax
            ╭─< 0x00001960      e97b050000     jmp 0x1ee0
    [0x00000fc0]> pd 3 @0x1ee0
                ; CODE XREF from verify_flag (+0x7d0)
                0x00001ee0      0fb65708       movzx edx, byte [rdi + 8]
                0x00001ee4      488d05951120.  lea rax, [0x00203080]
                0x00001eeb      ff24d0         jmp qword [rax + rdx*8]
    [0x00000fc0]> px/4xg @0x203080
    0x00203080  0x0000000000001a1f  0x0000000000001a20
    0x00203090  0x0000000000001a39  0x0000000000001a52
```

The handler increments the instruction pointer by 14 bytes and jumps to the instruction specified by the index **[rdi+8]**. The array at 0x203080 contains addresses of routines for emulating instructions.  
For example the routine at 0x1a20 has

```x86asm
    [0x00000fc0]> pd 7 @0x1a20
                0x00001a20      0fb64f0a       movzx ecx, byte [rdi + 0xa]
                0x00001a24      0fb6470b       movzx eax, byte [rdi + 0xb]
                0x00001a28      0fb65709       movzx edx, byte [rdi + 9]
                0x00001a2c      488b04c6       mov rax, qword [rsi + rax*8]
                0x00001a30      480304ce       add rax, qword [rsi + rcx*8]
                0x00001a34      488904d6       mov qword [rsi + rdx*8], rax
                0x00001a38      c3             ret
```

**rsi** stores the base address of the array of GPRs in the **ucontext**. So, this routine adds registers (indexed by **rdi**).  
Recall that **rip** is incremented by 14 bytes. Those 14 bytes are used to store the information for each instruction. Each of the 14 byte block starts with a **ud2**.  
So we have,

```c
    struct insn_t
    {
        int16_t ud2_op;         // marks the beginning of instruction. rip points here
        char __unknown[8];      // rdi points here. rdi = rip+2
        uint8_t instr;          // instruction index
        uint8_t dest;           // destination register
        uint8_t src_regs[2];    // source registers
    };
```

We need to figure out the '\_\_unknown' member and the order of the source registers.  
Let's move to the next routine at **0x1a39**

```x86asm
    [0x00000fc0]> pd 7 @0x1a39
                0x00001a39      0fb6470a       movzx eax, byte [rdi + 0xa]  ; src1
                0x00001a3d      0fb64f0b       movzx ecx, byte [rdi + 0xb]  ; src2
                0x00001a41      0fb65709       movzx edx, byte [rdi + 9]    ; dst
                0x00001a45      488b04c6       mov rax, qword [rsi + rax*8]
                0x00001a49      482b04ce       sub rax, qword [rsi + rcx*8]
                0x00001a4d      488904d6       mov qword [rsi + rdx*8], rax ; dst = src1-src2
                0x00001a51      c3             ret
```

Great! Now we get the order of the source registers. Let's rewrite the instruction struct

```c
    struct insn_t
    {
        int16_t ud2_op;     // marks the beginning of instruction. rip points here
        char __unknown[8];  // rdi points here. rdi = rip+2
        uint8_t instr;      // instruction index
        uint8_t dest;       // destination register
        uint8_t src1;       // source register 1
        uint8_t src2;       // source register 2
    };
```

Let's move to the function at **0x1ada**

```x86asm
    [0x00000fc0]> pd 7 @0x1ada
                0x00001ada      0fb64709       movzx eax, byte [rdi + 9]    ; dst
                0x00001ade      488b17         mov rdx, qword [rdi]         ; __unknown
                0x00001ae1      488914c6       mov qword [rsi + rax*8], rdx
                0x00001ae5      c3             ret
```

Cool ! this copies **\_\_unknown** to the dest register. So, this is emulates move immediate.  
Great ! now we have figured out the \_\_unknown

```c
    struct insn_t
    {
        int16_t ud2_op;     // marks the beginning of instruction. rip points here
        int64_t imm;        // immediate value
        uint8_t instr;      // instruction index
        uint8_t dest;       // destination register
        uint8_t src1;       // source register 1
        uint8_t src2;       // source register 2
    };
```

I've renamed the functions at **0x203080**

```x86asm
    .data:0000000000203080 off_203080      dq offset nullsub_2
    .data:0000000000203088                 dq offset add
    .data:0000000000203090                 dq offset sub
    .data:0000000000203098                 dq offset mul
    .data:00000000002030A0                 dq offset quot
    .data:00000000002030A8                 dq offset rem
    .data:00000000002030B0                 dq offset sar
    .data:00000000002030B8                 dq offset shl
    .data:00000000002030C0                 dq offset neg
    .data:00000000002030C8                 dq offset mov_imm
    .data:00000000002030D0                 dq offset movzx_byte_reg_imm
    .data:00000000002030D8                 dq offset movsx_byte_reg_imm
    .data:00000000002030E0                 dq offset movzx_word_reg_imm
    .data:00000000002030E8                 dq offset movsx_word_reg_imm
    .data:00000000002030F0                 dq offset mov_dword_reg_imm
    .data:00000000002030F8                 dq offset movsx_dword_reg_imm
    .data:0000000000203100                 dq offset mov_reg_qmem
    .data:0000000000203108                 dq offset mov_mem_byte
    .data:0000000000203110                 dq offset mov_mem_word
    .data:0000000000203118                 dq offset mov_mem_dword
    .data:0000000000203120                 dq offset mov_mem_qword
    .data:0000000000203128                 dq offset push_reg
    .data:0000000000203130                 dq offset push_imm
    .data:0000000000203138                 dq offset pop_reg
    .data:0000000000203140                 dq offset mov_reg_reg
    .data:0000000000203148                 dq offset or
    .data:0000000000203150                 dq offset and
    .data:0000000000203158                 dq offset xor
    .data:0000000000203160                 dq offset not
    .data:0000000000203168                 dq offset cmp_lt
    .data:0000000000203170                 dq offset cmp_le
    .data:0000000000203178                 dq offset cmp_gt
    .data:0000000000203180                 dq offset cmp_ge
    .data:0000000000203188                 dq offset cmp_eq
    .data:0000000000203190                 dq offset cmp_neq
    .data:0000000000203198                 dq offset cmp_eq_imm
    .data:00000000002031A0                 dq offset cmp_neq_imm
    .data:00000000002031A8                 dq offset cmp_reg_zero
    .data:00000000002031B0                 dq offset jmp_imm_if_zero
    .data:00000000002031B8                 dq offset jmp_imm_if_notzero
    .data:00000000002031C0                 dq offset call_imm
    .data:00000000002031C8                 dq offset ret
    .data:00000000002031D0                 dq offset ret_if_reg_not_zero
    .data:00000000002031D8                 dq offset ret_if_reg_zero
    .data:00000000002031E0                 dq offset lea_reg_imm
    .data:00000000002031E8                 dq offset sar_imm
    .data:00000000002031F0                 dq offset shl_imm
    .data:00000000002031F8                 dq offset or_imm
    .data:0000000000203200                 dq offset and_imm
    .data:0000000000203208                 dd offset xor_imm
```

So, the verify_flag routine is an array of **insn_t**. The flag is verified by emulating the instructions through a **SIGILL**. Now we need to write a disassembler for **verify_flag**

Here's the disassembly of `verify_flag`. I've defined some new instructions like

|Instruction|Syntax|Description
|:-----------:|:-------------------:|:--------------------------|
|ret.z|`ret.z reg`|returns if _reg_ is zero|
|ret.nz|`ret.nz reg`|returns if _reg_ is non zero|
|if.z|`if.z reg, jmp offset`|if _reg_ is zero, goto _offset_|
|if.nz|`if.nz reg, jmp offset`|if _reg_ is not zero, goto _offset_|
|cmp.cc|`cmp.cc Rd, Rs, Rt`|compare registers _Rs_ and _Rt_ and set the result of condition _cc_ into _Rd_|
|div.quot|`div.quot Rd, Rs, Rt`|Rd = ⌊Rs/Rt⌋|
|div.rem|`div.rem Rd, Rs, Rt`|Rd = Rs mod Rt|
  

```x86asm
    00000000          mov rax, 0x2
    00000001          cmp.neq r8, rdi, 0x2      ; argc must be 2
    00000002          ret.nz r8
    00000003          lea rsi, [rsi + 0x8]
    00000004          mov rdi, qword [rsi + 0]  ; argv[1]
    00000005          jmp 0x6

    00000006          push rbp
    00000007          mov rbp, rsp
    00000008          lea rsp, [rsp + 0xfffffff0]
    00000009          mov qword [rbp + 0xfffffff0], rdi
    0000000a          call 0x73                 ; find length
    0000000b          cmp.neq rax, rax, 0x24    ; len(argv[1]) == 0x24
    0000000c          if.nz rax, jmp 0x29
    0000000d          mov rdi, 0x20cd           ; "abdfgehikmanoqrstucvwlxyz-01h23p456u78j9-_.+"
    0000000e          call 0x73
    0000000f          mov qword [rbp + 0xfffffff8], rax
    00000010          mov rdi, qword [rbp + 0xfffffff0]
    00000011          mov rsi, 0x20cd           ; "FLAG{"
    00000012          mov rdx, rax
    00000013          call 0x79                 ; compare strings
    00000014          if.nz rax, jmp 0x29
    00000015          mov rdi, qword [rbp + 0xfffffff0]
    00000016          movzx rsi, byte [rdi + 0x23]
    00000017          cmp.neq rsi, rsi, 0x7d    ; input[0x23] == '}'
    00000018          if.nz rsi, jmp 0x29
    00000019          mov rsi, qword [rbp + 0xfffffff8]
    0000001a          add rdi, rdi, rsi         ; rdi += len("FLAG{")
    0000001b          neg rsi, rsi
    0000001c          lea rsi, [rsi + 0x23]     ; rsi = 0x23-5 = 0x1e
    0000001d          push rsi
    0000001e          call 0x2d                 ; compute indices
    0000001f          pop rsi
    00000020          if.z rax, jmp 0x29
    00000021          mov rdi, rax
    00000022          push rdi                  ; array of indices
    00000023          call 0x51                 ; validate the flag
    00000024          pop rdi
    00000025          push rax
    00000026          call [free]
    00000027          pop rax
    00000028          jmp 0x2a                  ; good jump
    00000029          mov rax, 0x1              ; bad jump
    0000002a          mov rsp, rbp
    0000002b          pop rbp
    0000002c          ret

    0000002d          mov rax, 0
    0000002e          ret.z rsi
    0000002f          push rdi                  ; string
    00000030          push rsi                  ; len
    00000031          shl rdi, rsi, 0x3
    00000032          call [malloc]             ; allocate len*8 bytes
    00000033          pop rsi
    00000034          pop rdi
    00000035          ret.z rax                 ; return 0 if malloc failed
    00000036          mov r8, rax
    00000037          mov r9, rax
    00000038          push r9
    00000039          push r8
    0000003a          push rdi
    0000003b          push rsi
    0000003c          movzx rsi, byte [rdi + 0] ; char
    0000003d          mov rdi, 0x20a0           ; "abdfgehikmanoqrstucvwlxyz-01h23p456u78j9-_.+"
    0000003e          call 0x84                 ; strchr
    0000003f          pop rsi
    00000040          pop rdi
    00000041          pop r8
    00000042          pop r9
    00000043          if.z rax, jmp 0x4d
    00000044          mov r10, 0x20a0
    00000045          sub rax, rax, r10         ; index of char
    00000046          mov qword [r9 + 0], rax   ; store index
    00000047          lea r9, [r9 + 0x8]
    00000048          lea rdi, [rdi + 0x1]      ; next char
    00000049          lea rsi, [rsi + 0xffffffff]
    0000004a          if.nz rsi, jmp 0x38
    0000004b          mov rax, r8               ; return array of indices
    0000004c          ret

    0000004d          mov rdi, r8
    0000004e          call [free]
    0000004f          mov rax, 0
    00000050          ret

    00000051          mov rax, 0x1
    00000052          ret.z rsi
    00000053          mov r8, qword [rdi + 0]
    00000054          cmp.neq r8, r8, 0x16      ; the first index is 0x16
    00000055          ret.nz r8
    00000056          push rdi                  ; indices array
    00000057          push rsi                  ; no.of elements
    00000058          call 0x66                 ; some transformation applied
    00000059          pop rsi
    0000005a          pop rdi
    0000005b          lea rsi, [rsi + 0xffffffff]
    0000005c          push rdi                  ; transformed array
    0000005d          shl rdx, rsi, 0x3         ; #bytes = #qwords * 8
    0000005e          mov rsi, 0x1fa0           ; magic array
    0000005f          call 0x79                 ; compare arrays
    00000060          pop rdi
    00000061          mov r8, rax               ; must return 0
    00000062          mov rax, 0x1
    00000063          ret.nz r8
    00000064          mov rax, 0
    00000065          ret

    00000066          ret.z rsi                 ; the transformation
    00000067          lea rsi, [rsi + 0xffffffff]
    00000068          ret.z rsi
    00000069          mov r8, qword [rdi + 0]
    0000006a          mov r9, qword [rdi + 0x8]
    0000006b          sub r8, r9, r8            ; rdi[1]-rdi[0]
    0000006c          xor r8, r8, rsi           ; rsi ^ rdi[1]-rdi[0]
    0000006d          mul r9, r8, r8
    0000006e          mul r8, r9, r8            ; r8 = (rsi ^ rdi[1]-rdi[0])**3
    0000006f          mov qword [rdi + 0], r8
    00000070          lea rdi, [rdi + 0x8]
    00000071          lea rsi, [rsi + 0xffffffff]
    00000072          jmp 0x68

    00000073          mov rax, 0
    00000074          movzx r10, byte [rdi + 0]
    00000075          ret.z r10
    00000076          lea rdi, [rdi + 0x1]
    00000077          lea rax, [rax + 0x1]
    00000078          jmp 0x74

    00000079          mov rax, 0
    0000007a          ret.z rdx
    0000007b          movzx r8, byte [rdi + 0]
    0000007c          movzx r9, byte [rsi + 0]
    0000007d          xor r8, r8, r9
    0000007e          or rax, rax, r8
    0000007f          lea rdx, [rdx + 0xffffffff]
    00000080          lea rdi, [rdi + 0x1]
    00000081          lea rsi, [rsi + 0x1]
    00000082          if.nz rdx, jmp 0x7b
    00000083          ret

    00000084          mov rax, rdi
    00000085          movzx r8, byte [rax + 0]
    00000086          if.z r8, jmp 0x8b
    00000087          cmp.eq r8, r8, rsi
    00000088          ret.nz r8
    00000089          lea rax, [rax + 0x1]
    0000008a          jmp 0x85
    0000008b          mov rax, 0
    0000008c          ret
```

Now let's analyze the disassembled code.  
The routine at **0x73** finds the length of the string pointed to by **rdi**.  
**0x79** compares byte arrays for equality. It xor's the respective bytes and performs a bitwise-or of the xor's. If the strings are equal then the result will be zero.  
The routine at 0x2d is like this  

```c
    long* get_indices(char* buf, int size)
    {
        long* words = (long*) malloc(size << 3);
        static char set[] = "abdfgehikmanoqrstucvwlxyz-01h23p456u78j9-_.+";
        for (int i = 0; i < size; ++i) {
            words[i] = strchr(set, buf[i])-buf;
        }
        return words;
    }
```

Now the function at 0x51 is called with the array of indices. It applies a transformation on the array of indices and compares the modified array with the array of bytes at **0x1fa0**. If they are equal we get to return 0 (success).  
**0x66** works like this

```c
    void modify(long* words, int count)
    {
        while (--count > 0) {
            long temp = words[1]-words[0] ^ count;
            *words++ = temp*temp*temp;
        }
    }
```

To find the flag, we have the modified array at **0x1fa0**, the starting index as **0x16**. Here's the code  

```c
    void solve(char* elf)
    {
        int64_t* delta = (int64_t*) (elf+0x1fa0);
        printf("-=-=-=- FLAG{");
        char set[] = "abdfgehikmanoqrstucvwlxyz-01h23p456u78j9-_.+";
        int i = 0x16, count = 0x1e;
        while (count--) {
            printf("%c", set[i]);
            int m = (int) round(cbrt(*delta++));
            i += m^count;
        }
        printf("} -=-=-=-\n");
    }

    int main()
    {
        int fd = open("hell86", 0);
        if (fd == -1) {
            fprintf(stderr, "open failed !\n");
            exit(1);
        }

        struct stat stbuf = {0};
        fstat(fd, &stbuf);

        char* buffer = mmap(NULL, stbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (! buffer) {
            close(fd);
            fprintf(stderr, "mmap failed !\n");
            exit(2);
        }

        solve(buffer);

        munmap(buffer, stbuf.st_size);
        close(fd);
    }
```

Which outputs  

    -=-=-=- FLAG{x86-1s-s0-fund4m3nt4lly-br0k3n} -=-=-=-

Here's the complete code (including the disassembler)

```c
    #include <math.h>
    #include <string.h>
    #include <stdlib.h>
    #include <stdio.h>
    #include <fcntl.h>
    #include <sys/stat.h>
    #include <unistd.h>
    #include <stdint.h>
    #include <sys/mman.h>
    #include <elf.h>

    char* regs[] = {
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "rdi", "rsi", "rbp", "rbx", "rdx", "rax", "rcx", "rsp",
        "rip"
    };

    #pragma pack(push, 1)
    struct instr_t
    {
        uint16_t ud2;
        uint64_t imm;
        uint8_t instr;
        uint8_t dest;
        uint8_t src1;
        uint8_t src2;
    };
    #pragma pack(pop)

    // printf(fmt_strings[i], imm, dest, src1, src2)

    char* fmt_strings[] = {
        "nop",
        "add %2$s, %3$s, %4$s",
        "sub %2$s, %3$s, %4$s",
        "mul %2$s, %3$s, %4$s",
        "div.quot %2$s, %3$s, %4$s",
        "div.rem %2$s, %3$s, %4$s",
        "sar %2$s, %3$s, %4$s",
        "shl %2$s, %3$s, %4$s",
        "neg %2$s, %3$s",
        "mov %2$s, %1$#x",
        "movzx %2$s, byte [%3$s + %1$#x]",
        "movsx %2$s, byte [%3$s + %1$#x]",
        "movzx %2$s, word [%3$s + %1$#x]",
        "movsx %2$s, word [%3$s + %1$#x]",
        "mov %2$s, dword [%3$s + %1$#x]",
        "movsxd %2$s, dword [%3$s + %1$#x]",
        "mov %2$s, qword [%3$s + %1$#x]",
        "mov byte [%3$s + %1$#x], %4$s",
        "mov word [%3$s + %1$#x], %4$s",
        "mov dword [%3$s + %1$#x], %4$s",
        "mov qword [%3$s + %1$#x], %4$s",
        "push %3$s",
        "push %1$#x",
        "pop %2$s",
        "mov %2$s, %3$s",
        "or %2$s, %3$s, %4$s",
        "and %2$s, %3$s, %4$s",
        "xor %2$s, %3$s, %4$s",
        "not %2$s, %3$s",
        "cmp.lt %2$s, %3$s, %4$s",
        "cmp.le %2$s, %3$s, %4$s",
        "cmp.gt %2$s, %3$s, %4$s",
        "cmp.ge %2$s, %3$s, %4$s",
        "cmp.eq %2$s, %3$s, %4$s",
        "cmp.neq %2$s, %3$s, %4$s",
        "cmp.eq %2$s, %3$s, %1$#x",
        "cmp.neq %2$s, %3$s, %1$#x",
        "cmp.z %2$s, %3$s       ; %2$s = %3$s == 0",
        "if.z %3$s, jmp %1$#x",
        "if.nz %3$s, jmp %1$#x",
        "call %1$#x",
        "ret",
        "ret.nz %3$s        ; return if %3$s is not zero",
        "ret.z %3$s         ; return if %3$s is zero",
        "lea %2$s, [%3$s + %1$#x]",
        "sar %2$s, %3$s, %1$#hx",
        "shl %2$s, %3$s, %1$#hx",
        "or %2$s, %3$s, %1$#x",
        "and %2$s, %3$s, %1$#x",
        "xor %2$s, %3$s, %1$#x"
    };

    char* resolve(char* elf, uint64_t addr)
    {
        // resolve address
        Elf64_Ehdr* header = (Elf64_Ehdr*) elf;
        Elf64_Shdr* section = (Elf64_Shdr*) (elf + header->e_shoff);
        int n_sections = header->e_shnum;
        Elf64_Shdr *strtab = 0, *symtab = 0, *rela = 0;
        for (int i = 0; i < n_sections; ++i) {
            if (!strtab && section->sh_type == SHT_STRTAB && section->sh_offset != header->e_shstrndx)
                strtab = section;
            else if (!symtab && (section->sh_type == SHT_SYMTAB || section->sh_type == SHT_DYNSYM))
                symtab = section;
            else if (!rela && section->sh_type == SHT_RELA)
                rela = section;
            section++;
        }
        Elf64_Sym* sym = (Elf64_Sym*) (elf+symtab->sh_offset);
        char* names = elf+strtab->sh_offset;
        Elf64_Rela* reloc = (Elf64_Rela*) (elf+rela->sh_offset);
        int n_relocs = rela->sh_size / sizeof(Elf64_Rela);
        for (int i = 0; i < n_relocs; ++i) {
            if (reloc->r_offset == addr) {
                // addr has an entry in reloc
                int sym_idx = reloc->r_info >> 32;
                Elf64_Sym* symb = sym+sym_idx;;
                return names+symb->st_name;
            }
            reloc++;
        }
        return NULL;
    }

    void solve(char* elf)
    {
        int64_t* delta = (int64_t*) (elf+0x1fa0);
        printf("-=-=-=- FLAG{");
        char set[] = "abdfgehikmanoqrstucvwlxyz-01h23p456u78j9-_.+";
        int i = 0x16, count = 0x1e;
        while (count--) {
            printf("%c", set[i]);
            int m = (int) round(cbrt(*delta++));
            i += m^count;
        }
        printf("} -=-=-=-\n");
    }

    int main()
    {
        int fd = open("hell86", 0);
        if (fd == -1) {
            fprintf(stderr, "open failed !\n");
            exit(1);
        }

        struct stat stbuf = {0};
        fstat(fd, &stbuf);

        char* buffer = mmap(NULL, stbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (! buffer) {
            close(fd);
            fprintf(stderr, "mmap failed !\n");
            exit(2);
        }

        char* start = buffer+0x1190;
        uint32_t eip = 0;

        while (start < buffer+0x1946) {
            struct instr_t* i = (struct instr_t*) start;
            printf("%08x%10s", eip, "");
            eip++;
            if (i->instr == 40 && 0 == i->imm)
                printf("call [%s]", resolve(buffer, (char*)(&i->imm)-buffer));
            else {
                uint64_t offset = (i->imm-0x1190)/sizeof(struct instr_t);
                uint64_t imm = i->imm;
                if (i->instr == 9 && i->dest == 0x10)
                    printf("jmp %#lx", offset);
                else {
                    if (i->instr >= 38 && i->instr <= 40)
                        imm = offset;
                    printf(fmt_strings[i->instr], imm, regs[i->dest], regs[i->src1], regs[i->src2]);
                }
            }
            putchar(10);
            start += sizeof (struct instr_t);
        }

        solve(buffer);

        munmap(buffer, stbuf.st_size);
        close(fd);
    }
```