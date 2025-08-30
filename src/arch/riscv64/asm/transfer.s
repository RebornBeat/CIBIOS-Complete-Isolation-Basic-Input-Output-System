// RISC-V Control Transfer - cibios/src/arch/riscv64/asm/transfer.s
/*
.section .text
.global riscv64_transfer_control_to_os

# Transfer control from RISC-V CIBIOS to CIBOS kernel
# Parameters:
#   a0 = CIBOS entry point address
#   a1 = pointer to HandoffData structure
# This function never returns
riscv64_transfer_control_to_os:
    # Disable interrupts
    csrci   mstatus, 0x8           # Clear MIE bit
    
    # Save parameters
    mv      t0, a0                 # Entry point
    mv      t1, a1                 # HandoffData
    
    # Setup clean register state for CIBOS
    mv      a0, t1                 # HandoffData as first parameter
    li      a1, 0
    li      a2, 0  
    li      a3, 0
    li      a4, 0
    li      a5, 0
    li      a6, 0
    li      a7, 0
    
    # Clear temporary registers
    li      t2, 0
    li      t3, 0
    li      t4, 0
    li      t5, 0
    li      t6, 0
    
    # Clear saved registers
    li      s0, 0
    li      s1, 0
    li      s2, 0
    li      s3, 0
    li      s4, 0
    li      s5, 0
    li      s6, 0
    li      s7, 0
    li      s8, 0
    li      s9, 0
    li      s10, 0
    li      s11, 0
    
    # Jump to CIBOS kernel entry point
    jr      t0
    
    # Should never reach here
    unimp                          # Unimplemented instruction trap
*/
