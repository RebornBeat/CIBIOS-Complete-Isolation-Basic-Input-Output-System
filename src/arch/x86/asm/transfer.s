// x86 Control Transfer - cibios/src/arch/x86/asm/transfer.s  
/*
.section .text
.global x86_transfer_control_to_os

# Transfer control from x86 CIBIOS to CIBOS kernel
# Parameters (cdecl):
#   ESP+4 = CIBOS entry point (32-bit address)
#   ESP+8 = pointer to HandoffData structure
# This function never returns
x86_transfer_control_to_os:
    # Disable interrupts
    cli
    
    # Get parameters from stack
    movl    4(%esp), %ebx          # Entry point
    movl    8(%esp), %eax          # HandoffData pointer
    
    # Setup clean stack for CIBOS
    movl    $0x7E00, %esp          # Use boot stack area
    
    # Clear segment registers
    xorl    %ecx, %ecx
    movw    %cx, %ds
    movw    %cx, %es
    movw    %cx, %fs
    movw    %cx, %gs
    movw    %cx, %ss
    
    # Clear general-purpose registers except handoff data
    pushl   %eax                   # Push HandoffData as parameter
    xorl    %ecx, %ecx
    xorl    %edx, %edx
    xorl    %esi, %esi
    xorl    %edi, %edi
    
    # Jump to CIBOS kernel
    jmpl    *%ebx
    
    # Should never reach here
    ud2                            # Undefined instruction
*/
