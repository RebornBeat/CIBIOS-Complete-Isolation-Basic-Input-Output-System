// =============================================================================
// cibios/src/arch/x86_64/asm/vt_x.s
// Intel VT-x virtualization assembly functions
// =============================================================================

/*
.section .text
.global x86_64_vt_x_enable_virtualization

# Enable Intel VT-x virtualization features
# Returns: true (1) if successful, false (0) if failed or not supported
x86_64_vt_x_enable_virtualization:
    # Save registers
    pushq   %rax
    pushq   %rbx
    pushq   %rcx
    pushq   %rdx
    
    # Check if VT-x is supported
    movq    $1, %rax
    cpuid
    testl   $0x20, %ecx            # Check VMX bit in ECX
    jz      .Lvt_x_not_supported
    
    # Check if VT-x is locked by BIOS
    movq    $0x3A, %rcx            # IA32_FEATURE_CONTROL MSR
    rdmsr
    testl   $0x1, %eax             # Check lock bit
    jnz     .Lvt_x_check_enabled   # If locked, check if VMX is enabled
    
    # VT-x not locked, enable it
    orl     $0x5, %eax             # Enable VMX outside SMX and lock
    wrmsr
    jmp     .Lvt_x_enable
    
.Lvt_x_check_enabled:
    # VT-x locked, check if enabled
    testl   $0x4, %eax             # Check VMX outside SMX bit
    jz      .Lvt_x_not_supported
    
.Lvt_x_enable:
    # Enable VT-x by setting VMXE bit in CR4
    movq    %cr4, %rax
    orq     $0x2000, %rax          # Set VMXE bit (bit 13)
    movq    %rax, %cr4
    
    # Test if VT-x is now enabled
    movq    %cr4, %rax
    testq   $0x2000, %rax
    jz      .Lvt_x_not_supported
    
    # Success
    movq    $1, %rax               # Return true
    jmp     .Lvt_x_cleanup
    
.Lvt_x_not_supported:
    # VT-x not supported or failed to enable
    xorq    %rax, %rax             # Return false
    
.Lvt_x_cleanup:
    # Restore registers (except RAX which contains return value)
    popq    %rdx
    popq    %rcx  
    popq    %rbx
    addq    $8, %rsp               # Adjust for saved RAX
    ret
*/
