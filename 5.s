# Øving 5
.data

# SETT DENNE TIL 0 NÅR DU SKAL LEVERE
test_mode: .word   0 

verbose:   .word   1

# Ikke rør disse
w_c:       .word   0xb5ad4ece
mask:      .word   0xFFFF

# Strenger for printing
str1:      .string "Puttet verdien "
str2:      .string " pÃ¥ addresselokasjon "

str3:      .string "StÃ¸rste tall: "


.text

# Programmet starter her
# Sett test_mode til 0 når du skal levere!
lw a7, test_mode
beq a7, zero, load_complete

# TEST - START
li a0, 42
li a1, 100
# TEST - SLUTT


load_complete:
j main
    

# Function: msws32
# Input a0, a1
# a0 = random/seed
# a1 = Wayl sequence
# Output a0, a1
# a0 = random/seed
# a1 = Wayl sequence
msws32:
    mul a0, a0, a0
    lw t0, w_c
    add a1, a1, t0
    add a0, a0, a1
    slli t0, a0, 16
    srli t1, a0, 16
    or a0, t0, t1
    lw t0, mask
    and a0, a0, t0
    ret


# Function: fill_array_with_random_numbers
# Input: a0, a1, a2, a3
# a0 = seed
# a1 = Wayl state
# a2 = Stack start
# a3 = Elements
# Reserved;
# a4 = Counter
# Output: a0, a1
# a0 = seed
# a1 = Wayl state
fill_array_with_random_numbers:
    addi sp, sp, -24
    sw ra, 0(sp)
    sw a2, 4(sp)
    sw a3, 8(sp)
    
    li a4, 0
fawrn_loop_start:
    lw t0, 8(sp)
    bge a4, t0, fawrn_loop_end
    
    sw a4, 12(sp)
    call msws32
    lw a4, 12(sp)

    li t0, 4 # Word in bytes
    mul t0, a4, t0
    add t0, a2, t0
    sw a0, 0(t0)
    
    lw t1, verbose
    beq t1, zero, fawrn_skip_print
# Else
    sw a4, 12(sp)
    sw a0, 16(sp)
    sw a1, 20(sp)
    mv a0, a0
    mv a1, t0
    call print_put_at_adress
    lw a4, 12(sp)
    lw a0, 16(sp)
    lw a1, 20(sp)
    
fawrn_skip_print:
    addi, a4, a4, 1
    j fawrn_loop_start
    
fawrn_loop_end:
    lw ra, 0(sp)
    addi sp, sp, 24
    ret



# Function: print_put_at_adress
# Input: a0, a1
# a0 = Value
# a1 = Adress
print_put_at_adress:
    mv t0, a0
    mv t1, a1
    la a0, str1
    li a7, 4
    ecall
    mv a0, t0
    li a7, 1
    ecall
    la a0, str2
    li a7, 4
    ecall
    mv a0, t1
    li a7, 34
    ecall
    li a0, 10
    li a7, 11
    ecall
    ret
    
    
# Function: print_max
# Input: a0
# a0: Max
print_max:
    mv t0, a0
    la a0, str3
    li a7, 4
    ecall
    mv a0, t0
    li a7, 1
    ecall
    li a0, 10
    li a7, 11
    ecall
    ret


# Function: find_max
# Input: a0, a1
# a0 = Stack/array start
# a1 = Length
# Reserved
# a2 = Counter
# a3 = Local max
# Output: a0
# a0 = Max
find_max:
    li a2, 0
    lw a3, 0(a0)
fm_loop_start:
    bge a2, a1, fm_loop_end
    li t0, 4
    mul t0, a2, t0
    add t0, a0, t0
    lw t0, 0(t0)
    blt t0, a3, fm_not_greater
# Else
    mv a3, t0
fm_not_greater:
    addi a2, a2, 1
    j fm_loop_start
fm_loop_end:
    mv a0, a3
    ret
    
    
# Main
# Input: a0, a1
# a0 = Seed
# a1 = Array length    
# Output: a0
# a0 = Max
main:
    mv a3, a1
    mv s3, a3
    li a1, 0
    li t0, -4
    mul t0, a3, t0
    add sp, sp, t0 # Allocated
    mv a2, sp
    mv s2, a2
    call fill_array_with_random_numbers
        
    mv a0, s2
    mv a1, s3
    call find_max
    mv s0, a0
    # a0 -> a0
    call print_max
    mv a0, s0
    nop
