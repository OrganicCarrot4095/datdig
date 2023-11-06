li t0, 1  # Incrementor
li t1, 1  # Largest current divisor
mv t2, a0 # Moving t2 into a0 to preserve original value

div_loop:
    sub  a0, a0, t0 # Decrement a0 by 1
    beqz a0, done # If a0 = 0, exit loop - no divisors
    rem t3, t2, a0 # The remainder of testvariable divided by testvariable - n
    beqz t3, found_div # if remainder is zero, branch to "found_div"
    j div_loop # Jump back to loop
    
found_div:
    mv t1, a0 
    j done
          
done:
     mv a0, t1 # Loop finished, moves largest divisor into a0
    
    
li a1, 0     
li t5, 1

sq_loop:
    mul t4, t5, t5 # Storing t5 multiplied with itself in t4
    beq t4, t2, square # If t2 == t4, a0 is a square number - branch to "square"
    bge t5, a0, no_square
    addi t5, t5, 1 
    j sq_loop
    
square:
    addi a1, a1, 1
    
no_square:
    nop