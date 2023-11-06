# Utfører dei etterspurde addisjonane
add s0, a0, a1 # a0a1
add s1, a2, a3 # a2a3
add s2, a4, a5 # a4a5

# Byrjar med å lagre s0 i a0
mv a0, s0

# Undersøkjer deretter om a0 er større enn hhv s1 og s2
bgt a0, s1, check_s2
mv a0, s1

check_s2:
bgt a0, s2, exit
mv a0, s2

exit:
nop
