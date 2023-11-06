.data
function_error_str: .string "ERROR: Woops, programmet returnerte ikke fra et funksjonskall!"
.text

# Test modus
# Set opp testverdiar dersom a7 = 1
li a7, 0
beq a7, zero, load_complete

li a0, 5
li a1, 4
li a2, 3
li a3, 2
li a4, 1
li a5, 0

load_complete:
# s0-s5 lagrar lista som skal sorterast
# s6 er ein indikator på om noko har endra seg sidan førre loop

j main # Hoppar forbi swap og swap_complete

swap:
    bge a1, a0, swap_complete # Dersom a0 > a1, bytter a0 og a1 om på verdiane
    mv t0, a0
    mv a0, a1
    mv a1, t0
    li s6, 1 # Set s6 til 1 for å vise at vi har gjort endringar

swap_complete:
    ret # Returnerer til funksjonskallet
    

# Feil i programmet
la a0, function_error_str
li a7, 4
ecall
j end

main:
    # Kopierer inputverdiane til andre register
    mv s0, a0
    mv s1, a1
    mv s2, a2
    mv s3, a3
    mv s4, a4
    mv s5, a5

loop:
    li s6, 0 # Set s6 til 0, har ikkje skjedd noko endring før vi har begynt

    # Samanliknar og moglegens byttar om s0 og s1 vha swap funksjonen
    mv a0, s0 
    mv a1, s1
    jal swap
    mv s0, a0
    mv s1, a1

    # Gjentar prosessen for resten av elementa i lista
    mv a0, s1
    mv a1, s2
    jal swap
    mv s1, a0
    mv s2, a1

    mv a0, s2
    mv a1, s3
    jal swap
    mv s2, a0
    mv s3, a1

    mv a0, s3
    mv a1, s4
    jal swap
    mv s3, a0
    mv s4, a1

    mv a0, s4
    mv a1, s5
    jal swap
    mv s4, a0
    mv s5, a1

    beqz s6, loop_end # Dersom s6 = 0 vart ingenting i løpet av den siste loopen - lista er sortert, branch til loop_end
    j loop # Dersom s6 != 0, har noko blitt endra, kjører loopen ein gong til

loop_end:
    # Vi er ferdige og flyttar dei sorterte tala til output-registera
    mv a0, s0
    mv a1, s1
    mv a2, s2
    mv a3, s3
    mv a4, s4
    mv a5, s5

end:
    nop # Programmet avsluttar
