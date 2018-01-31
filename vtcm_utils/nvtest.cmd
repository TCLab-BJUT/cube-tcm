# this cmdlist is for tcm_emulator test 

in: nvdefinespace -in 1 -sz 16 -pwd ooo -per 0
out: 

in: nvwritevalue -in 1 -ic Hello,World! -pwd ooo
out:

in: nvreadvalue -in 1 -sz 6 -off 6 -pwd ooo
out:
