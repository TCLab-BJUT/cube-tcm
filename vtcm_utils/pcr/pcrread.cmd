# this cmdlist is for tcm_emulator test 

in:  pcrread -ix 2 -wf pcrfile
out: 1:$pcrValue

in:  extend -ix 2 -ic aaaa
out: 1:$pcrValue

in:  pcrread -ix 2 -wf pcrfile
out: 1:$pcrValue
