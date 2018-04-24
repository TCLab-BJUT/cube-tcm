# this cmdlist is for tcm_emulator test 

in:  pcrread -ix 0 -wf pcrfile
out: 1:$pcrValue

in:  extend -ix 1 -ic aaaa
out: 1:$pcrValue

in:  pcrread -ix 1 -wf pcrfile
out: 1:$pcrValue
