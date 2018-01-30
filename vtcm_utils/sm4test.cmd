# this cmdlist is for tcm_emulator test 

in:  apcreate -it 04
out: 1:$smkHandle

#in:  pcrread -ix 1
#out: 1:$pcrValue

#in:  extend -ix 1 -ic aaaa
#out: 1:$pcrValue

in: createwrapkey -ih $smkHandle -is sm4 -kf sm4.key

in: loadkey -ih $smkHandle -kf sm4.key
out: 1:$keyHandle

in: apcreate -it 01 -iv $keyHandle
out: 1:$keyAuthHandle

in: sm4encrypt -ikh $keyHandle -idh $keyAuthHandle -wf sm4crypt.dat  

in: sm4decrypt -ikh $keyHandle -idh $keyAuthHandle -rf sm4crypt.dat  

