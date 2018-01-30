# this cmdlist is for tcm_emulator test 

in:  apcreate -it 04
out: 1:$smkHandle

in: createwrapkey -ih $smkHandle -is sm2 -kf sm2.key

in: sm2encrypt -rf sm2.key -wf sm2crypt.dat  

in: loadkey -ih $smkHandle -kf sm2.key
out: 1:$keyHandle

in: apcreate -it 01 -iv $keyHandle
out: 1:$keyAuthHandle

in: sm2decrypt -ikh $keyHandle -idh $keyAuthHandle -rf sm2crypt.dat  

