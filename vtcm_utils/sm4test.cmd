# this cmdlist is for tcm_emulator test 

in:  apcreate -it 04 -pwd sss
out: 1:$smkHandle

in: createwrapkey -ikh 40000000 -ish $smkHandle -is sm4 -kf sm4.key -pwdk kkk

in: loadkey -ih $smkHandle -kf sm4.key
out: 1:$keyHandle

in:  apterminate -ih $smkHandle

in: apcreate -it 01 -iv $keyHandle -pwd kkk
out: 1:$keyAuthHandle

in: sm4encrypt -ikh $keyHandle -idh $keyAuthHandle -rf sm4test.dat -wf sm4crypt.dat  

in: sm4decrypt -ikh $keyHandle -idh $keyAuthHandle -rf sm4crypt.dat -wf sm4decrypt.dat 

in:  apterminate -ih $keyAuthHandle
