# this cmdlist is for tcm_emulator sm4crypt test 

in:  apcreate -it 04 -pwd sss
out: 1:$smkHandle

in: loadkey -ih $smkHandle -kf sm4.key
out: 1:$keyHandle

in: apterminate -ih $smkHandle

in: apcreate -it 01 -iv $keyHandle -pwd sm4
out: 1:$keyAuthHandle

in: sm4encrypt -ikh $keyHandle -idh $keyAuthHandle -rf sm4test.dat -wf sm4crypt.dat  

in: sm4decrypt -ikh $keyHandle -idh $keyAuthHandle -rf sm4crypt.dat -wf sm4decrypt.dat 

in:  apterminate -ih $keyAuthHandle
