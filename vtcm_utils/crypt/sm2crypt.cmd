# this cmdlist is for tcm_emulator test 

in: sm2encrypt -kf sm2.key -rf sm2test.dat -wf sm2crypt.dat  

in:  apcreate -it 04 -pwd sss
out: 1:$smkHandle

in: loadkey -ih $smkHandle -kf sm2.key
out: 1:$keyHandle

in: apterminate -ih $smkHandle

in: apcreate -it 01 -iv $keyHandle -pwd sm2
out: 1:$keyAuthHandle

in: sm2decrypt -ik $keyHandle -is $keyAuthHandle -rf sm2crypt.dat  -wf sm2decrypt.dat

in: apterminate -ih $keyAuthHandle
