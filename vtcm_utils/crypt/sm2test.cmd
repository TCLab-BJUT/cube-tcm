# this cmdlist is for tcm_emulator test 

in:  apcreate -it 04 -pwd sss
out: 1:$smkHandle

in: createwrapkey -ikh 40000000 -ish $smkHandle -is sm2 -kf sm2.key -pwdk kss

in: sm2encrypt -kf sm2.key -rf sm2test.dat -wf sm2crypt.dat  

in: loadkey -ih $smkHandle -kf sm2.key
out: 1:$keyHandle

in: apcreate -it 01 -iv $keyHandle -pwd kss
out: 1:$keyAuthHandle

in: sm2decrypt -ik $keyHandle -is $keyAuthHandle -rf sm2crypt.dat  -wf sm2decrypt.dat

