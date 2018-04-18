# this cmdlist is for tcm_emulator test 

in:  apcreate -it 04 -pwd sss
out: 1:$smkHandle

in: createwrapkey -ikh 40000000 -ish $smkHandle -is sm2 -kf sm2sign.key -pwdk sign

in: loadkey -ih $smkHandle -kf sm2sign.key
out: 1:$keyHandle

in: apterminate -ih $smkHandle

in: apcreate -it 01 -iv $keyHandle -pwd sign
out: 1:$keyAuthHandle

in: sign -ik $keyHandle -is $keyAuthHandle  -rf signtest.dat -wf signtest.sig

in: apterminate -ih $keyAuthHandle
