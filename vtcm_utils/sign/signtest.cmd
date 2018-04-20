# this cmdlist is for tcm_emulator sign test 

in:  apcreate -it 04 -pwd sss
out: 1:$smkHandle

in: loadkey -ih $smkHandle -kf sm2.key
out: 1:$keyHandle

in: apterminate -ih $smkHandle

in: apcreate -it 01 -iv $keyHandle -pwd sm2
out: 1:$keyAuthHandle

in: sign -ik $keyHandle -is $keyAuthHandle  -rf signtest.dat -wf signtest.sig

in: apterminate -ih $keyAuthHandle

in: verify -kf sm2.key -rf signtest.dat -sf signtest.sig
