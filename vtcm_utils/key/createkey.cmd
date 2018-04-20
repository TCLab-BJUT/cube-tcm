# this cmdlist is for tcm_emulator create key operation 

in:  apcreate -it 04 -pwd sss
out: 1:$smkHandle

in: createwrapkey -ikh 40000000 -ish $smkHandle -is sm2 -kf sm2.key -pwdk sm2

in: createwrapkey -ikh 40000000 -ish $smkHandle -is sm4 -kf sm4.key -pwdk sm4

in: apterminate -ih $smkHandle

