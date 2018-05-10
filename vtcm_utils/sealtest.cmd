# this cmdlist is for tcm_emulator test 

in:  apcreate -it 04 -pwd sss
out: 1:$smkHandle

in: loadkey -ih $smkHandle -kf sm4.key
out: 1:$keyHandle

in: apcreate -it 01 -iv $keyHandle -pwd sm4
out: 1:$keyAuthHandle

in: seal -ikh $keyHandle -idh $keyAuthHandle -rf plain.dat -wf seal.dat  

in: unseal -ikh $keyHandle -idh $keyAuthHandle -rf seal.dat
