# this cmdlist is for tcm_emulator init

in: createek -wf ekpub.key  #create ekpair and output pubek to ekpub.key
info: create endorsement pair 

in: readpubek
info: read endorsement key's public key

in:  apcreate -it 12
out: 1:$ownerHandle

in: takeownership

in: apterminate -ih $ownerHandle

in:  apcreate -it 04
out: 1:$smkHandle

in:  pcrread -ix 1
out: 1:$pcrValue

in:  extend -ix 1 -ic aaaa
out: 1:$pcrValue

in: createwrapkey -ih $smkHandle -is sm2 -kf sm2.key
out:

in: loadkey -ih $smkHandle -kf sm2.key
out: 1:$keyHandle

in: apcreate -it 01 -iv $keyHandle
out: 1:$keyAuthHandle

