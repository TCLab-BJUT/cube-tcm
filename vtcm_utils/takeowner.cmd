# this cmdlist is for tcm_emulator init

in: readpubek
info: read endorsement key's public key

in:  apcreate -it 12
out: 1:$ownerHandle

in: takeownership

in: apterminate -ih $ownerHandle

in:  apcreate -it 04
out: 1:$smkHandle
