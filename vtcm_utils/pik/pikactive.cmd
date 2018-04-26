# this cmdlist is for tcm_emulator test 

in: readpubek 

in: loadcakey -pubkey capub.key
#载入CA公钥 与私钥 

in: apcreate -it 02 -pwd ooo
#建立owner会话  记录会话句柄 
out: 1:$ownerHandle

in: apcreate -it 04 -pwd sss
#建立smk会话，记录会话句柄
out: 1:$smkHandle
								     
in: loadkey -ih $smkHandle -kf pik.key  
out: 1:$keyHandle

in: apcreate -it 01 -iv $keyHandle -pwd kkk
#创建pik会话，返回pik会话句柄
out: 1:$authHandle

in: activateidentity -ish $authHandle -ioh $ownerHandle -ikh $keyHandle -symm symm.key

in: apterminate -ih $authHandle
out: 

in: apterminate -ih $ownerHandle
out: 

in: apterminate -ih $smkHandle
out: 

in: decryptpikcert -kf symm.key -cf pik.cert
