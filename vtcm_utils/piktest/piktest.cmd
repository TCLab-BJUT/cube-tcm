# this cmdlist is for tcm_emulator test 

in: readpubek -wf ekpub.key

in: createsm2key -pubkey capub.key -prikey capri.key 
#创建一个CA公私钥对，非可信根操作                        
out:

in: loadcakey -pubkey capub.key -prikey capri.key
#载入CA公钥 与私钥 

in: apcreate -it 02 -pwd ooo
#建立owner会话  记录会话句柄 
out: 1:$ownerHandle

in: apcreate -it 04 -pwd sss
#建立smk会话，记录会话句柄
out: 1:$smkHandle
								     
in: makeidentity -ioh $ownerHandle -ish $smkHandle -if user_info.list -of request.req -kf pik.key
#生成鉴别密钥和密钥认证申请包,密钥文件导出 

in: casign -user user_info.list -pik pik.key -cert pik.cert -symm symm.key
out:

in: loadkey -ih $smkHandle -kf pik.key  
out: 1:$keyHandle

in: apcreate -it 01 -iv $keyHandle -pwd kkk
#创建pik会话，返回pik会话句柄
out: 1:$authHandle

in: activateidentity -ish $authHandle -ioh $ownerHandle -ikh $keyHandle -symm symm.key -cert pik.cert

in: apterminate -ih $authHandle
out: 

in: apterminate -ih $ownerHandle
out: 

in: apterminate -ih $smkHandle
out: 
