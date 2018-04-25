# this cmdlist is for tcm_emulator test 

in: loadcakey -pubkey capub.key 
#载入CA公钥  

in: apcreate -it 02 -pwd ooo
#建立owner会话  记录会话句柄 
out: 1:$ownerHandle

in: apcreate -it 04 -pwd sss
#建立smk会话，记录会话句柄
out: 1:$smkHandle
								     
in: makeidentity -ioh $ownerHandle -ish $smkHandle -if user_info.list -of request.req -kf pik.key
#生成鉴别密钥和密钥认证申请包,密钥文件导出 

in: apterminate -ih $ownerHandle

in: apterminate -ih $smkHandle
