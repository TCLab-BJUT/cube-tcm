# this cmdlist is for tcm_emulator test 

in:  apcreate -it 04 -pwd sss
out: 1:$smkHandle

in: loadkey -ih $smkHandle -kf pik.key
#载入鉴别密钥,返回密钥句柄
out: 1:$keyHandle

in: apcreate -it 01 -iv $keyHandle -pwd kkk
#创建pik会话，返回pik会话句柄
out: 1:$keyAuthHandle

in: loadkey -ih $smkHandle -kf sm2.key
#载入鉴别密钥,返回密钥句柄
out: 1:$verifykeyHandle

in: apterminate -ih $smkHandle

in: apcreate -it 01 -iv $verifykeyHandle -pwd sm2
#创建sm2key会话，返回sm2key会话句柄
out: 1:$verifykeyAuthHandle

in: certifykey -kh $keyHandle -skh $verifykeyHandle -of sm2key.crt
#生成寄存器的完整性报告

in: apterminate -ih $keyAuthHandle

in: evictkey -ikh $keyHandle

in: apterminate -ih $verifykeyAuthHandle

in: evictkey -ikh $verifykeyHandle


