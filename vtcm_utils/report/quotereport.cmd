# this cmdlist is for tcm_emulator test 

in:  apcreate -it 04 -pwd sss
out: 1:$smkHandle

in: loadkey -ih $smkHandle -kf pik.key
#载入鉴别密钥,返回密钥句柄
out: 1:$keyHandle

in: apterminate -ih $smkHandle

in: apcreate -it 01 -iv $keyHandle -pwd kkk
#创建pik会话，返回pik会话句柄
out: 1:$keyAuthHandle

in: quote -ikh $keyHandle -ish $keyAuthHandle -ix 3 -of quote.rpt
#生成寄存器的完整性报告

in: apterminate -ih $keyAuthHandle

in: verifyquote -kf pik.key -rf quote.rpt

in: checkquotepcr -pf pcrfile -rf quote.rpt
