# this cmdlist is for tcm_emulator test 

in:  apcreate -it 04
out: 1:$smkHandle

in:  pcrread -ix 1
out: 1:$pcrValue

in:  extend -ix 1 -ic aaaa
out: 1:$pcrValue

in: loadkey -ih $smkHandle -kf pik.key
#载入鉴别密钥,返回密钥句柄
out: 1:$keyHandle

in: apcreate -it 01 -iv $keyHandle
#创建pik会话，返回pik会话句柄
out: 1:$keyAuthHandle

in: quote -ikh $keyHandle -ish $keyAuthHandle -ix 1 -of quote.rpt
#生成寄存器的完整性报告

