# this cmdlist is for tcm_emulator test 

in:  pcrread -ix 1 -wf pcrfile
out: 1:$pcrValue

in:  extend -ix 2 -ic aaaa
out: 1:$pcrValue

in:  pcrread -ix 2 -wf pcrfile
out: 1:$pcrValue

in:  apcreate -it 04 -pwd sss
out: 1:$smkHandle

in: loadkey -ih $smkHandle -kf pik.key
#载入鉴别密钥,返回密钥句柄
out: 1:$keyHandle

in: apcreate -it 01 -iv $keyHandle -pwd kkk
#创建pik会话，返回pik会话句柄
out: 1:$keyAuthHandle

in: quote -ikh $keyHandle -ish $keyAuthHandle -ix A -of quote.rpt
#生成寄存器的完整性报告

