# this cmdlist is for tcm_emulator test 

in: loadcakey -pubkey capub.key -prikey capri.key
#载入CA公钥 与私钥 

in: casign -user user_info.list -pik pik.key -ek ekpub.key -req request.req -cert pik.cert -symm symm.key
out:
