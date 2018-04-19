# this cmdlist is for tcm_emulator test 

in: createsm2key -pubkey capub.key -prikey capri.key 
#创建一个CA公私钥对，非可信根操作                        
out:

in: loadcakey -pubkey capub.key -prikey capri.key
#载入CA公钥 与私钥 
