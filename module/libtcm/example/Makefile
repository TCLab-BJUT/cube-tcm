FLAGS= -g -o 
INCLUDE= -I$(CUBESYSPATH)/include/ -I$(CUBELIBPATH)/include -I$(CUBEAPPPATH)/include
CFLAGS= -g -c -fPIC -DUSER_MODE $(INCLUDE)
CC=gcc
CCP=g++
LIBNAME=-L../../../locallib/bin -ltcm
DEPENDLIB= -L$(CUBELIBPATH)/lib -L$(CUBESYSPATH)/plugin -lsys_func -lchannel -lmessage -lmemdb -lconnector -lstruct -lcrypto_func -ljson -lbasefunc -lstring -lalloc -lsm2So
LOCALLIB=-L$(CUBEAPPPATH)/locallib/bin -lauth_func -lvtcm_ex_alg 

main: cainit  casign pikreq pikactive pikverify create_key sm2attr sm2sign key_certify quote_report key_verify sm2_verify loc_test
libtcm_test:  libtcm_test.c
	$(CC) $(FLAGS) libtcm_test libtcm_test.c $(INCLUDE) $(LIBNAME) $(DEPENDLIB) $(LOCALLIB)
cainit:  cainit.c
	$(CC) $(FLAGS) cainit cainit.c $(INCLUDE) $(LIBNAME) $(DEPENDLIB) $(LOCALLIB) 
casign:  casign.c
	$(CC) $(FLAGS) casign casign.c $(INCLUDE) $(LIBNAME) $(DEPENDLIB) $(LOCALLIB) 
pikreq:  pikreq.c
	$(CC) $(FLAGS) pikreq pikreq.c $(INCLUDE) $(LIBNAME) $(DEPENDLIB) $(LOCALLIB) 
pikactive:  pikactive.c
	$(CC) $(FLAGS) pikactive pikactive.c $(INCLUDE) $(LIBNAME) $(DEPENDLIB) $(LOCALLIB) 
pikverify:  pikverify.c
	$(CC) $(FLAGS) pikverify pikverify.c $(INCLUDE) $(LIBNAME) $(DEPENDLIB) $(LOCALLIB) 
create_key:  create_key.c
	$(CC) $(FLAGS) create_key create_key.c $(INCLUDE) $(LIBNAME) $(DEPENDLIB) $(LOCALLIB) 
sm2attr:  sm2attr.c
	$(CC) $(FLAGS) sm2attr sm2attr.c $(INCLUDE) $(LIBNAME) $(DEPENDLIB) $(LOCALLIB) 
sm2sign:  sm2sign.c
	$(CC) $(FLAGS) sm2sign sm2sign.c $(INCLUDE) $(LIBNAME) $(DEPENDLIB) $(LOCALLIB) 
key_certify:  key_certify.c
	$(CC) $(FLAGS) key_certify key_certify.c $(INCLUDE) $(LIBNAME) $(DEPENDLIB) $(LOCALLIB) 
loc_test:  loc_test.c
	$(CC) $(FLAGS) loc_test loc_test.c $(INCLUDE) $(LIBNAME) $(DEPENDLIB) $(LOCALLIB) 
sm2_verify:  sm2_verify.c
	$(CC) $(FLAGS) sm2_verify sm2_verify.c $(INCLUDE) $(LIBNAME) $(DEPENDLIB) $(LOCALLIB) 
key_verify:  key_verify.c
	$(CC) $(FLAGS) key_verify key_verify.c $(INCLUDE) $(LIBNAME) $(DEPENDLIB) $(LOCALLIB) 
quote_report:  quote_report.c
	$(CC) $(FLAGS) quote_report quote_report.c $(INCLUDE) $(LIBNAME) $(DEPENDLIB) $(LOCALLIB) 

clean:
	rm -f *~ *.o *.a cainit casign pikreq pikactive pikverify libtcm_test  create_key sm2attr sm2sign key_certify quote_report
