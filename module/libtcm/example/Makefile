FLAGS= -g -o 
INCLUDE= -I$(CUBESYSPATH)/include/ -I$(CUBELIBPATH)/include -I$(CUBEAPPPATH)/include
CFLAGS= -g -c -fPIC -DUSER_MODE $(INCLUDE)
CC=gcc
CCP=g++
DEPENDLIB= -L$(CUBELIBPATH)/lib -L$(CUBESYSPATH)/plugin -lsys_func -lchannel -lmessage -lmemdb -lconnector -lstruct -lcrypto_func -ljson -lbasefunc -lstring -lalloc -lsm2So
LOCALLIB=-L$(CUBEAPPPATH)/locallib/bin -lauth_func -lvtcm_ex_alg -ltcm

main: libtcm_test cainit  casign pikreq pikactive
libtcm_test:  libtcm_test.c
	$(CC) $(FLAGS) libtcm_test libtcm_test.c $(INCLUDE) $(DEPENDLIB) $(LOCALLIB) 
cainit:  cainit.c
	$(CC) $(FLAGS) cainit cainit.c $(INCLUDE) $(DEPENDLIB) $(LOCALLIB) 
casign:  casign.c
	$(CC) $(FLAGS) casign casign.c $(INCLUDE) $(DEPENDLIB) $(LOCALLIB) 
pikreq:  pikreq.c
	$(CC) $(FLAGS) pikreq pikreq.c $(INCLUDE) $(DEPENDLIB) $(LOCALLIB) 
pikactive:  pikactive.c
	$(CC) $(FLAGS) pikactive pikactive.c $(INCLUDE) $(DEPENDLIB) $(LOCALLIB) 

clean:
	rm -f *~ *.o *.a cainit casign pikreq pikactive libtcm_test 
