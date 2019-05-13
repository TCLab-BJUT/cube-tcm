FLAGS= -g -o 
INCLUDE= -I$(CUBESYSPATH)/include/ -I$(CUBELIBPATH)/include -I$(CUBEAPPPATH)/include
CFLAGS= -g -c -fPIC -DUSER_MODE $(INCLUDE)
CC=gcc
CCP=g++
STRUCTOBJ= read_config.o tcm_func.o tcm_ex_func.o
LIBNAME=tcm
DEPENDLIB= -L$(CUBELIBPATH)/lib -L$(CUBESYSPATH)/plugin -lsys_func -lchannel -lmessage -lmemdb -lconnector -lstruct -lcrypto_func -ljson -lbasefunc -lstring -lalloc -lsm2So
LOCALLIB=-L$(CUBEAPPPATH)/locallib/bin -lauth_func -lvtcm_ex_alg

main: lib$(LIBNAME).so libtcm_test sm1test sm1attr sm2test sm2attr sm3test sm3attr sm4test sm4attr
libtcm_test:  libtcm_test.c lib_rw.c main_proc_func.h $(STRUCTOBJ) lib$(LIBNAME).so
	$(CC) $(FLAGS) libtcm_test libtcm_test.c lib_rw.c -l$(LIBNAME) $(STRUCTOBJ) $(INCLUDE) $(DEPENDLIB) $(LOCALLIB) 
sm1test:  sm1test.c lib_rw.c main_proc_func.h $(STRUCTOBJ) lib$(LIBNAME).so
	$(CC) $(FLAGS) sm1test sm1test.c lib_rw.c -l$(LIBNAME) $(STRUCTOBJ) $(INCLUDE) $(DEPENDLIB) $(LOCALLIB) 
sm1attr:  sm1attr.c lib_rw.c main_proc_func.h $(STRUCTOBJ) lib$(LIBNAME).so
	$(CC) $(FLAGS) sm1attr sm1attr.c lib_rw.c -l$(LIBNAME) $(STRUCTOBJ) $(INCLUDE) $(DEPENDLIB) $(LOCALLIB) 
sm2test:  sm2test.c lib_rw.c main_proc_func.h $(STRUCTOBJ) lib$(LIBNAME).so
	$(CC) $(FLAGS) sm2test sm2test.c lib_rw.c -l$(LIBNAME) $(STRUCTOBJ) $(INCLUDE) $(DEPENDLIB) $(LOCALLIB) 
sm2attr:  sm2attr.c lib_rw.c main_proc_func.h $(STRUCTOBJ) lib$(LIBNAME).so
	$(CC) $(FLAGS) sm2attr sm2attr.c lib_rw.c -l$(LIBNAME) $(STRUCTOBJ) $(INCLUDE) $(DEPENDLIB) $(LOCALLIB) 
sm3test:  sm3test.c lib_rw.c main_proc_func.h $(STRUCTOBJ) lib$(LIBNAME).so
	$(CC) $(FLAGS) sm3test sm3test.c lib_rw.c -l$(LIBNAME) $(STRUCTOBJ) $(INCLUDE) $(DEPENDLIB) $(LOCALLIB) 
sm3attr:  sm3attr.c lib_rw.c main_proc_func.h $(STRUCTOBJ) lib$(LIBNAME).so
	$(CC) $(FLAGS) sm3attr sm3attr.c lib_rw.c -l$(LIBNAME) $(STRUCTOBJ) $(INCLUDE) $(DEPENDLIB) $(LOCALLIB) 
sm4test:  sm4test.c lib_rw.c main_proc_func.h $(STRUCTOBJ) lib$(LIBNAME).so
	$(CC) $(FLAGS) sm4test sm4test.c lib_rw.c -l$(LIBNAME) $(STRUCTOBJ) $(INCLUDE) $(DEPENDLIB) $(LOCALLIB) 
sm4attr:  sm4attr.c lib_rw.c main_proc_func.h $(STRUCTOBJ) lib$(LIBNAME).so
	$(CC) $(FLAGS) sm4attr sm4attr.c lib_rw.c -l$(LIBNAME) $(STRUCTOBJ) $(INCLUDE) $(DEPENDLIB) $(LOCALLIB) 
lib$(LIBNAME).so: $(STRUCTOBJ)
	$(CC) -shared -o lib$(LIBNAME).so $(STRUCTOBJ)	 
	cp lib$(LIBNAME).so $(CUBEAPPPATH)/locallib/bin
read_config.o:  read_config.c main_proc_func.h
	$(CC) $(CFLAGS) read_config.c
tcm_func.o:  tcm_func.c 
	$(CC) $(CFLAGS) tcm_func.c
tcm_ex_func.o:  tcm_ex_func.c 
	$(CC) $(CFLAGS) tcm_ex_func.c

clean:
	rm -f *~ *.o *.a  
