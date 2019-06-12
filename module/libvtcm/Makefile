FLAGS= -g -o 
INCLUDE= -I$(CUBESYSPATH)/include/ -I$(CUBELIBPATH)/include -I$(CUBEAPPPATH)/include
CFLAGS= -g -c -fPIC -DUSER_MODE $(INCLUDE)
CC=gcc
CCP=g++
STRUCTOBJ= read_config.o tcm_func.o tcm_ex_func.o
LIBNAME=vtcm
DEPENDLIB= -L$(CUBELIBPATH)/lib -L$(CUBESYSPATH)/plugin -lsys_func -lchannel -lmessage -lmemdb -lconnector -lstruct -lcrypto_func -ljson -lbasefunc -lstring -lalloc -lsm2So
LOCALLIB=-L$(CUBEAPPPATH)/locallib/bin -lauth_func -lvtcm_ex_alg

main: lib$(LIBNAME).so 
#sm4attr:  sm4attr.c lib_rw.c main_proc_func.h $(STRUCTOBJ) lib$(LIBNAME).so
#	$(CC) $(FLAGS) sm4attr sm4attr.c lib_rw.c -l$(LIBNAME) $(STRUCTOBJ) $(INCLUDE) $(DEPENDLIB) $(LOCALLIB) 
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
	rm -f *~ *.o *.a  shm_proc
