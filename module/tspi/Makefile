FLAGS= -g -o 
INCLUDE= -I$(CUBESYSPATH)/include/ -I$(CUBELIBPATH)/include -I$(CUBEAPPPATH)/include
CFLAGS= -g -c -fPIC -DUSER_MODE $(INCLUDE)
CC=gcc
CCP=g++
STRUCTOBJ= read_config.o tspi_context.o
LIBNAME=tspi
DEPENDLIB= -L$(CUBELIBPATH)/lib -L$(CUBESYSPATH)/plugin -lsys_func -lchannel -lmessage -lmemdb -lconnector -lstruct -lcrypto_func -ljson -lbasefunc -lstring -lalloc 
LOCALLIB=-L$(CUBEAPPPATH)/locallib/bin -lauth_func

main: lib$(LIBNAME).so shm_proc
shm_proc:  shm_proc.c lib_rw.c main_proc_func.h $(STRUCTOBJ) lib$(LIBNAME).so
	$(CC) $(FLAGS) shm_proc shm_proc.c lib_rw.c -l$(LIBNAME) $(STRUCTOBJ) $(INCLUDE) $(DEPENDLIB) $(LOCALLIB) 
lib$(LIBNAME).so: $(STRUCTOBJ)
	$(CC) -shared -o lib$(LIBNAME).so $(STRUCTOBJ)	 
read_config.o:  read_config.c main_proc_func.h
	$(CC) $(CFLAGS) read_config.c
tspi_context.o:  tspi_context.c 
	$(CC) $(CFLAGS) tspi_context.c

clean:
	rm -f *~ *.o *.a  shm_proc
