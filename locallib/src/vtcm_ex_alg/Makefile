FLAGS= -g -shared -o
INCLUDE= -I$(CUBESYSPATH)/include/ -I$(CUBELIBPATH)/include -I$(CUBEAPPPATH)/include
CFLAGS= -g -c -fPIC -DUSER_MODE -std=gnu99 $(INCLUDE)
CC=gcc
CCP=g++
LIBNAME=vtcm_ex_alg
LIBNAME_OBJ=
TEST_LIB= -L$(CUBELIBPATH)/lib -lstruct -lcrypto_func -ljson -lstring -lalloc
LOCALLIB=-L$(CUBEAPPPATH)/locallib/bin -lsm2So

main: lib$(LIBNAME).so
lib$(LIBNAME).so:  $(LIBNAME).o $(LIBNAME_OBJ) 
	$(CC) $(FLAGS) lib$(LIBNAME).so $(LIBNAME).o $(LIBNAME_OBJ) $(TEST_LIB) $(LOCALLIB)
	mv lib$(LIBNAME).so $(CUBEAPPPATH)/locallib/bin
$(LIBNAME).o: $(LIBNAME).c
	$(CC) $(CFLAGS) $(LIBNAME).c
clean:
	rm -f lib$(LIBNAME).so 
	rm -f *.o 
