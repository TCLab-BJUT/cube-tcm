FLAGS= -g -shared -o
INCLUDE= -I$(CUBESYSPATH)/include/ -I$(CUBELIBPATH)/include -I$(CUBEAPPPATH)/include
CFLAGS= -g -c -fPIC -DUSER_MODE -std=gnu99 $(INCLUDE)
CC=gcc
CCP=g++
PLUGIN=vtcm_auth
LIBNAME=
PLUGIN_OBJ=
TEST_LIB= -L$(CUBELIBPATH)/lib -lsys_func -lsm2So -lexmodule -lmessage -lmemdb -lconnector -lstruct -lcrypto_func -ljson -lstring -lalloc -lpthread
LOCALLIB=-L$(CUBEAPPPATH)/locallib/bin -lauth_func

main: lib$(PLUGIN).so
lib$(PLUGIN).so:  $(PLUGIN).o $(PLUGIN_PROC_OBJ) $(INIT_DB_OBJ)
	$(CC) $(FLAGS) lib$(PLUGIN).so $(PLUGIN).o $(PLUGIN_OBJ) $(TEST_LIB) $(LOCALLIB)
	mv lib$(PLUGIN).so $(CUBE_APP_PLUGIN)
	cp $(PLUGIN).cfg $(CUBE_APP_PLUGIN)
$(PLUGIN).o: $(PLUGIN).c $(PLUGIN).h
	$(CC) $(CFLAGS) $(PLUGIN).c
clean:
	rm -f lib$(PLUGIN).so 
	rm -f *.o 
