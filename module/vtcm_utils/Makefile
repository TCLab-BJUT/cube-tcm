FLAGS= -g -shared -o
INCLUDE= -I$(CUBESYSPATH)/include/ -I$(CUBELIBPATH)/include -I$(CUBEAPPPATH)/include
CFLAGS= -g -c -fPIC -DUSER_MODE $(INCLUDE)
CC=gcc
CCP=g++
PLUGIN=vtcm_utils
PLUGIN_OBJ= vtcm_ex_utils.o
TEST_LIB= -L$(CUBELIBPATH)/lib -lsys_func -lexmodule -lmessage -lmemdb -lconnector -lstruct -lcrypto_func -ljson -lstring -lalloc -lpthread -lsm2So
LOCALLIB=-L$(CUBEAPPPATH)/locallib/bin -lauth_func

main: lib$(PLUGIN).so $(PLUGIN_OBJ)
lib$(PLUGIN).so:  $(PLUGIN).o $(PLUGIN_OBJ) 
	$(CC) $(FLAGS) lib$(PLUGIN).so $(PLUGIN).o $(PLUGIN_OBJ) $(TEST_LIB) $(LOCALLIB)
	mv lib$(PLUGIN).so $(CUBE_APP_PLUGIN)
	cp $(PLUGIN).cfg $(CUBE_APP_PLUGIN)
$(PLUGIN).o: $(PLUGIN).c $(PLUGIN).h
	$(CC) $(CFLAGS) $(PLUGIN).c
vtcm_ex_utils.o: vtcm_ex_utils.c
	$(CC) $(CFLAGS) vtcm_ex_utils.c
	
clean:
	rm -f lib$(PLUGIN).so 
	rm  *.o *~
