CC      = g++
CFLAGS  = -I/home/nishant/Desktop/TAMU_Gant_Results/program -I/usr/include/modbus/ -DDEBUG=1 
LDFLAGS = `pkg-config --libs --cflags libmodbus`

all: CyberAttackSuite 

CyberAttackSuite: CyberAttackSuite.o
	$(CC) -o $@ $^ $(LDFLAGS)

CyberAttackSuite.o: CyberAttackSuite.cpp 
	$(CC) -c $(CFLAGS) $<

.PHONY: clean 

clean:
	rm *.o
	rm CyberAttackSuite

