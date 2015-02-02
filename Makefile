CC      = g++
CFLAGS  = -I/home/nishant/Desktop/TAMU_Gant_Results/program -DDEBUG=1 `pkg-config --libs --cflags libmodbus`
LDFLAGS = 

all: CyberAttackSuite 

CyberAttackSuite: CyberAttackSuite.o
	$(CC) -o $@ $^ $(LDFLAGS)

CyberAttackSuite.o: CyberAttackSuite.cpp 
	$(CC) -c $(CFLAGS) $<

.PHONY: clean 

clean:
	rm *.o
	rm CyberAttackSuite

