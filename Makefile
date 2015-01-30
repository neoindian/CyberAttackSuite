CC      = g++
CFLAGS  = -I/home/nishant/Desktop/TAMU_Gant_Results/program
LDFLAGS = 

all: CyberAttackSuite 

octhecdec: CyberAttackSuite.o
	$(CC) -o $@ $^ $(LDFLAGS)

CyberAttackSuite.o: CyberAttackSuite.cpp 
	$(CC) -c $(CFLAGS) $<

.PHONY: clean 

clean:
	rm *.o
	rm CyberAttackSuite

