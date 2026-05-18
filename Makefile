CFLAGS = -Wall -g
OBJ = newtwist.o crypto.o
all: newtwist

newtwist: crypto.o newtwist.o
	$(CC) -o newtwist $(OBJ) -lcrypto
	ln -f newtwist newuntwist

crypto.o: crypto.c crypto.h

newtwist.o: newtwist.c crypto.h

orig_twist: orig_twist.o
	$(CC) -o orig_twist orig_twist.o -lcrypto

clean:
	$(RM) *.o newtwist newuntwist orig_*twist
