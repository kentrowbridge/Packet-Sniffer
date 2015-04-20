sniffer: sniffer.o linknode.o
	g++ -o sniffer sniffer.o linknode.o -ltins

sniffer.o: sniffer.cpp sniffer.h
	g++ -c sniffer.cpp -ltins

linknode.o: linknode.cpp linknode.h
	g++ -c linknode.cpp -ltins

clean:
	rm -f *.o
	rm -f *.h.gch
	rm -f sniffer
