all:
	g++ -Wall -o tcp-block tcp-block.cpp -lpcap
 
clean:
	rm -f tcp-block
