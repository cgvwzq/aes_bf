CXX ?= c++

all:
	$(CXX) -Ofast -Wall -march=native -std=c++11 src/aes-brute-force.cpp -I include/ -o aes-brute-force -lpthread $(*)

clean:
	rm ./aes-brute-force
