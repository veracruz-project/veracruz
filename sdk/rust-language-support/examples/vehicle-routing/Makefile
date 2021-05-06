all: example.cpp RoutingKit/Makefile
	$(MAKE) -C RoutingKit -f Makefile
	g++ example.cpp -O0 -lroutingkit -lz -fopenmp -pthread -lm -o example -I RoutingKit/include -L RoutingKit/lib
