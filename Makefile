CXX = g++
CXXFLAGS = -w
LDFLAGS = -libverbs

all: rdma_server rdma_client

rdma_server: rdma_server.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

rdma_client: rdma_client.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f rdma_server rdma_client

.PHONY: all clean
