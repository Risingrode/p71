#---------------------------------------------------------------------
# Makefile for PuzzleSolve

.DEFAULT_GOAL := PuzzleSolve

OBJDIR  = obj
CUDA    = /usr/local/cuda
NVCC    = $(CUDA)/bin/nvcc
CXXCUDA = /usr/bin/g++
ccap    = $(shell echo $(CCAP) | tr -d '.')

OBJET = $(addprefix $(OBJDIR)/, \
        encoding/Base58.o math/IntGroup.o main.o \
        util/Timer.o util/Random.o math/Int.o math/IntMod.o math/Point.o \
        crypto/SECP256K1.o Psolve.o \
        hash/ripemd160.o hash/sha256.o hash/sha512.o \
        hash/ripemd160_sse.o hash/sha256_sse.o \
        GPU/GPUEngine.o encoding/Bech32.o)

ifdef debug
CXXFLAGS = -DWITHGPU -m64 -mssse3 -Wno-write-strings -g -I. -I$(CUDA)/include
NVCCFLAGS = -G -maxrregcount=0 --ptxas-options=-v --compile --compiler-options -fPIC \
            -ccbin $(CXXCUDA) -m64 -g -I$(CUDA)/include \
            -gencode=arch=compute_$(ccap),code=sm_$(ccap)
else
CXXFLAGS = -DWITHGPU -m64 -mssse3 -Wno-write-strings -O2 -I. -I$(CUDA)/include
NVCCFLAGS = -maxrregcount=0 --ptxas-options=-v --compile --compiler-options -fPIC \
            -ccbin $(CXXCUDA) -m64 -O2 -I$(CUDA)/include \
            -gencode=arch=compute_$(ccap),code=sm_$(ccap)
endif

LFLAGS = -lpthread -L$(CUDA)/lib64 -lcudart

#--------------------------------------------------------------------

$(OBJDIR)/GPU/GPUEngine.o: GPU/GPUEngine.cu
	$(NVCC) $(NVCCFLAGS) -o $@ -c GPU/GPUEngine.cu

$(OBJDIR)/%.o : %.cpp
	g++ $(CXXFLAGS) -o $@ -c $<

all: PuzzleSolve

PuzzleSolve: $(OBJET)
	@echo "链接 PuzzleSolve..."
	g++ $(OBJET) $(LFLAGS) -o PuzzleSolve

$(OBJET): | $(OBJDIR) $(OBJDIR)/GPU $(OBJDIR)/hash $(OBJDIR)/math \
            $(OBJDIR)/crypto $(OBJDIR)/encoding $(OBJDIR)/util

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/GPU:      $(OBJDIR) ; cd $(OBJDIR) && mkdir -p GPU
$(OBJDIR)/hash:     $(OBJDIR) ; cd $(OBJDIR) && mkdir -p hash
$(OBJDIR)/math:     $(OBJDIR) ; cd $(OBJDIR) && mkdir -p math
$(OBJDIR)/crypto:   $(OBJDIR) ; cd $(OBJDIR) && mkdir -p crypto
$(OBJDIR)/encoding: $(OBJDIR) ; cd $(OBJDIR) && mkdir -p encoding
$(OBJDIR)/util:     $(OBJDIR) ; cd $(OBJDIR) && mkdir -p util

clean:
	@echo "清理..."
	@rm -f obj/*.o obj/GPU/*.o obj/hash/*.o obj/math/*.o \
	       obj/crypto/*.o obj/encoding/*.o obj/util/*.o
