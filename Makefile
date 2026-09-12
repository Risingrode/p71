#---------------------------------------------------------------------
# Makefile for PuzzleSolve — 比特币谜题私钥搜索器

.DEFAULT_GOAL := PuzzleSolve

SRC = encoding/Base58.cpp math/IntGroup.cpp main.cpp \
      util/Timer.cpp math/Int.cpp math/IntMod.cpp math/Point.cpp \
      crypto/SECP256K1.cpp Psolve.cpp GPU/GPUGenerate.cpp \
      hash/ripemd160.cpp hash/sha256.cpp hash/sha512.cpp \
      hash/ripemd160_sse.cpp hash/sha256_sse.cpp encoding/Bech32.cpp

OBJDIR = obj

ifdef gpu

OBJET = $(addprefix $(OBJDIR)/, \
        encoding/Base58.o math/IntGroup.o main.o \
        util/Timer.o util/Random.o math/Int.o math/IntMod.o math/Point.o \
        crypto/SECP256K1.o Psolve.o GPU/GPUGenerate.o \
        hash/ripemd160.o hash/sha256.o hash/sha512.o \
        hash/ripemd160_sse.o hash/sha256_sse.o \
        GPU/GPUEngine.o encoding/Bech32.o)

else

OBJET = $(addprefix $(OBJDIR)/, \
        encoding/Base58.o math/IntGroup.o main.o \
        util/Timer.o util/Random.o math/Int.o math/IntMod.o math/Point.o \
        crypto/SECP256K1.o Psolve.o GPU/GPUGenerate.o \
        hash/ripemd160.o hash/sha256.o hash/sha512.o \
        hash/ripemd160_sse.o hash/sha256_sse.o encoding/Bech32.o)

endif

CXX     = g++
CUDA    = /usr/local/cuda
CXXCUDA = /usr/bin/g++
NVCC    = $(CUDA)/bin/nvcc
ccap    = $(shell echo $(CCAP) | tr -d '.')

ifdef gpu
ifdef debug
CXXFLAGS = -DWITHGPU -m64 -mssse3 -Wno-write-strings -g -I. -I$(CUDA)/include
else
CXXFLAGS = -DWITHGPU -m64 -mssse3 -Wno-write-strings -O2 -I. -I$(CUDA)/include
endif
LFLAGS = -lpthread -L$(CUDA)/lib64 -lcudart
else
ifdef debug
CXXFLAGS = -m64 -mssse3 -Wno-write-strings -g -I. -I$(CUDA)/include
else
CXXFLAGS = -m64 -mssse3 -Wno-write-strings -O2 -I. -I$(CUDA)/include
endif
LFLAGS = -lpthread
endif

#--------------------------------------------------------------------

ifdef gpu
ifdef debug
$(OBJDIR)/GPU/GPUEngine.o: GPU/GPUEngine.cu
	$(NVCC) -G -maxrregcount=0 --ptxas-options=-v --compile --compiler-options -fPIC \
	        -ccbin $(CXXCUDA) -m64 -g -I$(CUDA)/include \
	        -gencode=arch=compute_$(ccap),code=sm_$(ccap) \
	        -o $(OBJDIR)/GPU/GPUEngine.o -c GPU/GPUEngine.cu
else
$(OBJDIR)/GPU/GPUEngine.o: GPU/GPUEngine.cu
	$(NVCC) -maxrregcount=0 --ptxas-options=-v --compile --compiler-options -fPIC \
	        -ccbin $(CXXCUDA) -m64 -O2 -I$(CUDA)/include \
	        -gencode=arch=compute_$(ccap),code=sm_$(ccap) \
	        -o $(OBJDIR)/GPU/GPUEngine.o -c GPU/GPUEngine.cu
endif
endif

$(OBJDIR)/%.o : %.cpp
	$(CXX) $(CXXFLAGS) -o $@ -c $<

all: PuzzleSolve

PuzzleSolve: $(OBJET)
	@echo "链接 PuzzleSolve..."
	$(CXX) $(OBJET) $(LFLAGS) -o PuzzleSolve

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
