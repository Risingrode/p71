#---------------------------------------------------------------------
# Makefile for PuzzleSolve

.DEFAULT_GOAL := PuzzleSolve

OBJDIR  = obj
CUDA    = /usr/local/cuda
NVCC    = $(CUDA)/bin/nvcc
CXXCUDA = /usr/bin/g++
# GPU 计算能力：未指定 CCAP 时从 nvidia-smi 自动探测（如 7.5 → 75）
CCAP   ?= $(shell nvidia-smi --query-gpu=compute_cap --format=csv,noheader 2>/dev/null | head -1)
ccap    = $(shell echo $(CCAP) | tr -d '.')
ifeq ($(strip $(ccap)),)
$(error 无法确定 GPU 计算能力，请显式指定，例如: make CCAP=75)
endif

OBJET = $(addprefix $(OBJDIR)/, \
        encoding/Base58.o math/IntGroup.o main.o \
        util/Timer.o util/Random.o math/Int.o math/IntMod.o math/Point.o \
        crypto/SECP256K1.o Psolve.o \
        hash/ripemd160.o hash/sha256.o hash/sha512.o \
        hash/ripemd160_sse.o hash/sha256_sse.o \
        GPU/GPUEngine.o encoding/Bech32.o)

ifdef debug
CXXFLAGS = -MMD -MP -DWITHGPU -m64 -mssse3 -Wno-write-strings -g -I. -I$(CUDA)/include
NVCCFLAGS = -MMD -MF $(OBJDIR)/GPU/GPUEngine.d -G -maxrregcount=0 --ptxas-options=-v --compile --compiler-options -fPIC \
            -ccbin $(CXXCUDA) -m64 -g -I$(CUDA)/include \
            -gencode=arch=compute_$(ccap),code=sm_$(ccap)
else
CXXFLAGS = -MMD -MP -DWITHGPU -m64 -mssse3 -Wno-write-strings -O2 -I. -I$(CUDA)/include
NVCCFLAGS = -MMD -MF $(OBJDIR)/GPU/GPUEngine.d -maxrregcount=0 --ptxas-options=-v --compile --compiler-options -fPIC \
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

# 头文件依赖：改了任何被包含的头文件，相关目标文件都会重新编译
-include $(OBJET:.o=.d)

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
	@rm -f obj/*.o obj/*.d obj/GPU/*.[od] obj/hash/*.[od] obj/math/*.[od] \
	       obj/crypto/*.[od] obj/encoding/*.[od] obj/util/*.[od] PuzzleSolve
