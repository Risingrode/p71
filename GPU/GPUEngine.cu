/*
 * This file is part of the VanitySearch distribution (https://github.com/JeanLucPons/VanitySearch).
 * Copyright (c) 2019 Jean Luc PONS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef WIN64
#include <unistd.h>
#include <stdio.h>
#endif

#include "GPUEngine.h"
#include <cuda.h>
#include <cuda_runtime.h>

#include <stdint.h>
#include "../hash/sha256.h"
#include "../hash/ripemd160.h"
#include "../util/Timer.h"

#include "GPUGroup.h"
#include "GPUMath.h"
#include "GPUHash.h"
#include "GPUBase58.h"
#include "GPUWildcard.h"
#include "GPUCompute.h"
#include "GPUCombineABCD.h"

// ---------------------------------------------------------------------------------------

__global__ void comp_keys(uint32_t mode,prefix_t *prefix, uint32_t *lookup32, uint64_t *keys, uint32_t maxFound, uint32_t *found) {

  int xPtr = (blockIdx.x*blockDim.x) * 8;
  int yPtr = xPtr + 4 * blockDim.x;
  ComputeKeys(mode, keys + xPtr, keys + yPtr, prefix, lookup32, maxFound, found);

}

__global__ void comp_keys_p2sh(uint32_t mode, prefix_t *prefix, uint32_t *lookup32, uint64_t *keys, uint32_t maxFound, uint32_t *found) {

  int xPtr = (blockIdx.x*blockDim.x) * 8;
  int yPtr = xPtr + 4 * blockDim.x;
  ComputeKeysP2SH(mode, keys + xPtr, keys + yPtr, prefix, lookup32, maxFound, found);

}

__global__ void comp_keys_comp(prefix_t *prefix, uint32_t *lookup32, uint64_t *keys, uint32_t maxFound, uint32_t *found) {

  int xPtr = (blockIdx.x*blockDim.x) * 8;
  int yPtr = xPtr + 4 * blockDim.x;
  ComputeKeysComp(keys + xPtr, keys + yPtr, prefix, lookup32, maxFound, found);

}

__global__ void comp_keys_pattern(uint32_t mode, prefix_t *pattern, uint64_t *keys,  uint32_t maxFound, uint32_t *found) {

  int xPtr = (blockIdx.x*blockDim.x) * 8;
  int yPtr = xPtr + 4 * blockDim.x;
  ComputeKeys(mode, keys + xPtr, keys + yPtr, NULL, (uint32_t *)pattern, maxFound, found);

}

__global__ void comp_keys_p2sh_pattern(uint32_t mode, prefix_t *pattern, uint64_t *keys, uint32_t maxFound, uint32_t *found) {

  int xPtr = (blockIdx.x*blockDim.x) * 8;
  int yPtr = xPtr + 4 * blockDim.x;
  ComputeKeysP2SH(mode, keys + xPtr, keys + yPtr, NULL, (uint32_t *)pattern, maxFound, found);

}

//#define FULLCHECK
#ifdef FULLCHECK

// ---------------------------------------------------------------------------------------

__global__ void chekc_mult(uint64_t *a, uint64_t *b, uint64_t *r) {

  _ModMult(r, a, b);
  r[4]=0;

}

// ---------------------------------------------------------------------------------------

__global__ void chekc_hash160(uint64_t *x, uint64_t *y, uint32_t *h) {

  _GetHash160(x, y, (uint8_t *)h);
  _GetHash160Comp(x, y, (uint8_t *)(h+5));

}

// ---------------------------------------------------------------------------------------

__global__ void get_endianness(uint32_t *endian) {

  uint32_t a = 0x01020304;
  uint8_t fb = *(uint8_t *)(&a);
  *endian = (fb==0x04);

}

#endif //FULLCHECK

// ---------------------------------------------------------------------------------------

using namespace std;

std::string toHex(unsigned char *data, int length) {

  string ret;
  char tmp[3];
  for (int i = 0; i < length; i++) {
    if (i && i % 4 == 0) ret.append(" ");
    sprintf(tmp, "%02x", (int)data[i]);
    ret.append(tmp);
  }
  return ret;

}

int _ConvertSMVer2Cores(int major, int minor) {

  // Defines for GPU Architecture types (using the SM version to determine
  // the # of cores per SM
  typedef struct {
    int SM;  // 0xMm (hexidecimal notation), M = SM Major version,
    // and m = SM minor version
    int Cores;
  } sSMtoCores;

  sSMtoCores nGpuArchCoresPerSM[] = {
      {0x20, 32}, // Fermi Generation (SM 2.0) GF100 class
      {0x21, 48}, // Fermi Generation (SM 2.1) GF10x class
      {0x30, 192},
      {0x32, 192},
      {0x35, 192},
      {0x37, 192},
      {0x50, 128},
      {0x52, 128},
      {0x53, 128},
      {0x60,  64},
      {0x61, 128},
      {0x62, 128},
      {0x70,  64},
      {0x72,  64},
      {0x75,  64},
      {0x80,  64},
      {0x86, 128},
      {-1, -1} };

  int index = 0;

  while (nGpuArchCoresPerSM[index].SM != -1) {
    if (nGpuArchCoresPerSM[index].SM == ((major << 4) + minor)) {
      return nGpuArchCoresPerSM[index].Cores;
    }

    index++;
  }

  return 0;

}

GPUEngine::GPUEngine(int nbThreadGroup, int nbThreadPerGroup, int gpuId, uint32_t maxFound,bool rekey) {

  // Initialise CUDA
  this->rekey = rekey;
  this->nbThreadPerGroup = nbThreadPerGroup;
  initialised = false;
  cudaError_t err;

  int deviceCount = 0;
  cudaError_t error_id = cudaGetDeviceCount(&deviceCount);

  if (error_id != cudaSuccess) {
    printf("GPUEngine: CudaGetDeviceCount %s %d\n", cudaGetErrorString(error_id),error_id);
    return;
  }

  // This function call returns 0 if there are no CUDA capable devices.
  if (deviceCount == 0) {
    printf("GPUEngine: There are no available device(s) that support CUDA\n");
    return;
  }

  err = cudaSetDevice(gpuId);
  if (err != cudaSuccess) {
    printf("GPUEngine: %s\n", cudaGetErrorString(err));
    return;
  }

  cudaDeviceProp deviceProp;
  cudaGetDeviceProperties(&deviceProp, gpuId);

  if (nbThreadGroup == -1)
    nbThreadGroup = deviceProp.multiProcessorCount * 8;

  this->nbThread = nbThreadGroup * nbThreadPerGroup;
  this->maxFound = maxFound;
  this->outputSize = (maxFound*ITEM_SIZE + 4);

  char tmp[512];
  sprintf(tmp,"GPU #%d %s (%dx%d cores) Grid(%dx%d)",
  gpuId,deviceProp.name,deviceProp.multiProcessorCount,
  _ConvertSMVer2Cores(deviceProp.major, deviceProp.minor),
                      nbThread / nbThreadPerGroup,
                      nbThreadPerGroup);
  deviceName = std::string(tmp);

  // Prefer L1 (We do not use __shared__ at all)
  err = cudaDeviceSetCacheConfig(cudaFuncCachePreferL1);
  if (err != cudaSuccess) {
    printf("GPUEngine: %s\n", cudaGetErrorString(err));
    return;
  }

  size_t stackSize = 49152;
  err = cudaDeviceSetLimit(cudaLimitStackSize, stackSize);
  if (err != cudaSuccess) {
    printf("GPUEngine: %s\n", cudaGetErrorString(err));
    return;
  }

  /*
  size_t heapSize = ;
  err = cudaDeviceSetLimit(cudaLimitMallocHeapSize, heapSize);
  if (err != cudaSuccess) {
    printf("Error: %s\n", cudaGetErrorString(err));
    exit(0);
  }

  size_t size;
  cudaDeviceGetLimit(&size, cudaLimitStackSize);
  printf("Stack Size %lld\n", size);
  cudaDeviceGetLimit(&size, cudaLimitMallocHeapSize);
  printf("Heap Size %lld\n", size);
  */

  // Allocate memory
  err = cudaMalloc((void **)&inputPrefix, _64K * 2);
  if (err != cudaSuccess) {
    printf("GPUEngine: Allocate prefix memory: %s\n", cudaGetErrorString(err));
    return;
  }
  err = cudaHostAlloc(&inputPrefixPinned, _64K * 2, cudaHostAllocWriteCombined | cudaHostAllocMapped);
  if (err != cudaSuccess) {
    printf("GPUEngine: Allocate prefix pinned memory: %s\n", cudaGetErrorString(err));
    return;
  }
  err = cudaMalloc((void **)&inputKey, nbThread * 32 * 2);
  if (err != cudaSuccess) {
    printf("GPUEngine: Allocate input memory: %s\n", cudaGetErrorString(err));
    return;
  }
  err = cudaHostAlloc(&inputKeyPinned, nbThread * 32 * 2, cudaHostAllocWriteCombined | cudaHostAllocMapped);
  if (err != cudaSuccess) {
    printf("GPUEngine: Allocate input pinned memory: %s\n", cudaGetErrorString(err));
    return;
  }
  err = cudaMalloc((void **)&outputPrefix, outputSize);
  if (err != cudaSuccess) {
    printf("GPUEngine: Allocate output memory: %s\n", cudaGetErrorString(err));
    return;
  }
  err = cudaHostAlloc(&outputPrefixPinned, outputSize, cudaHostAllocMapped);
  if (err != cudaSuccess) {
    printf("GPUEngine: Allocate output pinned memory: %s\n", cudaGetErrorString(err));
    return;
  }

  searchMode = SEARCH_COMPRESSED;
  searchType = P2PKH;
  initialised = true;
  pattern = "";
  hasPattern = false;
  inputPrefixLookUp = NULL;

}

int GPUEngine::GetGroupSize() {
  return GRP_SIZE;
}

void GPUEngine::PrintCudaInfo() {

  cudaError_t err;

  const char *sComputeMode[] =
  {
    "Multiple host threads",
    "Only one host thread",
    "No host thread",
    "Multiple process threads",
    "Unknown",
     NULL
  };

  int deviceCount = 0;
  cudaError_t error_id = cudaGetDeviceCount(&deviceCount);

  if (error_id != cudaSuccess) {
    printf("GPUEngine: CudaGetDeviceCount %s\n", cudaGetErrorString(error_id));
    return;
  }

  // This function call returns 0 if there are no CUDA capable devices.
  if (deviceCount == 0) {
    printf("GPUEngine: There are no available device(s) that support CUDA\n");
    return;
  }

  for(int i=0;i<deviceCount;i++) {

    err = cudaSetDevice(i);
    if (err != cudaSuccess) {
      printf("GPUEngine: cudaSetDevice(%d) %s\n", i, cudaGetErrorString(err));
      return;
    }

    cudaDeviceProp deviceProp;
    cudaGetDeviceProperties(&deviceProp, i);
    printf("GPU #%d %s (%dx%d cores) (Cap %d.%d) (%.1f MB) (%s)\n",
      i,deviceProp.name,deviceProp.multiProcessorCount,
      _ConvertSMVer2Cores(deviceProp.major, deviceProp.minor),
      deviceProp.major, deviceProp.minor,(double)deviceProp.totalGlobalMem/1048576.0,
      sComputeMode[deviceProp.computeMode]);

  }

}

GPUEngine::~GPUEngine() {

  cudaFree(inputKey);
  cudaFree(inputPrefix);
  if(inputPrefixLookUp) cudaFree(inputPrefixLookUp);
  cudaFreeHost(outputPrefixPinned);
  cudaFree(outputPrefix);

}

int GPUEngine::GetNbThread() {
  return nbThread;
}

void GPUEngine::SetSearchMode(int searchMode) {
  this->searchMode = searchMode;
}

void GPUEngine::SetSearchType(int searchType) {
  this->searchType = searchType;
}

void GPUEngine::SetPrefix(std::vector<prefix_t> prefixes) {

  memset(inputPrefixPinned, 0, _64K * 2);
  for(int i=0;i<(int)prefixes.size();i++)
    inputPrefixPinned[prefixes[i]]=1;

  // Fill device memory
  cudaMemcpy(inputPrefix, inputPrefixPinned, _64K * 2, cudaMemcpyHostToDevice);

  // We do not need the input pinned memory anymore
  cudaFreeHost(inputPrefixPinned);
  inputPrefixPinned = NULL;
  lostWarning = false;

  cudaError_t err = cudaGetLastError();
  if (err != cudaSuccess) {
    printf("GPUEngine: SetPrefix: %s\n", cudaGetErrorString(err));
  }

}

void GPUEngine::SetPattern(const char *pattern) {

  strcpy((char *)inputPrefixPinned,pattern);

  // Fill device memory
  cudaMemcpy(inputPrefix, inputPrefixPinned, _64K * 2, cudaMemcpyHostToDevice);

  // We do not need the input pinned memory anymore
  cudaFreeHost(inputPrefixPinned);
  inputPrefixPinned = NULL;
  lostWarning = false;

  cudaError_t err = cudaGetLastError();
  if (err != cudaSuccess) {
    printf("GPUEngine: SetPattern: %s\n", cudaGetErrorString(err));
  }

  hasPattern = true;

}

void GPUEngine::SetPrefix(std::vector<LPREFIX> prefixes, uint32_t totalPrefix) {

  // Allocate memory for the second level of lookup tables
  cudaError_t err = cudaMalloc((void **)&inputPrefixLookUp, (_64K+totalPrefix) * 4);
  if (err != cudaSuccess) {
    printf("GPUEngine: Allocate prefix lookup memory: %s\n", cudaGetErrorString(err));
    return;
  }
  err = cudaHostAlloc(&inputPrefixLookUpPinned, (_64K+totalPrefix) * 4, cudaHostAllocWriteCombined | cudaHostAllocMapped);
  if (err != cudaSuccess) {
    printf("GPUEngine: Allocate prefix lookup pinned memory: %s\n", cudaGetErrorString(err));
    return;
  }

  uint32_t offset = _64K;
  memset(inputPrefixPinned, 0, _64K * 2);
  memset(inputPrefixLookUpPinned, 0, _64K * 4);
  for (int i = 0; i < (int)prefixes.size(); i++) {
    int nbLPrefix = (int)prefixes[i].lPrefixes.size();
    inputPrefixPinned[prefixes[i].sPrefix] = (uint16_t)nbLPrefix;
    inputPrefixLookUpPinned[prefixes[i].sPrefix] = offset;
    for (int j = 0; j < nbLPrefix; j++) {
      inputPrefixLookUpPinned[offset++]=prefixes[i].lPrefixes[j];
    }
  }

  if (offset != (_64K+totalPrefix)) {
    printf("GPUEngine: Wrong totalPrefix %d!=%d!\n",offset- _64K, totalPrefix);
    return;
  }

  // Fill device memory
  cudaMemcpy(inputPrefix, inputPrefixPinned, _64K * 2, cudaMemcpyHostToDevice);
  cudaMemcpy(inputPrefixLookUp, inputPrefixLookUpPinned, (_64K+totalPrefix) * 4, cudaMemcpyHostToDevice);

  // We do not need the input pinned memory anymore
  cudaFreeHost(inputPrefixPinned);
  inputPrefixPinned = NULL;
  cudaFreeHost(inputPrefixLookUpPinned);
  inputPrefixLookUpPinned = NULL;
  lostWarning = false;

  err = cudaGetLastError();
  if (err != cudaSuccess) {
    printf("GPUEngine: SetPrefix (large): %s\n", cudaGetErrorString(err));
  }

}

bool GPUEngine::callKernel() {

  // Reset nbFound
  cudaMemset(outputPrefix,0,4);

  // Call the kernel (Perform STEP_SIZE keys per thread)
  if (searchType == P2SH) {

    if (hasPattern) {
      comp_keys_p2sh_pattern << < nbThread / nbThreadPerGroup, nbThreadPerGroup >> >
        (searchMode, inputPrefix, inputKey, maxFound, outputPrefix);
    } else {
      comp_keys_p2sh << < nbThread / nbThreadPerGroup, nbThreadPerGroup >> >
        (searchMode, inputPrefix, inputPrefixLookUp, inputKey, maxFound, outputPrefix);
    }

  } else {

    // P2PKH or BECH32
    if (hasPattern) {
      if (searchType == BECH32) {
        // TODO
        printf("GPUEngine: (TODO) BECH32 not yet supported with wildard\n");
        return false;
      }
      comp_keys_pattern << < nbThread / nbThreadPerGroup, nbThreadPerGroup >> >
        (searchMode, inputPrefix, inputKey, maxFound, outputPrefix);
    } else {
      if (searchMode == SEARCH_COMPRESSED) {
        comp_keys_comp << < nbThread / nbThreadPerGroup, nbThreadPerGroup >> >
          (inputPrefix, inputPrefixLookUp, inputKey, maxFound, outputPrefix);
      } else {
        comp_keys << < nbThread / nbThreadPerGroup, nbThreadPerGroup >> >
          (searchMode, inputPrefix, inputPrefixLookUp, inputKey, maxFound, outputPrefix);
      }
    }

  }

  cudaError_t err = cudaGetLastError();
  if (err != cudaSuccess) {
    printf("GPUEngine: Kernel: %s\n", cudaGetErrorString(err));
    return false;
  }
  return true;

}

bool GPUEngine::SetKeys(Point *p) {

  // Sets the starting keys for each thread
  // p must contains nbThread public keys
  for (int i = 0; i < nbThread; i+= nbThreadPerGroup) {
    for (int j = 0; j < nbThreadPerGroup; j++) {

      inputKeyPinned[8*i + j + 0* nbThreadPerGroup] = p[i + j].x.bits64[0];
      inputKeyPinned[8*i + j + 1* nbThreadPerGroup] = p[i + j].x.bits64[1];
      inputKeyPinned[8*i + j + 2* nbThreadPerGroup] = p[i + j].x.bits64[2];
      inputKeyPinned[8*i + j + 3* nbThreadPerGroup] = p[i + j].x.bits64[3];

      inputKeyPinned[8*i + j + 4* nbThreadPerGroup] = p[i + j].y.bits64[0];
      inputKeyPinned[8*i + j + 5* nbThreadPerGroup] = p[i + j].y.bits64[1];
      inputKeyPinned[8*i + j + 6* nbThreadPerGroup] = p[i + j].y.bits64[2];
      inputKeyPinned[8*i + j + 7* nbThreadPerGroup] = p[i + j].y.bits64[3];

    }
  }

  // Fill device memory
  cudaMemcpy(inputKey, inputKeyPinned, nbThread*32*2, cudaMemcpyHostToDevice);

  if (!rekey) {
    // We do not need the input pinned memory anymore
    cudaFreeHost(inputKeyPinned);
    inputKeyPinned = NULL;
  }

  cudaError_t err = cudaGetLastError();
  if (err != cudaSuccess) {
    printf("GPUEngine: SetKeys: %s\n", cudaGetErrorString(err));
  }

  return callKernel();

}

bool GPUEngine::Launch(std::vector<ITEM> &prefixFound,bool spinWait) {


  prefixFound.clear();

  // Get the result

  if(spinWait) {

    cudaMemcpy(outputPrefixPinned, outputPrefix, outputSize, cudaMemcpyDeviceToHost);

  } else {

    // Use cudaMemcpyAsync to avoid default spin wait of cudaMemcpy wich takes 100% CPU
    cudaEvent_t evt;
    cudaEventCreate(&evt);
    cudaMemcpyAsync(outputPrefixPinned, outputPrefix, 4, cudaMemcpyDeviceToHost, 0);
    cudaEventRecord(evt, 0);
    while (cudaEventQuery(evt) == cudaErrorNotReady) {
      // Sleep 1 ms to free the CPU
      Timer::SleepMillis(1);
    }
    cudaEventDestroy(evt);

  }

  cudaError_t err = cudaGetLastError();
  if (err != cudaSuccess) {
    printf("GPUEngine: Launch: %s\n", cudaGetErrorString(err));
    return false;
  }

  // Look for prefix found
  uint32_t nbFound = outputPrefixPinned[0];
  if (nbFound > maxFound) {
    // prefix has been lost
    if (!lostWarning) {
      printf("\nWarning, %d items lost\nHint: Search with less prefixes, less threads (-g) or increase maxFound (-m)\n", (nbFound - maxFound));
      lostWarning = true;
    }
    nbFound = maxFound;
  }

  // When can perform a standard copy, the kernel is eneded
  cudaMemcpy( outputPrefixPinned , outputPrefix , nbFound*ITEM_SIZE + 4 , cudaMemcpyDeviceToHost);

  for (uint32_t i = 0; i < nbFound; i++) {
    uint32_t *itemPtr = outputPrefixPinned + (i*ITEM_SIZE32 + 1);
    ITEM it;
    it.thId = itemPtr[0];
    int16_t *ptr = (int16_t *)&(itemPtr[1]);
    it.endo = ptr[0] & 0x7FFF;
    it.mode = (ptr[0]&0x8000)!=0;
    it.incr = ptr[1];
    it.hash = (uint8_t *)(itemPtr + 2);
    prefixFound.push_back(it);
  }

  return callKernel();

}

bool GPUEngine::CheckHash(uint8_t *h, vector<ITEM>& found,int tid,int incr,int endo, int *nbOK) {

  bool ok = true;

  // Search in found by GPU
  bool f = false;
  int l = 0;
  //printf("Search: %s\n", toHex(h,20).c_str());
  while (l < found.size() && !f) {
    f = ripemd160_comp_hash(found[l].hash, h);
    if (!f) l++;
  }
  if (f) {
    found.erase(found.begin() + l);
    *nbOK = *nbOK+1;
  } else {
    ok = false;
    printf("Expected item not found %s (thread=%d, incr=%d, endo=%d)\n",
      toHex(h, 20).c_str(),tid,incr,endo);
  }

  return ok;

}

bool GPUEngine::Check(Secp256K1 *secp) {

  uint8_t h[20];
  int i = 0;
  int j = 0;
  bool ok = true;

  if(!initialised)
    return false;

  printf("GPU: %s\n",deviceName.c_str());

#ifdef FULLCHECK

  // Get endianess
  get_endianness<<<1,1>>>(outputPrefix);
  cudaError_t err = cudaGetLastError();
  if (err != cudaSuccess) {
    printf("GPUEngine: get_endianness: %s\n", cudaGetErrorString(err));
    return false;
  }
  cudaMemcpy(outputPrefixPinned, outputPrefix,1,cudaMemcpyDeviceToHost);
  littleEndian = *outputPrefixPinned != 0;
  printf("Endianness: %s\n",(littleEndian?"Little":"Big"));

  // Check modular mult
  Int a;
  Int b;
  Int r;
  Int c;
  a.Rand(256);
  b.Rand(256);
  c.ModMulK1(&a,&b);
  memcpy(inputKeyPinned,a.bits64,BIFULLSIZE);
  memcpy(inputKeyPinned+5,b.bits64,BIFULLSIZE);
  cudaMemcpy(inputKey, inputKeyPinned, BIFULLSIZE*2, cudaMemcpyHostToDevice);
  chekc_mult<<<1,1>>>(inputKey,inputKey+5,(uint64_t *)outputPrefix);
  cudaMemcpy(outputPrefixPinned, outputPrefix, BIFULLSIZE, cudaMemcpyDeviceToHost);
  memcpy(r.bits64,outputPrefixPinned,BIFULLSIZE);

  if(!c.IsEqual(&r)) {
    printf("\nModular Mult wrong:\nR=%s\nC=%s\n",
    toHex((uint8_t *)r.bits64,BIFULLSIZE).c_str(),
    toHex((uint8_t *)c.bits64,BIFULLSIZE).c_str());
    return false;
  }

  // Check hash 160C
  uint8_t hc[20];
  Point pi;
  pi.x.Rand(256);
  pi.y.Rand(256);
  secp.GetHash160(pi, false, h);
  secp.GetHash160(pi, true, hc);
  memcpy(inputKeyPinned,pi.x.bits64,BIFULLSIZE);
  memcpy(inputKeyPinned+5,pi.y.bits64,BIFULLSIZE);
  cudaMemcpy(inputKey, inputKeyPinned, BIFULLSIZE*2, cudaMemcpyHostToDevice);
  chekc_hash160<<<1,1>>>(inputKey,inputKey+5,outputPrefix);
  cudaMemcpy(outputPrefixPinned, outputPrefix, 64, cudaMemcpyDeviceToHost);

  if(!ripemd160_comp_hash((uint8_t *)outputPrefixPinned,h)) {
    printf("\nGetHask160 wrong:\n%s\n%s\n",
    toHex((uint8_t *)outputPrefixPinned,20).c_str(),
    toHex(h,20).c_str());
    return false;
  }
  if (!ripemd160_comp_hash((uint8_t *)(outputPrefixPinned+5), hc)) {
    printf("\nGetHask160Comp wrong:\n%s\n%s\n",
      toHex((uint8_t *)(outputPrefixPinned + 5), 20).c_str(),
      toHex(h, 20).c_str());
    return false;
  }

#endif //FULLCHECK

  Point *p = new Point[nbThread];
  Point *p2 = new Point[nbThread];
  Int k;

  // Check kernel
  int nbFoundCPU[6];
  int nbOK[6];
  vector<ITEM> found;
  bool searchComp;

  if (searchMode == SEARCH_BOTH) {
    printf("Warning, Check function does not support BOTH_MODE, use either compressed or uncompressed");
    return true;
  }

  searchComp = (searchMode == SEARCH_COMPRESSED)?true:false;

  uint32_t seed = (uint32_t)time(NULL);
  printf("Seed: %u\n",seed);
  rseed(seed);
  memset(nbOK,0,sizeof(nbOK));
  memset(nbFoundCPU, 0, sizeof(nbFoundCPU));
  for (int i = 0; i < nbThread; i++) {
    k.Rand(256);
    p[i] = secp->ComputePublicKey(&k);
    // Group starts at the middle
    k.Add((uint64_t)GRP_SIZE/2);
    p2[i] = secp->ComputePublicKey(&k);
  }

  std::vector<prefix_t> prefs;
  prefs.push_back(0xFEFE);
  prefs.push_back(0x1234);
  SetPrefix(prefs);
  SetKeys(p2);
  double t0 = Timer::get_tick();
  Launch(found,true);
  double t1 = Timer::get_tick();
  Timer::printResult((char *)"Key", 6*STEP_SIZE*nbThread, t0, t1);

  //for (int i = 0; i < found.size(); i++) {
  //  printf("[%d]: thId=%d incr=%d\n", i, found[i].thId,found[i].incr);
  //  printf("[%d]: %s\n", i,toHex(found[i].hash,20).c_str());
  //}

  printf("ComputeKeys() found %d items , CPU check...\n",(int)found.size());

  Int beta,beta2;
  beta.SetBase16((char *)"7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee");
  beta2.SetBase16((char *)"851695d49a83f8ef919bb86153cbcb16630fb68aed0a766a3ec693d68e6afa40");

  // Check with CPU
  for (j = 0; (j<nbThread); j++) {
    for (i = 0; i < STEP_SIZE; i++) {

      Point pt,p1,p2;
      pt = p[j];
      p1 = p[j];
      p2 = p[j];
      p1.x.ModMulK1(&beta);
      p2.x.ModMulK1(&beta2);
      p[j] = secp->NextKey(p[j]);

      // Point and endo
      secp->GetHash160(P2PKH, searchComp, pt, h);
      prefix_t pr = *(prefix_t *)h;
      if (pr == 0xFEFE || pr == 0x1234) {
	      nbFoundCPU[0]++;
        ok &= CheckHash(h,found, j, i, 0, nbOK + 0);
      }
      secp->GetHash160(P2PKH, searchComp, p1, h);
      pr = *(prefix_t *)h;
      if (pr == 0xFEFE || pr == 0x1234) {
        nbFoundCPU[1]++;
        ok &= CheckHash(h, found, j, i, 1, nbOK + 1);
      }
      secp->GetHash160(P2PKH, searchComp, p2, h);
      pr = *(prefix_t *)h;
      if (pr == 0xFEFE || pr == 0x1234) {
        nbFoundCPU[2]++;
        ok &= CheckHash(h, found, j, i, 2, nbOK + 2);
      }

      // Symetrics
      pt.y.ModNeg();
      p1.y.ModNeg();
      p2.y.ModNeg();

      secp->GetHash160(P2PKH, searchComp, pt, h);
      pr = *(prefix_t *)h;
      if (pr == 0xFEFE || pr == 0x1234) {
        nbFoundCPU[3]++;
        ok &= CheckHash(h, found, j, -i, 0, nbOK + 3);
      }
      secp->GetHash160(P2PKH, searchComp, p1, h);
      pr = *(prefix_t *)h;
      if (pr == 0xFEFE || pr == 0x1234) {
        nbFoundCPU[4]++;
        ok &= CheckHash(h, found, j, -i, 1, nbOK + 4);
      }
      secp->GetHash160(P2PKH, searchComp, p2, h);
      pr = *(prefix_t *)h;
      if (pr == 0xFEFE || pr == 0x1234) {
        nbFoundCPU[5]++;
        ok &= CheckHash(h, found, j, -i, 2, nbOK + 5);
      }

    }
  }

  if (ok && found.size()!=0) {
    ok = false;
    printf("Unexpected item found !\n");
  }

  if( !ok ) {

    int nbF = nbFoundCPU[0] + nbFoundCPU[1] + nbFoundCPU[2] +
              nbFoundCPU[3] + nbFoundCPU[4] + nbFoundCPU[5];
    printf("CPU found %d items\n",nbF);

    printf("GPU: point   correct [%d/%d]\n", nbOK[0] , nbFoundCPU[0]);
    printf("GPU: endo #1 correct [%d/%d]\n", nbOK[1] , nbFoundCPU[1]);
    printf("GPU: endo #2 correct [%d/%d]\n", nbOK[2] , nbFoundCPU[2]);

    printf("GPU: sym/point   correct [%d/%d]\n", nbOK[3] , nbFoundCPU[3]);
    printf("GPU: sym/endo #1 correct [%d/%d]\n", nbOK[4] , nbFoundCPU[4]);
    printf("GPU: sym/endo #2 correct [%d/%d]\n", nbOK[5] , nbFoundCPU[5]);

    printf("GPU/CPU check Failed !\n");

  }

  if(ok) printf("GPU/CPU check OK\n");

  delete[] p;
  return ok;

}

// ── AB+CD 组合搜索 ─────────────────────────────────────────
// 独立于 GPUEngine 类，直接分配显存、上传表、启动 kernel

struct ABCDContext {
  uint64_t *d_ab;          // GPU 上的 AB 表
  uint64_t *d_cd;          // GPU 上的 CD 表
  uint8_t  *d_ab_hw;      // AB hw(c&d) AND，nullptr=不过滤
  uint8_t  *d_cd_hw;      // CD hw(a&b) AND，nullptr=不过滤
  uint8_t  *d_ab_hw2;     // AB hw(c^d) XOR，nullptr=不过滤
  uint8_t  *d_cd_hw2;     // CD hw(a^b) XOR，nullptr=不过滤
  uint8_t  *d_ab_sum_r13; // AB hw(r13) popcount，nullptr=不过滤
  uint8_t  *d_cd_sum_r14; // CD hw(r14) popcount
  uint8_t  *d_cd_sum_r15; // CD hw(r15) popcount
  uint32_t *d_out;         // GPU 上的输出缓冲
  uint32_t *h_out;         // CPU 端固定内存输出缓冲
  uint32_t abSize;
  uint32_t cdSize;
  uint32_t maxFound;
  prefix_t targetPrefix;
  int      optimal_nc;     // 自动适配的批量求逆大小
  int      block_size;     // kernel block 大小
};

// ── 根据 GPU 架构 + CD 表大小自动选择最优 ABCD_NC ────────────────────────
//
// 双维度优化：
// 1. L1 大小决定 NC 基准（_ModInvGroupedN 的 subp stack 命中率）
// 2. CD 表是否放得进 L2 决定 NC 微调方向：
//    ・CD < L2（小表）→ L2 可以缓存 CD，但 ModInv 频繁调用会污染 L2。
//      用更大 NC 减少 ModInv 调用频率，保护 L2 里的 CD 缓存。
//    ・CD >> L2（大表）→ CD 全走 DRAM，subp 同样走 DRAM。
//      用更小 NC 减小 subp 的 DRAM 带宽占用，降低与 CD 的冲突。
//
// T4 实测最优点：小 CD 表用 NC=160，大 CD 表用 NC=128
static int abcdSelectNC(int gpuId, uint32_t cdSize)
{
  cudaDeviceProp prop;
  cudaGetDeviceProperties(&prop, gpuId);

  int sm = prop.major * 10 + prop.minor;

  // 各架构 L1 cache 大小（PreferL1 模式，单位 KB）
  int l1_kb;
  if      (sm >= 120) l1_kb = 128;  // SM 12.0+: Blackwell 工作站/消费级
  else if (sm >= 100) l1_kb = 228;  // SM 10.0:  Blackwell 数据中心 (B100/B200)
  else if (sm >=  90) l1_kb = 256;  // SM 9.0:   Hopper (H100/H200)
  else if (sm >=  89) l1_kb = 128;  // SM 8.9:   Ada Lovelace (RTX 4090, RTX A6000 Ada)
  else if (sm >=  86) l1_kb = 128;  // SM 8.6:   Ampere 消费/专业 (RTX 3090, A10, RTX A1000)
  else if (sm >=  80) l1_kb = 192;  // SM 8.0:   Ampere 数据中心 (A100)
  else if (sm >=  75) l1_kb =  32;  // SM 7.5:   Turing (T4, RTX 2080)
  else if (sm >=  70) l1_kb = 128;  // SM 7.0:   Volta (V100)
  else                l1_kb =  32;  // 更老架构保守默认值

  // L2 大小（字节），CUDA DeviceProp 有直接字段
  int l2_bytes = prop.l2CacheSize;

  // CD 表字节数（每个 EC 点 64 字节）
  size_t cd_bytes = (size_t)cdSize * 64;

  // 基础 NC：L1_KB × 4，夹在 [128, 512]
  int nc_base = l1_kb * 4;
  if (nc_base <= 128) nc_base = 128;
  else if (nc_base <= 256) nc_base = 256;
  else nc_base = 512;

  // CD 表放得进 L2 时，适当增大 NC（减少 ModInv 对 L2 的污染）
  // 经验因子：1.25×（T4 实测 128→160 对小 CD 表有 +2% 提升）
  int nc;
  if (l2_bytes > 0 && cd_bytes < (size_t)l2_bytes) {
    // 小 CD 表：NC 增大 25%，让 L2 更专注缓存 CD
    nc = (int)(nc_base * 1.25f);
    // 对齐到 16 的倍数，不超过 nc_base × 2
    nc = (nc / 16) * 16;
    nc = nc > nc_base * 2 ? nc_base * 2 : nc;
  } else {
    // 大 CD 表：使用基础 NC（减小 DRAM 带宽竞争）
    nc = nc_base;
  }

  printf("GPU #%d %s (SM %d.%d): L1≈%dKB L2≈%dMB CD=%zuKB → ABCD_NC=%d, block=128\n",
         gpuId, prop.name, prop.major, prop.minor,
         l1_kb, l2_bytes/1024/1024,
         cd_bytes/1024, nc);
  return nc;
}

// 初始化：上传表数据、设置目标 hash、自动选 NC
ABCDContext *abcdSetup(
    uint64_t *abTable, uint8_t *abHwTable, uint8_t *abHwTable2, uint32_t abSize,
    uint64_t *cdTable, uint8_t *cdHwTable, uint8_t *cdHwTable2, uint32_t cdSize,
    uint8_t *targetH160, prefix_t targetPrefix,
    uint32_t maxFound,
    const std::vector<std::pair<int,int>> &hwPairs,
    const std::vector<std::pair<int,int>> &hwXorPairs,
    int forced_nc,
    uint8_t *abHwSumR13, uint8_t *cdHwSumR14, uint8_t *cdHwSumR15,
    const std::vector<std::pair<int,int>> &hwSumPairs,
    uint8_t hw_outer_sum)
{
  ABCDContext *ctx = new ABCDContext();
  ctx->abSize        = abSize;
  ctx->cdSize        = cdSize;
  ctx->maxFound      = maxFound;
  ctx->targetPrefix  = targetPrefix;
  ctx->block_size    = 128;
  ctx->d_ab_hw       = nullptr;
  ctx->d_cd_hw       = nullptr;
  ctx->d_ab_hw2      = nullptr;
  ctx->d_cd_hw2      = nullptr;
  ctx->d_ab_sum_r13  = nullptr;
  ctx->d_cd_sum_r14  = nullptr;
  ctx->d_cd_sum_r15  = nullptr;

  // 构建 hw 有效对表并上传到 GPU 常量内存
  // _hw_valid[hw_ab][hw_cd] = 1 表示该对有效
  if (!hwPairs.empty()) {
    uint8_t valid[17][17] = {};
    for (auto &p : hwPairs)
      if (p.first >= 0 && p.first <= 16 && p.second >= 0 && p.second <= 16)
        valid[p.first][p.second] = 1;
    cudaMemcpyToSymbol(_hw_valid, valid, sizeof(valid));
  }
  if (!hwXorPairs.empty()) {
    uint8_t valid2[17][17] = {};
    for (auto &p : hwXorPairs)
      if (p.first >= 0 && p.first <= 16 && p.second >= 0 && p.second <= 16)
        valid2[p.first][p.second] = 1;
    cudaMemcpyToSymbol(_hw_valid2, valid2, sizeof(valid2));
  }

  // 选最优 NC（forced_nc>0 时静默复用已知值，否则自动选并打印）
  int gpuId = 0;
  cudaGetDevice(&gpuId);
  ctx->optimal_nc = (forced_nc > 0) ? forced_nc : abcdSelectNC(gpuId, cdSize);

  // 上传 AB 表
  cudaMalloc(&ctx->d_ab, (size_t)abSize * 8 * sizeof(uint64_t));
  cudaMemcpy(ctx->d_ab, abTable, (size_t)abSize * 8 * sizeof(uint64_t), cudaMemcpyHostToDevice);

  // 上传 AB hw 表（AND / XOR 各可选）
  if (abHwTable) {
    cudaMalloc(&ctx->d_ab_hw, (size_t)abSize);
    cudaMemcpy(ctx->d_ab_hw, abHwTable, (size_t)abSize, cudaMemcpyHostToDevice);
  }
  if (abHwTable2) {
    cudaMalloc(&ctx->d_ab_hw2, (size_t)abSize);
    cudaMemcpy(ctx->d_ab_hw2, abHwTable2, (size_t)abSize, cudaMemcpyHostToDevice);
  }

  // 上传 CD 表
  cudaMalloc(&ctx->d_cd, (size_t)cdSize * 8 * sizeof(uint64_t));
  cudaMemcpy(ctx->d_cd, cdTable, (size_t)cdSize * 8 * sizeof(uint64_t), cudaMemcpyHostToDevice);

  // 上传 CD hw 表（AND / XOR 各可选）
  if (cdHwTable) {
    cudaMalloc(&ctx->d_cd_hw, (size_t)cdSize);
    cudaMemcpy(ctx->d_cd_hw, cdHwTable, (size_t)cdSize, cudaMemcpyHostToDevice);
  }
  if (cdHwTable2) {
    cudaMalloc(&ctx->d_cd_hw2, (size_t)cdSize);
    cudaMemcpy(ctx->d_cd_hw2, cdHwTable2, (size_t)cdSize, cudaMemcpyHostToDevice);
  }

  // 上传 sum 过滤表（hw(r13)/r14/r15 per entry，nullptr=不启用）
  if (abHwSumR13) {
    cudaMalloc(&ctx->d_ab_sum_r13, (size_t)abSize);
    cudaMemcpy(ctx->d_ab_sum_r13, abHwSumR13, (size_t)abSize, cudaMemcpyHostToDevice);
  }
  if (cdHwSumR14) {
    cudaMalloc(&ctx->d_cd_sum_r14, (size_t)cdSize);
    cudaMemcpy(ctx->d_cd_sum_r14, cdHwSumR14, (size_t)cdSize, cudaMemcpyHostToDevice);
  }
  if (cdHwSumR15) {
    cudaMalloc(&ctx->d_cd_sum_r15, (size_t)cdSize);
    cudaMemcpy(ctx->d_cd_sum_r15, cdHwSumR15, (size_t)cdSize, cudaMemcpyHostToDevice);
  }

  // 上传和有效对表到常量内存（33×33 字节）
  if (!hwSumPairs.empty()) {
    uint8_t sv[33][33] = {};
    for (auto &p : hwSumPairs)
      if (p.first >= 0 && p.first <= 32 && p.second >= 0 && p.second <= 32)
        sv[p.first][p.second] = 1;
    cudaMemcpyToSymbol(_sum_valid, sv, sizeof(sv));
  }

  // 上传当前外层 r16 的 popcount 到常量内存
  cudaMemcpyToSymbol(_hw_r16_sum, &hw_outer_sum, 1);

  // 上传目标 hash160 到常量内存（20 字节 = 5 uint32_t）
  cudaMemcpyToSymbol(_abcd_target, targetH160, 20);

  // 分配输出缓冲（1 + maxFound × ABCD_ITEM32 个 uint32_t）
  size_t outBytes = (1 + (size_t)maxFound * ABCD_ITEM32) * sizeof(uint32_t);
  cudaMalloc(&ctx->d_out, outBytes);
  cudaHostAlloc(&ctx->h_out, outBytes, cudaHostAllocDefault);

  return ctx;
}

int abcdGetNC(ABCDContext *ctx) { return ctx->optimal_nc; }

void abcdFree(ABCDContext *ctx) {
  cudaFree(ctx->d_ab);
  if (ctx->d_ab_hw)       cudaFree(ctx->d_ab_hw);
  if (ctx->d_ab_hw2)      cudaFree(ctx->d_ab_hw2);
  if (ctx->d_ab_sum_r13)  cudaFree(ctx->d_ab_sum_r13);
  cudaFree(ctx->d_cd);
  if (ctx->d_cd_hw)       cudaFree(ctx->d_cd_hw);
  if (ctx->d_cd_hw2)      cudaFree(ctx->d_cd_hw2);
  if (ctx->d_cd_sum_r14)  cudaFree(ctx->d_cd_sum_r14);
  if (ctx->d_cd_sum_r15)  cudaFree(ctx->d_cd_sum_r15);
  cudaFree(ctx->d_out);
  cudaFreeHost(ctx->h_out);
  delete ctx;
}

// ── 启动一批组合的检查，返回命中列表 ───────────────────────────────────────
// startCombo ~ startCombo+numCombos-1 的组合由本次 kernel 处理
bool abcdLaunch(ABCDContext *ctx, uint64_t startCombo, uint64_t numCombos,
                std::vector<std::tuple<uint32_t,uint32_t,uint8_t>> &found)
{
  found.clear();
  if (numCombos == 0) return true;

  cudaMemset(ctx->d_out, 0, sizeof(uint32_t));

  const int BLOCK        = ctx->block_size;
  const int COMBOS_PER_T = ctx->optimal_nc;
  uint64_t threads  = (numCombos + COMBOS_PER_T - 1) / COMBOS_PER_T;
  uint64_t gridSize = (threads + BLOCK - 1) / BLOCK;
  if (gridSize > 65535) gridSize = 65535;

#define _ABCD_LAUNCH(NC) \
  comp_keys_abcd<NC><<<(uint32_t)gridSize, BLOCK>>>( \
    ctx->d_ab, ctx->d_ab_hw, ctx->d_ab_hw2, ctx->d_ab_sum_r13, \
    ctx->d_cd, ctx->d_cd_hw, ctx->d_cd_hw2, ctx->d_cd_sum_r14, ctx->d_cd_sum_r15, \
    ctx->abSize, ctx->cdSize, \
    startCombo, ctx->targetPrefix, ctx->maxFound, ctx->d_out)

  // 根据运行时选出的 NC 分发到对应模板实例
  switch (ctx->optimal_nc) {
    case  80:  _ABCD_LAUNCH( 80); break;
    case  96:  _ABCD_LAUNCH( 96); break;
    case 112:  _ABCD_LAUNCH(112); break;
    case 128:  _ABCD_LAUNCH(128); break;
    case 160:  _ABCD_LAUNCH(160); break;
    case 192:  _ABCD_LAUNCH(192); break;
    case 256:  _ABCD_LAUNCH(256); break;
    case 512:
    default:   _ABCD_LAUNCH(512); break;
  }
#undef _ABCD_LAUNCH

  cudaError_t err = cudaGetLastError();
  if (err != cudaSuccess) {
    printf("ABCDKernel: %s\n", cudaGetErrorString(err));
    return false;
  }

  cudaDeviceSynchronize();
  size_t outBytes = (1 + (size_t)ctx->maxFound * ABCD_ITEM32) * sizeof(uint32_t);
  cudaMemcpy(ctx->h_out, ctx->d_out, outBytes, cudaMemcpyDeviceToHost);

  uint32_t count = ctx->h_out[0];
  if (count > ctx->maxFound) count = ctx->maxFound;

  for (uint32_t i = 0; i < count; i++) {
    uint32_t ab  = ctx->h_out[1 + i * ABCD_ITEM32 + 0];
    uint32_t cd  = ctx->h_out[1 + i * ABCD_ITEM32 + 1];
    uint8_t  var = (uint8_t)ctx->h_out[1 + i * ABCD_ITEM32 + 2];
    found.push_back({ab, cd, var});
  }
  return true;
}


