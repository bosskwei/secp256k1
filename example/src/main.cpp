// clang-format off
#include <cmath>
#include <array>
#include <deque>
#include <atomic>
#include <cassert>
#include <iostream>
#include <fstream>
#include <numeric>
#include <chrono>
#include <thread>
#include <set>
#include <unordered_set>

#define CL_HPP_ENABLE_EXCEPTIONS
#define CL_HPP_TARGET_OPENCL_VERSION 200
#include <CL/cl2.hpp>

#include <secp256k1/field.h>
#include <secp256k1/field_impl.h>
#include <secp256k1/scalar.h>
#include <secp256k1/scalar_impl.h>

#include <crypto/sha256.h>

#include "utils.hpp"
// clang-format on

class BaseModel {
public:
  BaseModel() {
    // init device
    device_ = getDevice();
    onDeviceReady();

    // init context
    context_ = cl::Context(device_);
    program_ = onKernelLoad();

    // ready
    queue_ = cl::CommandQueue(context_, device_);
    onKernel();
    queue_.finish();
    onResult();
  }

private:
  void onDeviceReady() {
    std::cout << "========== INFO ==========" << std::endl;
    printDevice(device_);
    std::cout << "==========================" << std::endl;
  }

  cl::Program onKernelLoad() {
    // read source
    std::string kernel_code = readTxtFull("../cl/kernel.cl");

    // compile
    cl::Program program(context_, kernel_code);
    try {
      program.build("-D __x86_64__");
    } catch (...) {
      std::cout << " Error building: "
                << program.getBuildInfo<CL_PROGRAM_BUILD_LOG>(device_)
                << std::endl;
      throw std::runtime_error("build error");
    }
    return program;
  }

  void onKernel() {
    // input
    auto hBuffer = linspace<cl_float, 1024>(0.0f, 1.0f);
    cl::Buffer tBuffer(context_, CL_MEM_READ_WRITE,
                       hBuffer->size() * sizeof(cl_float));
    queue_.enqueueWriteBuffer(tBuffer, CL_TRUE, 0,
                              hBuffer->size() * sizeof(cl_float),
                              hBuffer->data());

    // get kernel function
    cl::Kernel vectorAdd = cl::Kernel(program_, "vectorAdd");
    vectorAdd.setArg(0, tBuffer);
    queue_.enqueueNDRangeKernel(vectorAdd, cl::NullRange, cl::NDRange(1024));
  }

  void onResult() {
    // output
    auto hBuffer = linspace<cl_float, 1024>(0.0f, 1.0f);
    cl::Buffer tBuffer(context_, CL_MEM_READ_WRITE,
                       hBuffer->size() * sizeof(cl_float));
    queue_.enqueueReadBuffer(tBuffer, CL_TRUE, 0,
                             hBuffer->size() * sizeof(cl_float),
                             hBuffer->data());
  }

private:
  cl::Device device_;
  cl::Context context_;
  cl::Program program_;
  cl::CommandQueue queue_;
};

void matrixMul_cpu(const float *A, const float *B, float *C, size_t hA,
                   size_t wA, size_t hB, size_t wB) {
  if (wA != hB) {
    fprintf(stderr, "matrix error, wA: %ld, hB: %ld\n", wA, hB);
    return;
  }

  clock_t before = clock();
  for (size_t rA = 0; rA < hA; rA++) {
    for (size_t cB = 0; cB < wB; cB++) {
      //
      size_t iC = (rA * wB) + cB;
      C[iC] = 0.0f;

      //
      for (size_t offset = 0; offset < wA; offset++) {
        size_t iA = rA * wA + offset;
        size_t iB = (offset * wB) + cB;

        C[iC] += A[iA] * B[iB];
      }
    }
  }
  printf("cpu duration: %ld\n", clock() - before);
}

float *randMatrix(size_t height, size_t width) {
  size_t size = height * width * sizeof(float);
  float *dst = (float *)malloc(size);

  for (size_t i = 0; i < height * width; i++) {
    dst[i] = (float)rand() / RAND_MAX;
  }

  return dst;
}

bool allClose(float *A, float *B, size_t height, size_t width) {
  for (size_t row = 0; row < height; row++) {
    for (size_t col = 0; col < width; col++) {
      size_t idx = row * width + col;
      if (!std::isfinite(A[idx]) or !std::isfinite(B[idx])) {
        fprintf(stderr, "infinite error, idx: %ld\n", idx);
        return false;
      }
      if (std::fabs(A[idx] - B[idx]) > 1e-5) {
        fprintf(stderr, "inequal error, %f != %f, (x, y): (%ld, %ld)\n", A[idx],
                B[idx], col, row);
        return false;
      }
    }
  }
  return true;
}

void print_hex(const uint8_t *r, size_t n) {
  for (size_t i = 0; i < n; i += 1) {
    printf("%02x", r[i]);
  }
  printf("\n");
}

void print_hex(const std::vector<uint8_t> &a) {
  for (const auto &x : a) {
    printf("%02x", x);
  }
  printf("\n");
}

namespace {
typedef struct {
  secp256k1_fe x;
  secp256k1_fe y;
} secp256k1_ge;

void secp256k1_ge_mov(secp256k1_ge *r, const secp256k1_ge *a) {
  secp256k1_fe_mov(&(r->x), &(a->x));
  secp256k1_fe_mov(&(r->y), &(a->y));
}

int secp256k1_ge_equal(const secp256k1_ge *a, const secp256k1_ge *b) {
  return secp256k1_fe_equal(&(a->x), &(b->x)) &&
         secp256k1_fe_equal(&(a->y), &(b->y));
}

void secp256k1_ge_dbl(secp256k1_ge *r, const secp256k1_ge *a) {
  /*
   * # Calculate 3*x^2/(2*y)  modulus p
   * slope = 3 * pow(x, 2, self.M) * self.mod_inverse(2 * y)
   * x_sum = pow(slope, 2, self.M) - 2 * x
   * y_sum = slope * (x - x_sum) - y
   **/
  secp256k1_fe c, d, e;

  // c = 3 * pow(x, 2)
  secp256k1_fe_sqr(&c, &(a->x));
  secp256k1_fe_mul_int(&c, 3);

  // e = mod_inv(2 * y), free d
  secp256k1_fe_mov(&d, &(a->y));
  secp256k1_fe_mul_int(&d, 2);
  secp256k1_fe_inv(&e, &d);

  // d = slope = c * e, free c, e
  secp256k1_fe_mul(&d, &c, &e);

  // c = pow(slope, 2, self.M)
  secp256k1_fe_sqr(&c, &d);

  // r.x = c - 2 * x, free c
  secp256k1_fe_mov(&(r->x), &(a->x));
  secp256k1_fe_mul_int(&(r->x), 2);
  secp256k1_fe_normalize_weak(&(r->x));
  secp256k1_fe_negate(&(r->x), &(r->x), 1);
  secp256k1_fe_add(&(r->x), &c);
  secp256k1_fe_normalize(&(r->x));

  // c = slope * (x - r.x)
  secp256k1_fe_negate(&e, &(r->x), 1);
  secp256k1_fe_add(&e, &(a->x));
  secp256k1_fe_mul(&c, &e, &d);
  secp256k1_fe_normalize_weak(&c);

  // r.y = c - y
  secp256k1_fe_negate(&(r->y), &(a->y), 1);
  secp256k1_fe_add(&(r->y), &c);
  secp256k1_fe_normalize(&(r->y));
}

void test_secp256k1_ge_dlb() {
  uint8_t n_ax[32] = {0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
                      0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
                      0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
                      0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98};
  uint8_t n_ay[32] = {0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
                      0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
                      0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
                      0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8};
  uint8_t n_tx[32] = {0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d,
                      0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0, 0x7c, 0xd8,
                      0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7,
                      0xab, 0xac, 0x09, 0xb9, 0x5c, 0x70, 0x9e, 0xe5};
  uint8_t n_ty[32] = {0x1a, 0xe1, 0x68, 0xfe, 0xa6, 0x3d, 0xc3, 0x39,
                      0xa3, 0xc5, 0x84, 0x19, 0x46, 0x6c, 0xea, 0xee,
                      0xf7, 0xf6, 0x32, 0x65, 0x32, 0x66, 0xd0, 0xe1,
                      0x23, 0x64, 0x31, 0xa9, 0x50, 0xcf, 0xe5, 0x2a};

  secp256k1_ge r, t, a;
  secp256k1_fe_set_b32(&(a.x), n_ax);
  secp256k1_fe_set_b32(&(a.y), n_ay);
  secp256k1_fe_set_b32(&(t.x), n_tx);
  secp256k1_fe_set_b32(&(t.y), n_ty);

  secp256k1_ge_dbl(&r, &a);

  assert(secp256k1_fe_equal(&(r.x), &(t.x)));
  assert(secp256k1_fe_equal(&(r.y), &(t.y)));
}

void secp256k1_ge_add(secp256k1_ge *r, const secp256k1_ge *a,
                      const secp256k1_ge *b) {
  /*
   * # calculate (y1-y2)/(x1-x2)  modulus p
   * slope = (y1 - y2) * self.mod_inverse(x1 - x2)
   * x_sum = pow(slope, 2, self.M) - (x1 + x2)
   * y_sum = slope * (x1 - x_sum) - y1
   * return x_sum % self.M, y_sum % self.M
   **/
  /*
  if (secp256k1_fe_equal(&(a->x), &(b->x))) {
    assert(0 && "not implemented, divided by zero");
    // secp256k1_ge_dbl(r, a);
    return;
  }
  */

  secp256k1_fe c, d, e;

  // c = y1 - y2
  secp256k1_fe_negate(&c, &(b->y), 1);
  secp256k1_fe_add(&c, &(a->y));

  // d = x1 - x2
  secp256k1_fe_negate(&d, &(b->x), 1);
  secp256k1_fe_add(&d, &(a->x));

  // d = slope = c * mod_inv(d), free c, e
  secp256k1_fe_inv(&e, &d);
  secp256k1_fe_mul(&d, &c, &e);

  // e = pow(d, 2)
  secp256k1_fe_sqr(&e, &d);

  // c = x1 + x2
  secp256k1_fe_mov(&c, &(a->x));
  secp256k1_fe_add(&c, &(b->x));
  secp256k1_fe_normalize_weak(&c);

  // r.x = e - c, free c
  secp256k1_fe_negate(&(r->x), &c, 1);
  secp256k1_fe_add(&(r->x), &e);
  secp256k1_fe_normalize(&(r->x));

  // c = x1 - r.x
  secp256k1_fe_negate(&c, &(r->x), 1);
  secp256k1_fe_add(&c, &(a->x));

  // r.y = slope * c - y1
  secp256k1_fe_mul(&(r->y), &d, &c);
  secp256k1_fe_negate(&c, &(a->y), 1);
  secp256k1_fe_add(&(r->y), &c);
  secp256k1_fe_normalize(&(r->y));
}

void test_secp256k1_ge_add() {
  uint8_t n_ax[32] = {0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
                      0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
                      0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
                      0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98};
  uint8_t n_ay[32] = {0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
                      0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
                      0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
                      0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8};
  uint8_t n_bx[32] = {0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d,
                      0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0, 0x7c, 0xd8,
                      0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7,
                      0xab, 0xac, 0x09, 0xb9, 0x5c, 0x70, 0x9e, 0xe5};
  uint8_t n_by[32] = {0x1a, 0xe1, 0x68, 0xfe, 0xa6, 0x3d, 0xc3, 0x39,
                      0xa3, 0xc5, 0x84, 0x19, 0x46, 0x6c, 0xea, 0xee,
                      0xf7, 0xf6, 0x32, 0x65, 0x32, 0x66, 0xd0, 0xe1,
                      0x23, 0x64, 0x31, 0xa9, 0x50, 0xcf, 0xe5, 0x2a};
  uint8_t n_tx[32] = {0xf9, 0x30, 0x8a, 0x01, 0x92, 0x58, 0xc3, 0x10,
                      0x49, 0x34, 0x4f, 0x85, 0xf8, 0x9d, 0x52, 0x29,
                      0xb5, 0x31, 0xc8, 0x45, 0x83, 0x6f, 0x99, 0xb0,
                      0x86, 0x01, 0xf1, 0x13, 0xbc, 0xe0, 0x36, 0xf9};
  uint8_t n_ty[32] = {0x38, 0x8f, 0x7b, 0x0f, 0x63, 0x2d, 0xe8, 0x14,
                      0x0f, 0xe3, 0x37, 0xe6, 0x2a, 0x37, 0xf3, 0x56,
                      0x65, 0x00, 0xa9, 0x99, 0x34, 0xc2, 0x23, 0x1b,
                      0x6c, 0xb9, 0xfd, 0x75, 0x84, 0xb8, 0xe6, 0x72};
  uint8_t n_rx[32] = {0}, n_ry[32] = {0};

  secp256k1_ge r, t, a, b;
  secp256k1_fe_set_b32(&(a.x), n_ax);
  secp256k1_fe_set_b32(&(a.y), n_ay);
  secp256k1_fe_set_b32(&(b.x), n_bx);
  secp256k1_fe_set_b32(&(b.y), n_by);
  secp256k1_fe_set_b32(&(t.x), n_tx);
  secp256k1_fe_set_b32(&(t.y), n_ty);

  secp256k1_ge_add(&r, &a, &b);

  assert(secp256k1_fe_equal(&(r.x), &(t.x)));
  assert(secp256k1_fe_equal(&(r.y), &(t.y)));
}

void bench_secp256k1_ge_add() {
  int n = 1e3;

  auto begin = std::chrono::high_resolution_clock::now();
  for (int i = 0; i < n; i += 1) {
    test_secp256k1_ge_add();
  }
  auto finish = std::chrono::high_resolution_clock::now();
  auto diff = finish - begin;
  std::cout << "bench_secp256k1_ge_add(): time = ";
  std::cout << double(std::chrono::duration_cast<std::chrono::nanoseconds>(diff)
                          .count()) /
                   double(1e9) / double(n)
            << " sec/op, ";
  std::cout << double(1e9 * n) /
                   double(std::chrono::duration_cast<std::chrono::nanoseconds>(
                              diff)
                              .count())
            << " op/sec" << std::endl;
}

void secp256k1_ecmult(secp256k1_ge *r, const secp256k1_ge *a,
                      const secp256k1_scalar *k) {
  /*
   * while (k):
   *   r +=  scale if k & 0x01 else 0
   *   scale *= 2
   *   k >>= 1
   **/
  secp256k1_ge base;
  secp256k1_ge_mov(&base, a);

  secp256k1_scalar cond;
  secp256k1_scalar_mov(&cond, k);

#ifdef VERIFY
  if (secp256k1_scalar_is_zero(&cond)) {
    assert(0 && "wrong private key");
  }
#endif

  /*
  // first
  while (!secp256k1_scalar_is_odd(&cond)) {
    secp256k1_ge t;
    secp256k1_ge_dbl(&t, &base);
    secp256k1_ge_mov(&base, &t);
    secp256k1_scalar_shr_int(&cond, 1);
  }
  secp256k1_ge_mov(r, &base);
  secp256k1_ge t;
  secp256k1_ge_dbl(&t, &base);
  secp256k1_ge_mov(&base, &t);
  secp256k1_scalar_shr_int(&cond, 1);

  // repeat
  while (!secp256k1_scalar_is_zero(&cond)) {
    if (secp256k1_scalar_is_odd(&cond)) {
      secp256k1_ge t;
      secp256k1_ge_add(&t, r, &base);
      secp256k1_ge_mov(r, &t);
    }
    secp256k1_ge t;
    secp256k1_ge_dbl(&t, &base);
    secp256k1_ge_mov(&base, &t);
    secp256k1_scalar_shr_int(&cond, 1);
  }
  */

  // loop in loop
  int first = 1;
  while (!secp256k1_scalar_is_zero(&cond)) {
    if (secp256k1_scalar_is_odd(&cond)) {
      if (first) {
        first = 0;
        secp256k1_ge_mov(r, &base);
      } else {
        secp256k1_ge t;
        secp256k1_ge_add(&t, r, &base);
        secp256k1_ge_mov(r, &t);
      }
    }
    secp256k1_ge t;
    secp256k1_ge_dbl(&t, &base);
    secp256k1_ge_mov(&base, &t);
    secp256k1_scalar_shr_int(&cond, 1);
  }
}

void test_secp256k1_ecmult() {
  uint8_t n_gx[32] = {0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
                      0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
                      0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
                      0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98};
  uint8_t n_gy[32] = {0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
                      0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
                      0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
                      0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8};
  uint8_t n_tx[32] = {0x71, 0xee, 0x91, 0x8b, 0xc1, 0x9b, 0xb5, 0x66,
                      0xe3, 0xa5, 0xf1, 0x2c, 0x0c, 0xd0, 0xde, 0x62,
                      0x0b, 0xec, 0x10, 0x25, 0xda, 0x6e, 0x98, 0x95,
                      0x13, 0x55, 0xeb, 0xbd, 0xe8, 0x72, 0x7b, 0xe3};
  uint8_t n_ty[32] = {0x37, 0xb3, 0x65, 0x0e, 0xfa, 0xd4, 0x19, 0x0b,
                      0x73, 0x28, 0xb1, 0x15, 0x63, 0x04, 0xf2, 0xe9,
                      0xe2, 0x3d, 0xbb, 0x7f, 0x2d, 0xa5, 0x09, 0x99,
                      0xdd, 0xe5, 0x0e, 0xa7, 0x3b, 0x4c, 0x26, 0x88};
  uint8_t n_private[32] = {0xf8, 0xef, 0x38, 0x0d, 0x6c, 0x05, 0x11, 0x6d,
                           0xbe, 0xd7, 0x8b, 0xfd, 0xd6, 0xe6, 0x62, 0x5e,
                           0x57, 0x42, 0x6a, 0xf9, 0xa0, 0x82, 0xb8, 0x1c,
                           0x2f, 0xa2, 0x7b, 0x06, 0x98, 0x4c, 0x11, 0xf3};
  uint8_t n_rx[32] = {0}, n_ry[32] = {0};

  secp256k1_scalar k;
  secp256k1_ge r, t, g;
  secp256k1_fe_set_b32(&(g.x), n_gx);
  secp256k1_fe_set_b32(&(g.y), n_gy);
  secp256k1_scalar_set_b32(&k, n_private);
  secp256k1_fe_set_b32(&(t.x), n_tx);
  secp256k1_fe_set_b32(&(t.y), n_ty);

  secp256k1_ecmult(&r, &g, &k);

  assert(secp256k1_fe_equal(&(r.x), &(t.x)));
  assert(secp256k1_fe_equal(&(r.y), &(t.y)));
}

void bench_secp256k1_ecmult() {
  int n = 1e2;

  auto begin = std::chrono::high_resolution_clock::now();
  for (int i = 0; i < n; i += 1) {
    test_secp256k1_ecmult();
  }
  auto finish = std::chrono::high_resolution_clock::now();
  auto diff = finish - begin;
  std::cout << "bench_secp256k1_ecmult(): time = ";
  std::cout << double(std::chrono::duration_cast<std::chrono::nanoseconds>(diff)
                          .count()) /
                   double(1e9) / double(n)
            << " sec/op, ";
  std::cout << double(1e9 * n) /
                   double(std::chrono::duration_cast<std::chrono::nanoseconds>(
                              diff)
                              .count())
            << " op/sec" << std::endl;
}

void test_self_validate() {
  //
  uint32_t n_offset = 0;
  secp256k1_scalar offset;
  {
    auto clock = std::chrono::system_clock::now().time_since_epoch();
    std::default_random_engine generator(clock.count());
    std::uniform_int_distribution<uint32_t> distribution(0x0001, 0xFFFF);
    n_offset = distribution(generator);
  }
  secp256k1_scalar_set_int(&offset, n_offset);

  // random private key
  secp256k1_scalar k1, k2;
  uint8_t n_private[32] = {0};
  {
    auto clock = std::chrono::system_clock::now().time_since_epoch();
    std::default_random_engine generator(clock.count());
    std::uniform_int_distribution<uint8_t> distribution(0x00, 0xFF);
    for (size_t i = 0; i < 32; i += 1) {
      n_private[i] = distribution(generator);
    }
  }
  secp256k1_scalar_set_b32(&k1, n_private);
  secp256k1_scalar_add(&k2, &k1, &offset);

  // run
  secp256k1_ge r1, r2, g;
  uint8_t n_gx[32] = {0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
                      0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
                      0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
                      0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98};
  uint8_t n_gy[32] = {0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
                      0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
                      0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
                      0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8};
  secp256k1_fe_set_b32(&(g.x), n_gx);
  secp256k1_fe_set_b32(&(g.y), n_gy);
  secp256k1_ecmult(&r1, &g, &k1);
  for (uint32_t i = 0; i < n_offset; i += 1) {
    secp256k1_ge t;
    secp256k1_ge_add(&t, &g, &r1);
    secp256k1_ge_mov(&r1, &t);
  }
  secp256k1_ecmult(&r2, &g, &k2);
  assert(secp256k1_ge_equal(&r1, &r2));
}

static std::atomic<size_t> cnt(0);

void test_self_validate_infinite() {
  for (size_t i = 0;; i += 1) {
    test_self_validate();
    cnt += 1;
  }
}

void test_self_validate_infinite_multithread() {
  std::vector<std::thread> works;
  for (std::size_t i = 0; i < 16; i += 1) {
    works.emplace_back(test_self_validate_infinite);
  }
  works.emplace_back([]() {
    while (true) {
      fprintf(stdout, "\33[2K\r%ld Passed", cnt.load());
      fflush(stdout);
      std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
  });
  for (auto &work : works) {
    work.join();
  }
}

void generate_ripemd160hash(uint8_t n_h160[20],
                            const secp256k1_ge *public_key) {
  /**
    * def generate_ripemd160hash(self, public_key):
        x, y = public_key
        s = b'\x04' + x.to_bytes(length=32, byteorder='big') + \
            y.to_bytes(length=32, byteorder='big')

        h = hashlib.sha256()
        h.update(s)
        r = h.digest()

        h = hashlib.new("ripemd160")
        h.update(r)
        r = h.digest()
        return r
  */
  uint8_t buffer[65] = {0x04};
  secp256k1_fe_get_b32(buffer + 1, &(public_key->x));
  secp256k1_fe_get_b32(buffer + 1 + 32, &(public_key->y));
  //
  SHA256 sha256;
  sha256.Write(buffer, 65);
  sha256.Finalize(buffer);
  //
  RIPEMD160 ripemd160;
  ripemd160.Write(buffer, 32);
  ripemd160.Finalize(n_h160);
}

void test_ripemd160hash() {
  uint8_t n_ax[32] = {0x71, 0xee, 0x91, 0x8b, 0xc1, 0x9b, 0xb5, 0x66,
                      0xe3, 0xa5, 0xf1, 0x2c, 0x0c, 0xd0, 0xde, 0x62,
                      0x0b, 0xec, 0x10, 0x25, 0xda, 0x6e, 0x98, 0x95,
                      0x13, 0x55, 0xeb, 0xbd, 0xe8, 0x72, 0x7b, 0xe3};
  uint8_t n_ay[32] = {0x37, 0xb3, 0x65, 0x0e, 0xfa, 0xd4, 0x19, 0x0b,
                      0x73, 0x28, 0xb1, 0x15, 0x63, 0x04, 0xf2, 0xe9,
                      0xe2, 0x3d, 0xbb, 0x7f, 0x2d, 0xa5, 0x09, 0x99,
                      0xdd, 0xe5, 0x0e, 0xa7, 0x3b, 0x4c, 0x26, 0x88};
  uint8_t n_h160t[20] = {0x01, 0x50, 0x65, 0x1a, 0xd9, 0x13, 0x30,
                         0xad, 0x19, 0x13, 0xcb, 0x04, 0x91, 0x28,
                         0x17, 0xa8, 0xd9, 0x80, 0xc9, 0xad};
  secp256k1_ge a;
  secp256k1_fe_set_b32(&(a.x), n_ax);
  secp256k1_fe_set_b32(&(a.y), n_ay);
  //
  uint8_t n_h160r[20] = {0};
  generate_ripemd160hash(n_h160r, &a);
  for (size_t i = 0; i < 20; i += 1) {
    assert(n_h160r[i] == n_h160t[i]);
  }
}

std::vector<uint8_t> hex_to_bytes(const std::string &hex) {
  std::vector<uint8_t> bytes;
  for (unsigned int i = 0; i < hex.length(); i += 2) {
    std::string byteString = hex.substr(i, 2);
    uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
    bytes.push_back(byte);
  }
  return bytes;
}

std::vector<uint8_t> to_vector(const uint8_t *data, size_t n) {
  std::vector<uint8_t> bytes;
  for (unsigned int i = 0; i < n; i += 1) {
    bytes.push_back(data[i]);
  }
  return bytes;
}

std::set<std::vector<uint8_t>> build_search_table() {
  std::set<std::vector<uint8_t>> table;
  std::ifstream infile("/disk2/guiyuntao/.data/h160_top500000.txt");
  if (not infile.is_open()) {
    throw std::runtime_error("file not opened");
  }
  std::string line;
  while (std::getline(infile, line)) {
    assert(line.length() == 40);
    std::vector<uint8_t> h160bytes = hex_to_bytes(line);
    assert(h160bytes.size() == 20);
    table.insert(h160bytes);
    //
    // std::cout << line << std::endl;
    // print_hex(h160bytes);
    break;
  }

  auto search =
      table.find(hex_to_bytes("4616b2c00cfc401861b98e86ccce47a683ed63da"));
  if (search != table.end()) {
    // std::cout << "build_search_table() ok" << std::endl;
  } else {
    std::cout << "build_search_table() error" << std::endl;
  }

  return table;
}

void start_task() {
  // improve random level
  uint32_t seed;
  {
    auto clock = std::chrono::system_clock::now().time_since_epoch();
    std::default_random_engine generator(clock.count());
    std::uniform_int_distribution<uint32_t> distribution(0x00000100,
                                                         0xFFFFFFFF);
    seed = distribution(generator);
    seed = (seed << 8) >> 16;
    seed = seed * seed;
  }

  // generage key
  secp256k1_scalar k;
  uint8_t n_private[32] = {0};
  {
    std::default_random_engine generator(seed);
    std::uniform_int_distribution<uint8_t> distribution(0x00, 0xFF);
    for (size_t i = 0; i < 32; i += 1) {
      n_private[i] = distribution(generator);
    }
  }
  printf("at: ");
  print_hex(n_private, 32);
  secp256k1_scalar_set_b32(&k, n_private);

  // secp256k1 point
  uint8_t n_gx[32] = {0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
                      0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
                      0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
                      0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98};
  uint8_t n_gy[32] = {0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
                      0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
                      0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
                      0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8};
  uint8_t n_rx[32] = {0}, n_ry[32] = {0};
  secp256k1_ge r, g;
  secp256k1_fe_set_b32(&(g.x), n_gx);
  secp256k1_fe_set_b32(&(g.y), n_gy);

  //
  std::set<std::vector<uint8_t>> table = build_search_table();
  secp256k1_ecmult(&r, &g, &k);
  for (size_t i = 0; i < 0xFFFFFFFF; i += 1) {
    //
    cnt += 1;

    // gen h160
    uint8_t n_h160[20] = {0};
    generate_ripemd160hash(n_h160, &r);

    // do search
    auto search = table.find(to_vector(n_h160, 20));
    if (search != table.end()) {
      std::cout << "Found:" << std::endl;
      print_hex(to_vector(n_h160, 20));
      throw std::runtime_error("Exit Success!");
    }

    // next epoch
    secp256k1_ge t;
    secp256k1_ge_add(&t, &g, &r);
    secp256k1_ge_mov(&r, &t);
  }
}

void start_task_infinite() {
  for (size_t i = 0; i < 1024; i += 1) {
    start_task();
  }
}

} // namespace

int main() {
  // ----- TODO -----
  // 1. Simplify scalar_impl.h, remove useless functions
  // 2. Refine project directory (cpp_test, py_test ...)
  // 3. Impl ripemd160 and sha256
  // 4. Add full test
  // 5. Add test slot for search table
  // 6. Refine code
  // ----------------
  test_secp256k1_ge_dlb();
  test_secp256k1_ge_add();
  test_secp256k1_ecmult();
  bench_secp256k1_ge_add();
  bench_secp256k1_ecmult();
  test_self_validate();
  test_ripemd160hash();
  printf("all test passed\n");
  // ----------------
  std::vector<std::thread> works;
  for (std::size_t i = 0; i < 16; i += 1) {
    works.emplace_back(start_task_infinite);
  }
  works.emplace_back([]() {
    while (true) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1000));
      fprintf(stdout, "\33[2K\r%ld Passed ", cnt.load());
      fflush(stdout);
      std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
  });
  for (auto &work : works) {
    work.join();
  }
  // ----------------
  return 0;
}
