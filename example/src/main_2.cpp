#include <array>
#include <iostream>
#include <numeric>

#define CL_HPP_ENABLE_EXCEPTIONS
#define CL_HPP_TARGET_OPENCL_VERSION 200
#include <CL/cl2.hpp>

#include "utils.hpp"


class ExecutionModel {
public:
  ExecutionModel() {
    cl::Device default_device = getDevice();
  }
};

class ExecutionHandler {
private:
};


int main() {
  // init device
  cl::Device default_device = getDevice();
  cl::Context context({default_device});
  
  // print info
  std::cout << "========== INFO ==========" << std::endl;
  printDevice(default_device);
  std::cout << "==========================" << std::endl;

  // read source
  std::string kernel_code = readTxtFull("../cl/kernel.cl");

  // compile
  cl::Program program(context, kernel_code);
  try {
    program.build();
  }
  catch (...) {
    std::cout << " Error building: "
              << program.getBuildInfo<CL_PROGRAM_BUILD_LOG>(default_device)
              << std::endl;
    throw std::runtime_error("build error");
  }

  // command
  cl::CommandQueue queue(context, default_device);

  // buffer
  std::array<cl_float, 64 * 1024> first = {0};
  linespace<cl_float, 64 * 1024>(first, 0.0, 1.0);
  cl::Buffer bufferA(context, CL_MEM_READ_WRITE, first.size() * sizeof(cl_float));

  // before
  std::cout << first[0] << " " << first[1] << " " << first[2] << std::endl;

  // input
  queue.enqueueWriteBuffer(bufferA, CL_TRUE, 0, first.size() * sizeof(cl_float), first.data());

  // get kernel
  cl::Kernel vectorAdd = cl::Kernel(program, "vectorAdd");
  vectorAdd.setArg(0, bufferA);
  queue.enqueueNDRangeKernel(vectorAdd, cl::NullRange, cl::NDRange(1024));

  // wait
  queue.finish();

  // output
  queue.enqueueReadBuffer(bufferA, CL_TRUE, 0, first.size() * sizeof(cl_float), first.data());

  // after
  std::cout << first[0] << " " << first[1] << " " << first[2] << std::endl;
}