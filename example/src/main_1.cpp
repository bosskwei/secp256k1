#include <array>
#include <iostream>
#include <numeric>

#define CL_HPP_TARGET_OPENCL_VERSION 200
#include <CL/cl2.hpp>

int main() {
  std::vector<cl::Platform> all_platforms;
  cl::Platform::get(&all_platforms);
  if (all_platforms.size() == 0) {
    std::cout << "No platforms found. Check OpenCL installation!\n";
    exit(1);
  }
  cl::Platform default_platform = all_platforms[0];

  std::vector<cl::Device> all_devices;
  default_platform.getDevices(CL_DEVICE_TYPE_ALL, &all_devices);
  if (all_devices.size() == 0) {
    std::cout << "No devices found. Check OpenCL installation!\n";
    exit(1);
  }

  cl::Device default_device = all_devices[0];
  cl::Context context({default_device});

  cl::Program::Sources sources;
  std::string kernel_code = "   void kernel mul2(global int* A) {"
                            "       int gid = get_global_id(0);"
                            "       A[gid] = A[gid] * 2;"
                            "   }";
  sources.push_back({kernel_code.c_str(), kernel_code.length()});

  cl::Program program(context, sources);
  if (program.build({default_device}) != CL_SUCCESS) {
    std::cout << "Error building:\n"
              << program.getBuildInfo<CL_PROGRAM_BUILD_LOG>(default_device)
              << "\n";
    exit(1);
  }

  constexpr size_t array_size = 1024 * 512;
  std::array<cl_int, array_size> a;
  std::iota(begin(a), end(a), 2);

  cl::Buffer buffer_A(context, CL_MEM_READ_WRITE, sizeof(int) * a.size());
  cl::CommandQueue queue(context, default_device);

  if (queue.enqueueWriteBuffer(buffer_A, CL_TRUE, 0, sizeof(int) * a.size(),
                               a.data()) != CL_SUCCESS) {
    std::cout << "Failed to write memory\n";
    exit(1);
  }

  cl::Kernel kernel_add = cl::Kernel(program, "mul2");
  kernel_add.setArg(0, buffer_A);

  if (queue.enqueueNDRangeKernel(kernel_add, cl::NullRange,
                                 cl::NDRange(a.size()),
                                 cl::NullRange) != CL_SUCCESS) {
    std::cout << "Failed to enqueue kernel\n";
    exit(1);
  }

  if (queue.finish() != CL_SUCCESS) {
    std::cout << "Failed to finish kernel\n";
    exit(1);
  }

  std::cout << a[0] << std::endl;

  if (queue.enqueueReadBuffer(buffer_A, CL_TRUE, 0, sizeof(int) * a.size(),
                              a.data()) != CL_SUCCESS) {
    std::cout << "Failed to read result\n";
    exit(1);
  }

  std::cout << a[0] << std::endl;
}
