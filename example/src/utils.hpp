#include <CL/cl2.hpp>
#include <array>
#include <fstream>
#include <iostream>
#include <memory>
#include <random>
#include <string>
#include <unordered_map>

template <typename... Args>
std::string stringFormat(const std::string &format, Args... args) {
  size_t size = std::snprintf(nullptr, 0, format.c_str(), args...) +
                1; // Extra space for '\0'
  std::unique_ptr<char[]> buf(new char[size]);
  std::snprintf(buf.get(), size, format.c_str(), args...);
  return std::string(buf.get(),
                     buf.get() + size - 1); // We don't want the '\0' inside
}

void printPlatforms() {
  // init platforms
  std::vector<cl::Platform> platforms;
  cl::Platform::get(&platforms);
  std::cout << "Finding platforms: " << platforms.size() << std::endl;

  // walk through platforms
  for (auto &platform : platforms) {
    std::cout << "CL_PLATFORM_NAME: " << platform.getInfo<CL_PLATFORM_NAME>()
              << std::endl;
    std::cout << "CL_PLATFORM_VENDOR: "
              << platform.getInfo<CL_PLATFORM_VENDOR>() << std::endl;
    std::cout << "CL_PLATFORM_PROFILE: "
              << platform.getInfo<CL_PLATFORM_PROFILE>() << std::endl;
    std::cout << "CL_PLATFORM_VERSION: "
              << platform.getInfo<CL_PLATFORM_VERSION>() << std::endl;
    std::cout << std::endl;
  }
}

template <typename T> std::string beautyMem(T memSize) {
  if (memSize > 1024 * 1024 * 1024) {
    memSize /= 1024 * 1024 * 1024;
    return stringFormat("%d GB", memSize);
  } else if (memSize > 1024 * 1024) {
    memSize /= 1024 * 1024;
    return stringFormat("%d MB", memSize);
  } else if (memSize > 1024) {
    memSize /= 1024;
    return stringFormat("%d KB", memSize);
  } else {
    return stringFormat("%d B", memSize);
  }
}

std::string beautyDevType(cl_device_type type) {
  std::unordered_map<cl_device_type, std::string> table = {
      {CL_DEVICE_TYPE_DEFAULT, "DEVICE_TYPE_DEFAULT"},
      {CL_DEVICE_TYPE_CPU, "DEVICE_TYPE_CPU"},
      {CL_DEVICE_TYPE_GPU, "DEVICE_TYPE_GPU"},
      {CL_DEVICE_TYPE_ACCELERATOR, "DEVICE_TYPE_ACCELERATOR"},
      {CL_DEVICE_TYPE_CUSTOM, "DEVICE_TYPE_CUSTOM"},
      {CL_DEVICE_TYPE_ALL, "DEVICE_TYPE_ALL"}};
  return table[type];
}

void printAllDevices(cl::Platform platform) {
  // init device
  std::vector<cl::Device> all_devices;
  platform.getDevices(CL_DEVICE_TYPE_ALL, &all_devices);
  std::cout << "Finding devices: " << all_devices.size() << std::endl;

  // walk through devices
  for (auto &device : all_devices) {
    std::cout << "CL_DEVICE_NAME: " << device.getInfo<CL_DEVICE_NAME>()
              << std::endl;
    std::cout << "CL_DEVICE_TYPE: "
              << beautyDevType(device.getInfo<CL_DEVICE_TYPE>()) << std::endl;
    std::cout << "CL_DEVICE_MAX_COMPUTE_UNITS: "
              << device.getInfo<CL_DEVICE_MAX_COMPUTE_UNITS>() << std::endl;
    std::cout << "CL_DEVICE_MAX_WORK_GROUP_SIZE: "
              << device.getInfo<CL_DEVICE_MAX_WORK_GROUP_SIZE>() << std::endl;
    std::cout << "CL_DEVICE_MAX_WORK_ITEM_SIZES[0]: "
              << device.getInfo<CL_DEVICE_MAX_WORK_ITEM_SIZES>()[0]
              << std::endl;
    std::cout << "CL_DEVICE_GLOBAL_MEM_SIZE: "
              << beautyMem(device.getInfo<CL_DEVICE_GLOBAL_MEM_SIZE>())
              << std::endl;
    std::cout << "CL_DEVICE_LOCAL_MEM_SIZE: "
              << beautyMem(device.getInfo<CL_DEVICE_LOCAL_MEM_SIZE>())
              << std::endl;
    std::cout << std::endl;
  }
}

void printDevice(cl::Device device) {
  std::cout << "CL_DEVICE_NAME: " << device.getInfo<CL_DEVICE_NAME>()
            << std::endl;
  std::cout << "CL_DEVICE_TYPE: "
            << beautyDevType(device.getInfo<CL_DEVICE_TYPE>()) << std::endl;
  std::cout << "CL_DEVICE_MAX_COMPUTE_UNITS: "
            << device.getInfo<CL_DEVICE_MAX_COMPUTE_UNITS>() << std::endl;
  std::cout << "CL_DEVICE_MAX_WORK_GROUP_SIZE: "
            << device.getInfo<CL_DEVICE_MAX_WORK_GROUP_SIZE>() << std::endl;
  std::cout << "CL_DEVICE_MAX_WORK_ITEM_SIZES[0]: "
            << device.getInfo<CL_DEVICE_MAX_WORK_ITEM_SIZES>()[0] << std::endl;
  std::cout << "CL_DEVICE_GLOBAL_MEM_SIZE: "
            << beautyMem(device.getInfo<CL_DEVICE_GLOBAL_MEM_SIZE>())
            << std::endl;
  std::cout << "CL_DEVICE_LOCAL_MEM_SIZE: "
            << beautyMem(device.getInfo<CL_DEVICE_LOCAL_MEM_SIZE>())
            << std::endl;
}

cl::Device getDevice() {
  // init platforms
  std::vector<cl::Platform> platforms;
  cl::Platform::get(&platforms);

  // select default platform
  cl::Platform default_platform;
  for (auto &platform : platforms) {
    std::string platformVersion = platform.getInfo<CL_PLATFORM_VERSION>();
    if (platformVersion.find("OpenCL 2.") != std::string::npos) {
      default_platform = platform;
      break;
    }
  }
  if (default_platform() == nullptr) {
    throw std::runtime_error("No OpenCL 2.x platform found.");
  }

  // init devices
  std::vector<cl::Device> all_devices;
  default_platform.getDevices(CL_DEVICE_TYPE_ALL, &all_devices);

  // select default device
  cl::Device default_device;
  for (auto &device : all_devices) {
    if (device()) {
      default_device = device;
      break;
    }
  }
  if (default_device() == nullptr) {
    throw std::runtime_error("No device found.");
  }

  // init context
  return default_device;
}

std::string readTxtFull(std::string filename) {
  std::ifstream file(filename, std::ifstream::in | std::ifstream::binary);
  if (not file.good()) {
    throw std::runtime_error("readTxtFull() error");
  }
  file.seekg(0, file.end);
  size_t length = file.tellg();
  file.seekg(0, file.beg);

  std::unique_ptr<char[]> buf(new char[length + 1]);
  memset(buf.get(), 0, length + 1);
  file.read(buf.get(), length);
  return std::string(buf.get());
}

template <typename T, size_t N>
std::shared_ptr<std::array<T, N>> linspace(T start, T end) {
  auto buffer = std::make_shared<std::array<T, N>>();
  T increasement = (end - start) / N;
  for (auto &item : *buffer) {
    item = start;
    start += increasement;
  }
  return buffer;
}

template <typename T, size_t N>
std::shared_ptr<std::array<T, N>> zeros() {
  auto buffer = std::make_shared<std::array<T, N>>();
  for (auto &x : *buffer) {
    x = T(0.0);
  }
  return buffer;
}

template <typename T, size_t N>
std::shared_ptr<std::array<T, N>> randn(T mean = T(0.0), T std = T(1.0)) {
  auto clock = std::chrono::system_clock::now().time_since_epoch();
  std::default_random_engine generator(clock.count());
  std::normal_distribution<T> distribution(mean, std);

  auto buffer = std::make_shared<std::array<T, N>>();
  for (auto &x : *buffer) {
    x = distribution(generator);
  }
  return buffer;
}
