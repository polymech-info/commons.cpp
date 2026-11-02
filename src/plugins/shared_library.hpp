#pragma once

#include <string>

namespace pm::plugins {

/** RAII / attach wrapper over media::library. No second LoadLibrary stack. */
class SharedLibrary {
public:
    SharedLibrary() noexcept = default;
    SharedLibrary(const SharedLibrary&) = delete;
    SharedLibrary& operator=(const SharedLibrary&) = delete;
    SharedLibrary(SharedLibrary&& other) noexcept;
    SharedLibrary& operator=(SharedLibrary&& other) noexcept;
    ~SharedLibrary();

    void attach(void* handle) noexcept;
    void* load(const std::string& path, const std::string& search_dir = {}) noexcept;
    void release() noexcept;
    void* get_function_ptr(const char* name) const noexcept;

    void* handle() const noexcept { return handle_; }
    bool owns() const noexcept { return owns_; }
    bool loaded() const noexcept { return handle_ != nullptr; }

private:
    void* handle_ = nullptr;
    bool  owns_ = false;
};

} // namespace pm::plugins
