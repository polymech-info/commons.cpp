#include "shared_library.hpp"

#include "core/library_utils.hpp"

#include <utility>

namespace pm::plugins {

SharedLibrary::SharedLibrary(SharedLibrary&& other) noexcept
    : handle_(other.handle_)
    , owns_(other.owns_)
{
    other.handle_ = nullptr;
    other.owns_ = false;
}

SharedLibrary& SharedLibrary::operator=(SharedLibrary&& other) noexcept
{
    if (this != &other) {
        release();
        handle_ = other.handle_;
        owns_ = other.owns_;
        other.handle_ = nullptr;
        other.owns_ = false;
    }
    return *this;
}

SharedLibrary::~SharedLibrary()
{
    release();
}

void SharedLibrary::attach(void* handle) noexcept
{
    release();
    handle_ = handle;
    owns_ = false;
}

void* SharedLibrary::load(const std::string& path, const std::string& search_dir) noexcept
{
    release();
    if (!search_dir.empty())
        media::library::add_search_dir(search_dir);
    handle_ = media::library::load(path, search_dir);
    owns_ = handle_ != nullptr;
    return handle_;
}

void SharedLibrary::release() noexcept
{
    if (owns_ && handle_)
        media::library::unload(handle_);
    handle_ = nullptr;
    owns_ = false;
}

void* SharedLibrary::get_function_ptr(const char* name) const noexcept
{
    if (!handle_ || !name || !*name)
        return nullptr;
    return media::library::sym(handle_, name);
}

} // namespace pm::plugins
