#include "process/stdio_child_runner.hpp"

#include "process/process_helpers.hpp"
#include "process/process_runner.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <thread>
#include <utility>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  include <UserEnv.h>
#  include <sddl.h>
#  if defined(FEATURE_SECURITY_AGENT) && FEATURE_SECURITY_AGENT
#    include "security/backends/win/SandboxAppContainer.hpp"
#  endif
#else
#  include <cerrno>
#  include <cstring>
#  include <fcntl.h>
#  include <signal.h>
#  include <sys/wait.h>
#  include <thread>
#  include <unistd.h>
#endif

namespace media::process {

namespace {

#if defined(_WIN32)
std::wstring build_shell_cmdline(const std::string& executable,
                                 const std::vector<std::string>& args)
{
    const auto shell = detect_shell("cmd");
    std::wstring line = quote_process_arg(widen_utf8(shell.exe))
        + L" " + widen_utf8(shell.flag)
        + L" " + quote_process_arg(widen_utf8(executable));
    for (const auto& arg : args) {
        line.push_back(L' ');
        line += quote_process_arg(widen_utf8(arg));
    }
    return line;
}

std::wstring build_direct_cmdline(const std::string& executable,
                                  const std::vector<std::string>& args)
{
    std::wstring line = quote_process_arg(widen_utf8(executable));
    for (const auto& arg : args) {
        line.push_back(L' ');
        line += quote_process_arg(widen_utf8(arg));
    }
    return line;
}

std::string default_sandbox_moniker()
{
    const auto ticks = std::chrono::steady_clock::now().time_since_epoch().count();
    return "pm-stdio-" + std::to_string(::GetCurrentProcessId()) + "-" + std::to_string(ticks);
}
#endif

} // namespace

struct StdioChildProcess::Impl {
    StdioChildInfo info;

#if defined(_WIN32)
    std::atomic<bool> stopping{false};
    HANDLE process = nullptr;
    HANDLE job = nullptr;
    HANDLE stdin_write = nullptr;
    HANDLE stdout_read = nullptr;
    std::string sandbox_moniker;
    std::vector<StdioPathGrant> granted_paths;
    bool retain_sandbox_profile = false;
#else
    pid_t pid = -1;
    int stdin_write = -1;
    int stdout_read = -1;
#endif
};

StdioChildProcess::StdioChildProcess(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl))
{}

StdioChildProcess::~StdioChildProcess()
{
    terminate_tree();
}

StdioChildProcess::StdioChildProcess(StdioChildProcess&&) noexcept = default;
StdioChildProcess& StdioChildProcess::operator=(StdioChildProcess&&) noexcept = default;

bool StdioChildProcess::valid() const noexcept
{
    if (!impl_)
        return false;
#if defined(_WIN32)
    return impl_->process && impl_->process != INVALID_HANDLE_VALUE &&
           impl_->stdin_write && impl_->stdin_write != INVALID_HANDLE_VALUE &&
           impl_->stdout_read && impl_->stdout_read != INVALID_HANDLE_VALUE;
#else
    return impl_->pid > 0 && impl_->stdin_write >= 0 && impl_->stdout_read >= 0;
#endif
}

const StdioChildInfo& StdioChildProcess::info() const noexcept
{
    static const StdioChildInfo empty;
    return impl_ ? impl_->info : empty;
}

bool StdioChildProcess::write_all(const std::string& data, std::string& err)
{
    if (!valid()) {
        err = "stdio child: process not started";
        return false;
    }
    const char* p = data.data();
    std::size_t left = data.size();
    while (left > 0) {
#if defined(_WIN32)
        DWORD n = 0;
        const DWORD chunk = static_cast<DWORD>(left > 65536 ? 65536 : left);
        if (!::WriteFile(impl_->stdin_write, p, chunk, &n, nullptr) || n == 0) {
            err = "stdio child: WriteFile(stdin) failed";
            return false;
        }
#else
        const ssize_t n = ::write(impl_->stdin_write, p, left > 65536 ? 65536 : left);
        if (n <= 0) {
            err = std::string("stdio child: write(stdin) failed: ") + std::strerror(errno);
            return false;
        }
#endif
        p += static_cast<std::size_t>(n);
        left -= static_cast<std::size_t>(n);
    }
    return true;
}

bool StdioChildProcess::read_some(char* buffer, std::size_t capacity,
                                  std::size_t& bytes_read, std::string& err)
{
    bytes_read = 0;
    if (!valid()) {
        err = "stdio child: process not started";
        return false;
    }
    if (!buffer || capacity == 0)
        return true;
#if defined(_WIN32)
    for (;;) {
        if (impl_->stopping.load(std::memory_order_acquire))
            return false;
        DWORD available = 0;
        if (!::PeekNamedPipe(impl_->stdout_read, nullptr, 0, nullptr, &available, nullptr)) {
            err = "stdio child: PeekNamedPipe(stdout) failed";
            return false;
        }
        if (available > 0) {
            DWORD n = 0;
            const DWORD chunk = static_cast<DWORD>(
                std::min<std::size_t>(capacity, static_cast<std::size_t>(available)));
            if (!::ReadFile(impl_->stdout_read, buffer, chunk, &n, nullptr) || n == 0) {
                if (n == 0)
                    return false;
                err = "stdio child: ReadFile(stdout) failed";
                return false;
            }
            bytes_read = static_cast<std::size_t>(n);
            return true;
        }
        if (impl_->process && impl_->process != INVALID_HANDLE_VALUE) {
            const DWORD wait = ::WaitForSingleObject(impl_->process, 0);
            if (wait == WAIT_OBJECT_0)
                return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
#else
    const ssize_t n = ::read(impl_->stdout_read, buffer, capacity);
    if (n <= 0) {
        if (n < 0)
            err = std::string("stdio child: read(stdout) failed: ") + std::strerror(errno);
        return false;
    }
    bytes_read = static_cast<std::size_t>(n);
    return true;
#endif
}

void StdioChildProcess::terminate_tree()
{
    if (!impl_)
        return;
#if defined(_WIN32)
    impl_->stopping.store(true, std::memory_order_release);
    if (impl_->stdout_read && impl_->stdout_read != INVALID_HANDLE_VALUE)
        (void)::CancelIoEx(impl_->stdout_read, nullptr);
    if (impl_->stdin_write && impl_->stdin_write != INVALID_HANDLE_VALUE)
        (void)::CancelIoEx(impl_->stdin_write, nullptr);
    if (impl_->stdin_write && impl_->stdin_write != INVALID_HANDLE_VALUE) {
        ::CloseHandle(impl_->stdin_write);
        impl_->stdin_write = nullptr;
    }
    if (impl_->job && impl_->job != INVALID_HANDLE_VALUE) {
        (void)::TerminateJobObject(impl_->job, 1);
        if (impl_->process && impl_->process != INVALID_HANDLE_VALUE)
            (void)::WaitForSingleObject(impl_->process, 3000);
    } else if (impl_->process && impl_->process != INVALID_HANDLE_VALUE) {
        const DWORD wait = ::WaitForSingleObject(impl_->process, 1500);
        if (wait == WAIT_TIMEOUT) {
            if (impl_->info.pid != 0)
                terminate_process_tree(static_cast<DWORD>(impl_->info.pid));
            else
                ::TerminateProcess(impl_->process, 1);
            (void)::WaitForSingleObject(impl_->process, 3000);
        }
    }
    if (impl_->stdout_read && impl_->stdout_read != INVALID_HANDLE_VALUE) {
        ::CloseHandle(impl_->stdout_read);
        impl_->stdout_read = nullptr;
    }
    if (impl_->process && impl_->process != INVALID_HANDLE_VALUE) {
        ::CloseHandle(impl_->process);
        impl_->process = nullptr;
    }
    if (impl_->job && impl_->job != INVALID_HANDLE_VALUE) {
        ::CloseHandle(impl_->job);
        impl_->job = nullptr;
    }
#if defined(FEATURE_SECURITY_AGENT) && FEATURE_SECURITY_AGENT
    if (!impl_->sandbox_moniker.empty()) {
        pm::security::SandboxAppContainer sandbox;
        for (const auto& pg : impl_->granted_paths)
            (void)sandbox.revokePath(impl_->sandbox_moniker, pg.path);
        if (!impl_->retain_sandbox_profile)
            (void)sandbox.deleteProfile(impl_->sandbox_moniker);
    }
#endif
    impl_->info.pid = 0;
#else
    if (impl_->stdin_write >= 0) {
        ::close(impl_->stdin_write);
        impl_->stdin_write = -1;
    }
    if (impl_->pid > 0) {
        (void)::kill(impl_->pid, SIGTERM);
        int st = 0;
        bool exited = false;
        for (int i = 0; i < 30; ++i) {
            const pid_t r = ::waitpid(impl_->pid, &st, WNOHANG);
            if (r == impl_->pid) {
                exited = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        if (!exited) {
            (void)::kill(impl_->pid, SIGKILL);
            (void)::waitpid(impl_->pid, &st, 0);
        }
        impl_->pid = -1;
    }
    if (impl_->stdout_read >= 0) {
        ::close(impl_->stdout_read);
        impl_->stdout_read = -1;
    }
    impl_->info.pid = 0;
#endif
}

StdioChildProcess launch_stdio_child(const StdioLaunchOptions& opts, std::string& err)
{
    err.clear();
    auto impl = std::unique_ptr<StdioChildProcess::Impl>(new StdioChildProcess::Impl());

    if (opts.executable.empty()) {
        err = "stdio child: executable is required";
        return StdioChildProcess(std::move(impl));
    }

#if defined(_WIN32)
    const bool use_sandbox = !opts.sandbox_backend.empty();
    if (use_sandbox && opts.sandbox_backend != "appcontainer") {
        err = "stdio child: unsupported sandbox backend: " + opts.sandbox_backend;
        return StdioChildProcess(std::move(impl));
    }
#if !(defined(FEATURE_SECURITY_AGENT) && FEATURE_SECURITY_AGENT)
    if (use_sandbox) {
        err = "stdio child: appcontainer sandbox launch requires FEATURE_SECURITY_AGENT";
        return StdioChildProcess(std::move(impl));
    }
#endif

    std::vector<std::pair<std::wstring, std::wstring>> env;
    env.reserve(opts.extra_env.size());
    for (const auto& [k, v] : opts.extra_env)
        env.emplace_back(widen_utf8(k), widen_utf8(v));
    std::vector<wchar_t> env_block = build_environment_block({}, env);

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE out_rd = nullptr, out_wr = nullptr, in_rd = nullptr, in_wr = nullptr;
    if (!::CreatePipe(&out_rd, &out_wr, &sa, 0)) {
        err = "stdio child: CreatePipe(stdout) failed";
        return StdioChildProcess(std::move(impl));
    }
    if (!::SetHandleInformation(out_rd, HANDLE_FLAG_INHERIT, 0)) {
        err = "stdio child: SetHandleInformation(stdout read) failed";
        ::CloseHandle(out_rd); ::CloseHandle(out_wr);
        return StdioChildProcess(std::move(impl));
    }
    if (!::CreatePipe(&in_rd, &in_wr, &sa, 0)) {
        err = "stdio child: CreatePipe(stdin) failed";
        ::CloseHandle(out_rd); ::CloseHandle(out_wr);
        return StdioChildProcess(std::move(impl));
    }
    if (!::SetHandleInformation(in_wr, HANDLE_FLAG_INHERIT, 0)) {
        err = "stdio child: SetHandleInformation(stdin write) failed";
        ::CloseHandle(out_rd); ::CloseHandle(out_wr);
        ::CloseHandle(in_rd); ::CloseHandle(in_wr);
        return StdioChildProcess(std::move(impl));
    }

    HANDLE nul = ::CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (nul == INVALID_HANDLE_VALUE) {
        err = "stdio child: opening NUL failed";
        ::CloseHandle(out_rd); ::CloseHandle(out_wr);
        ::CloseHandle(in_rd); ::CloseHandle(in_wr);
        return StdioChildProcess(std::move(impl));
    }
    (void)::SetHandleInformation(nul, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = out_wr;
    si.hStdInput = in_rd;
    si.hStdError = nul;

    PROCESS_INFORMATION pi{};
    std::wstring cmdline = build_shell_cmdline(opts.executable, opts.args);
    std::vector<wchar_t> cmd_buf(cmdline.begin(), cmdline.end());
    cmd_buf.push_back(L'\0');
    std::wstring shell_exe = widen_utf8(detect_shell("cmd").exe);
    std::wstring cwd = widen_utf8(opts.cwd);
    const wchar_t* cwdp = cwd.empty() ? nullptr : cwd.c_str();

    BOOL ok = FALSE;
    DWORD create_error = 0;

#if defined(FEATURE_SECURITY_AGENT) && FEATURE_SECURITY_AGENT
    PSID app_sid = nullptr;
    LPPROC_THREAD_ATTRIBUTE_LIST attr_list = nullptr;
    if (use_sandbox) {
        pm::security::SandboxAppContainer sandbox;
        std::string moniker = opts.sandbox_moniker.empty()
            ? default_sandbox_moniker()
            : opts.sandbox_moniker;
        const std::string sid_str = sandbox.containerSid(moniker);
        if (sid_str.empty()) {
            err = "stdio child: AppContainer profile setup failed";
            ::CloseHandle(out_rd); ::CloseHandle(out_wr);
            ::CloseHandle(in_rd); ::CloseHandle(in_wr);
            ::CloseHandle(nul);
            return StdioChildProcess(std::move(impl));
        }
        const HRESULT sid_hr = ::DeriveAppContainerSidFromAppContainerName(
            widen_utf8(moniker).c_str(), &app_sid);
        if (FAILED(sid_hr) || !app_sid) {
            err = "stdio child: DeriveAppContainerSidFromAppContainerName failed";
            (void)sandbox.deleteProfile(moniker);
            ::CloseHandle(out_rd); ::CloseHandle(out_wr);
            ::CloseHandle(in_rd); ::CloseHandle(in_wr);
            ::CloseHandle(nul);
            return StdioChildProcess(std::move(impl));
        }
        for (const auto& pg : opts.paths) {
            if (!sandbox.grantPath(moniker, pg.path, pg.access)) {
                err = "stdio child: AppContainer path grant failed: " + pg.path;
                ::FreeSid(app_sid);
                (void)sandbox.deleteProfile(moniker);
                ::CloseHandle(out_rd); ::CloseHandle(out_wr);
                ::CloseHandle(in_rd); ::CloseHandle(in_wr);
                ::CloseHandle(nul);
                return StdioChildProcess(std::move(impl));
            }
        }

        impl->job = ::CreateJobObjectW(nullptr, nullptr);
        if (impl->job) {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli{};
            jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            (void)::SetInformationJobObject(impl->job, JobObjectExtendedLimitInformation,
                                            &jeli, sizeof(jeli));
        }

        SIZE_T attr_size = 0;
        ::InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
        attr_list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
            ::HeapAlloc(::GetProcessHeap(), 0, attr_size));
        if (!attr_list || !::InitializeProcThreadAttributeList(attr_list, 1, 0, &attr_size)) {
            err = "stdio child: InitializeProcThreadAttributeList failed";
            if (attr_list) ::HeapFree(::GetProcessHeap(), 0, attr_list);
            ::FreeSid(app_sid);
            for (const auto& pg : opts.paths) (void)sandbox.revokePath(moniker, pg.path);
            (void)sandbox.deleteProfile(moniker);
            ::CloseHandle(out_rd); ::CloseHandle(out_wr);
            ::CloseHandle(in_rd); ::CloseHandle(in_wr);
            ::CloseHandle(nul);
            return StdioChildProcess(std::move(impl));
        }

        SECURITY_CAPABILITIES sc{};
        sc.AppContainerSid = app_sid;
        sc.CapabilityCount = 0;
        if (!::UpdateProcThreadAttribute(attr_list, 0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                &sc, sizeof(sc), nullptr, nullptr)) {
            err = "stdio child: UpdateProcThreadAttribute(SECURITY_CAPABILITIES) failed";
            ::DeleteProcThreadAttributeList(attr_list);
            ::HeapFree(::GetProcessHeap(), 0, attr_list);
            ::FreeSid(app_sid);
            for (const auto& pg : opts.paths) (void)sandbox.revokePath(moniker, pg.path);
            (void)sandbox.deleteProfile(moniker);
            ::CloseHandle(out_rd); ::CloseHandle(out_wr);
            ::CloseHandle(in_rd); ::CloseHandle(in_wr);
            ::CloseHandle(nul);
            return StdioChildProcess(std::move(impl));
        }

        STARTUPINFOEXW six{};
        six.StartupInfo = si;
        six.StartupInfo.cb = sizeof(six);
        six.lpAttributeList = attr_list;
        std::wstring direct_cmdline = build_direct_cmdline(opts.executable, opts.args);
        std::vector<wchar_t> direct_buf(direct_cmdline.begin(), direct_cmdline.end());
        direct_buf.push_back(L'\0');
        std::wstring direct_exe = widen_utf8(opts.executable);
        ok = ::CreateProcessW(direct_exe.c_str(), direct_buf.data(), nullptr, nullptr, TRUE,
                              EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW |
                                  CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
                              env_block.data(), cwdp,
                              reinterpret_cast<LPSTARTUPINFOW>(&six), &pi);
        create_error = ok ? 0 : ::GetLastError();
        ::DeleteProcThreadAttributeList(attr_list);
        ::HeapFree(::GetProcessHeap(), 0, attr_list);
        ::FreeSid(app_sid);
        if (ok && impl->job)
            (void)::AssignProcessToJobObject(impl->job, pi.hProcess);
        if (ok)
            (void)::ResumeThread(pi.hThread);
        if (!ok) {
            for (const auto& pg : opts.paths) (void)sandbox.revokePath(moniker, pg.path);
            if (!opts.retain_sandbox_profile) (void)sandbox.deleteProfile(moniker);
        } else {
            impl->sandbox_moniker = moniker;
            impl->granted_paths = opts.paths;
            impl->retain_sandbox_profile = opts.retain_sandbox_profile;
            impl->info.sandboxed = true;
            impl->info.sandbox_backend = "appcontainer";
            impl->info.container_sid = sid_str;
        }
    } else
#endif
    {
        ok = ::CreateProcessW(shell_exe.c_str(), cmd_buf.data(), nullptr, nullptr, TRUE,
                              CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                              env_block.data(), cwdp, &si, &pi);
        create_error = ok ? 0 : ::GetLastError();
    }
    ::CloseHandle(out_wr);
    ::CloseHandle(in_rd);
    ::CloseHandle(nul);
    if (!ok) {
        err = "stdio child: CreateProcessW failed (Win32 " + std::to_string(create_error) + ")";
        ::CloseHandle(out_rd);
        ::CloseHandle(in_wr);
        return StdioChildProcess(std::move(impl));
    }
    ::CloseHandle(pi.hThread);
    if (!use_sandbox)
        (void)bind_process_to_lifetime_job(pi.hProcess);
    impl->process = pi.hProcess;
    impl->stdin_write = in_wr;
    impl->stdout_read = out_rd;
    impl->info.pid = pi.dwProcessId;
#else
    int in_pipe[2];
    int out_pipe[2];
    if (::pipe(in_pipe) != 0 || ::pipe(out_pipe) != 0) {
        err = "stdio child: pipe failed";
        return StdioChildProcess(std::move(impl));
    }
    const pid_t p = ::fork();
    if (p < 0) {
        err = std::string("stdio child: fork failed: ") + std::strerror(errno);
        ::close(in_pipe[0]); ::close(in_pipe[1]);
        ::close(out_pipe[0]); ::close(out_pipe[1]);
        return StdioChildProcess(std::move(impl));
    }
    if (p == 0) {
        ::close(in_pipe[1]);
        ::close(out_pipe[0]);
        ::dup2(in_pipe[0], STDIN_FILENO);
        ::dup2(out_pipe[1], STDOUT_FILENO);
        ::close(in_pipe[0]);
        ::close(out_pipe[1]);
        const int dn = ::open("/dev/null", O_WRONLY);
        if (dn >= 0) {
            ::dup2(dn, STDERR_FILENO);
            ::close(dn);
        }
        for (const auto& [k, v] : opts.extra_env)
            ::setenv(k.c_str(), v.c_str(), 1);

        auto shell = detect_shell("auto");
        if (shell.is_pwsh)
            shell = {"/bin/sh", "-c", false};
        std::string shell_cmd = opts.executable;
        for (const auto& arg : opts.args) {
            shell_cmd += ' ';
            shell_cmd += shell_quote_posix(arg);
        }
        const char* argv[] = {shell.exe.c_str(), shell.flag.c_str(), shell_cmd.c_str(), nullptr};
        (void)::execvp(shell.exe.c_str(), const_cast<char* const*>(argv));
        ::_exit(127);
    }
    ::close(in_pipe[0]);
    ::close(out_pipe[1]);
    impl->pid = p;
    impl->stdin_write = in_pipe[1];
    impl->stdout_read = out_pipe[0];
    impl->info.pid = static_cast<unsigned long>(p);
#endif

    return StdioChildProcess(std::move(impl));
}

} // namespace media::process
