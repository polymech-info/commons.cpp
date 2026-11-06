#pragma once
//
// Persistent stdio child process primitive.
//
// This is intentionally lower-level than ProcessRunner's run-to-exit modes and
// lower-level than command_runner's UI lifecycle tracking. It owns only launch
// handles for a long-lived child with broker-written stdin and broker-read
// stdout; protocol code (MCP JSON-RPC, language server framing, etc.) lives
// above this layer.
//

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace media::process {

struct StdioPathGrant {
    std::string path;
    std::string access = "read";
};

struct StdioLaunchOptions {
    std::string executable;
    std::vector<std::string> args;
    std::string cwd;
    std::map<std::string, std::string> extra_env;

    // Empty = normal launch. "appcontainer" routes the persistent child through
    // the Win32 AppContainer backend when FEATURE_SECURITY_AGENT is enabled.
    std::string sandbox_backend;
    std::string sandbox_moniker;
    bool lpac = false;
    bool retain_sandbox_profile = false;
    std::vector<StdioPathGrant> paths;
};

struct StdioChildInfo {
    unsigned long pid = 0;
    std::string sandbox_backend;
    std::string container_sid;
    bool sandboxed = false;
};

class StdioChildProcess {
public:
    ~StdioChildProcess();
    StdioChildProcess(StdioChildProcess&&) noexcept;
    StdioChildProcess& operator=(StdioChildProcess&&) noexcept;
    StdioChildProcess(const StdioChildProcess&) = delete;
    StdioChildProcess& operator=(const StdioChildProcess&) = delete;

    bool valid() const noexcept;
    const StdioChildInfo& info() const noexcept;

    bool write_all(const std::string& data, std::string& err);
    bool read_some(char* buffer, std::size_t capacity, std::size_t& bytes_read, std::string& err);

    void terminate_tree();

private:
    struct Impl;
    explicit StdioChildProcess(std::unique_ptr<Impl> impl);

    std::unique_ptr<Impl> impl_;

    friend StdioChildProcess launch_stdio_child(const StdioLaunchOptions&, std::string&);
};

StdioChildProcess launch_stdio_child(const StdioLaunchOptions& opts, std::string& err);

} // namespace media::process
