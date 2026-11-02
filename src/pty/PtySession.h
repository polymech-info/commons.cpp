#ifndef PM_PTY_SESSION_H
#define PM_PTY_SESSION_H

#include <functional>
#include <memory>
#include <string>

namespace pm::pty {

struct SpawnOptions {
    std::string  shell_id;
    std::string  shell_type;
    int          cols = 80;
    int          rows = 24;
    std::wstring cwd;
    /// When true, omit PowerShell -NoExit so `exit` and script completion can close the PTY.
    bool         one_shot = false;
};

struct EventSink {
    std::function<void(const std::string& shell_id, const std::string& data)> on_output;
    std::function<void(const std::string& shell_id, int exit_code)>           on_exit;
    std::function<void(const std::string& shell_id, const std::string& error)> on_error;
};

class PtySession {
public:
    virtual ~PtySession() = default;

    virtual void write(const std::string& data) = 0;
    virtual void resize(int cols, int rows) = 0;
    virtual void close() = 0;
};

std::unique_ptr<PtySession> create_session(const SpawnOptions& options, EventSink sink);

} // namespace pm::pty

#endif // PM_PTY_SESSION_H
