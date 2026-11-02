#include "security/AuditLog.hpp"
#include "security/PathSecurity.hpp"

#include <chrono>
#include <cstdio>
#include <deque>
#include <mutex>

namespace pm::security {

struct AuditLog::Impl {
    std::size_t cap;
    mutable std::mutex mu;
    std::deque<AuditRecord> ring;

    static std::int64_t now_ms() {
        using namespace std::chrono;
        return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    }

    void push(AuditRecord rec) {
        std::lock_guard<std::mutex> lk(mu);
        ring.push_back(std::move(rec));
        while (ring.size() > cap) ring.pop_front();
        // TODO(security, Phase 3): mirror into spdlog + SQLite audit.db; encrypt
        // the target/reason BLOB columns via CryptoStore before insert.
    }
};

AuditLog::AuditLog(std::size_t ringCapacity)
    : impl_(std::make_unique<Impl>()) {
    impl_->cap = ringCapacity == 0 ? 1 : ringCapacity;
}

AuditLog::~AuditLog() = default;

void AuditLog::record(const ToolRequest& request,
                      AuditEvent event,
                      Risk risk,
                      const std::string& reason,
                      const std::string& grantId) {
    AuditRecord rec;
    rec.tsUnixMs = Impl::now_ms();
    rec.sessionId = request.sessionId;
    rec.profile = request.profile;
    rec.actor = request.actor;
    rec.toolId = request.tool.toolId;
    rec.provider = request.tool.provider;
    rec.serverId = request.tool.serverId;
    rec.action = request.action;
    if (request.target)
        rec.target = PathSecurity::normalizeForMatch(request.target->path);
    rec.event = event;
    rec.risk = risk;
    rec.grantId = grantId;
    rec.reason = reason;
    rec.argsHash = request.argumentsHash;

#if defined(FEATURE_SECURITY_AUDIT_LOG) && FEATURE_SECURITY_AUDIT_LOG
    // Layer 1+ (FEATURE_SECURITY_AUDIT_LOG): mirror decisions to stderr. Off by
    // default — the in-memory ring below is always available for tests/UIs.
    std::fprintf(stderr, "[security] %s %s tool=%s action=%s risk=%s %s\n",
                 std::string(to_string(event)).c_str(),
                 std::string(to_string(request.profile)).c_str(),
                 rec.toolId.c_str(),
                 std::string(to_string(request.action)).c_str(),
                 std::string(to_string(risk)).c_str(),
                 reason.c_str());
#endif

    impl_->push(std::move(rec));
}

void AuditLog::recordEvent(AuditEvent event, const std::string& reason) {
    AuditRecord rec;
    rec.tsUnixMs = Impl::now_ms();
    rec.event = event;
    rec.reason = reason;
#if defined(FEATURE_SECURITY_AUDIT_LOG) && FEATURE_SECURITY_AUDIT_LOG
    std::fprintf(stderr, "[security] %s %s\n",
                 std::string(to_string(event)).c_str(), reason.c_str());
#endif
    impl_->push(std::move(rec));
}

std::vector<AuditRecord> AuditLog::recent(std::size_t max) const {
    std::lock_guard<std::mutex> lk(impl_->mu);
    std::vector<AuditRecord> out;
    const std::size_t n = (max < impl_->ring.size()) ? max : impl_->ring.size();
    out.reserve(n);
    for (auto it = impl_->ring.end() - static_cast<std::ptrdiff_t>(n);
         it != impl_->ring.end(); ++it)
        out.push_back(*it);
    return out;
}

} // namespace pm::security
