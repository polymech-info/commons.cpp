#include "security/ConsentDelegateRegistry.hpp"
#include "security/SecurityGateway.hpp"   // for ConsentDelegate definition

#include <atomic>

namespace pm::security {

namespace {
std::atomic<ConsentDelegate*> g_active{nullptr};
} // namespace

void set_active_consent_delegate(ConsentDelegate* d) noexcept
{
    g_active.store(d, std::memory_order_release);
}

void clear_active_consent_delegate(ConsentDelegate* d) noexcept
{
    if (d == nullptr) {
        g_active.store(nullptr, std::memory_order_release);
        return;
    }
    ConsentDelegate* expected = d;
    g_active.compare_exchange_strong(expected, nullptr,
                                     std::memory_order_acq_rel,
                                     std::memory_order_relaxed);
}

ConsentDelegate* active_consent_delegate() noexcept
{
    return g_active.load(std::memory_order_acquire);
}

} // namespace pm::security
