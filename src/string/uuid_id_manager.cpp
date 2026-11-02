#include "uuid_id_manager.h"

UuidIdManager::UuidIdManager()
{
}

Uuid64 UuidIdManager::GenerateUuid()
{
    // Use sequential generation for determinism and debugging
    // (can switch to random if needed: m_UuidGen.GenerateRandom64())
    return m_UuidGen.GenerateSequential64();
}

// ========== Registration ==========

void UuidIdManager::RegisterNode(const Uuid64& uuid, int runtimeId)
{
    if (!uuid.IsValid())
        return;
    
    m_NodeUuidToRuntime[uuid] = runtimeId;
    m_NodeRuntimeToUuid[runtimeId] = uuid;
}

void UuidIdManager::RegisterLink(const Uuid64& uuid, int runtimeId)
{
    if (!uuid.IsValid())
        return;
    
    m_LinkUuidToRuntime[uuid] = runtimeId;
    m_LinkRuntimeToUuid[runtimeId] = uuid;
}

void UuidIdManager::RegisterPin(const Uuid64& uuid, int runtimeId)
{
    if (!uuid.IsValid())
        return;
    
    m_PinUuidToRuntime[uuid] = runtimeId;
    m_PinRuntimeToUuid[runtimeId] = uuid;
}

// ========== Lookup: UUID -> Runtime ID ==========

int UuidIdManager::GetNodeRuntimeId(const Uuid64& uuid) const
{
    auto it = m_NodeUuidToRuntime.find(uuid);
    return (it != m_NodeUuidToRuntime.end()) ? it->second : -1;
}

int UuidIdManager::GetLinkRuntimeId(const Uuid64& uuid) const
{
    auto it = m_LinkUuidToRuntime.find(uuid);
    return (it != m_LinkUuidToRuntime.end()) ? it->second : -1;
}

int UuidIdManager::GetPinRuntimeId(const Uuid64& uuid) const
{
    auto it = m_PinUuidToRuntime.find(uuid);
    return (it != m_PinUuidToRuntime.end()) ? it->second : -1;
}

// ========== Lookup: Runtime ID -> UUID ==========

Uuid64 UuidIdManager::GetNodeUuid(int runtimeId) const
{
    auto it = m_NodeRuntimeToUuid.find(runtimeId);
    return (it != m_NodeRuntimeToUuid.end()) ? it->second : Uuid64(0, 0);
}

Uuid64 UuidIdManager::GetLinkUuid(int runtimeId) const
{
    auto it = m_LinkRuntimeToUuid.find(runtimeId);
    return (it != m_LinkRuntimeToUuid.end()) ? it->second : Uuid64(0, 0);
}

Uuid64 UuidIdManager::GetPinUuid(int runtimeId) const
{
    auto it = m_PinRuntimeToUuid.find(runtimeId);
    return (it != m_PinRuntimeToUuid.end()) ? it->second : Uuid64(0, 0);
}

// ========== Validation ==========

bool UuidIdManager::HasNode(const Uuid64& uuid) const
{
    return m_NodeUuidToRuntime.find(uuid) != m_NodeUuidToRuntime.end();
}

bool UuidIdManager::HasLink(const Uuid64& uuid) const
{
    return m_LinkUuidToRuntime.find(uuid) != m_LinkUuidToRuntime.end();
}

bool UuidIdManager::HasPin(const Uuid64& uuid) const
{
    return m_PinUuidToRuntime.find(uuid) != m_PinUuidToRuntime.end();
}

// ========== Management ==========

void UuidIdManager::Clear()
{
    m_NodeUuidToRuntime.clear();
    m_NodeRuntimeToUuid.clear();
    m_LinkUuidToRuntime.clear();
    m_LinkRuntimeToUuid.clear();
    m_PinUuidToRuntime.clear();
    m_PinRuntimeToUuid.clear();
}

void UuidIdManager::UnregisterNode(const Uuid64& uuid)
{
    auto it = m_NodeUuidToRuntime.find(uuid);
    if (it != m_NodeUuidToRuntime.end())
    {
        int runtimeId = it->second;
        m_NodeUuidToRuntime.erase(it);
        m_NodeRuntimeToUuid.erase(runtimeId);
    }
}

void UuidIdManager::UnregisterLink(const Uuid64& uuid)
{
    auto it = m_LinkUuidToRuntime.find(uuid);
    if (it != m_LinkUuidToRuntime.end())
    {
        int runtimeId = it->second;
        m_LinkUuidToRuntime.erase(it);
        m_LinkRuntimeToUuid.erase(runtimeId);
    }
}

void UuidIdManager::UnregisterPin(const Uuid64& uuid)
{
    auto it = m_PinUuidToRuntime.find(uuid);
    if (it != m_PinUuidToRuntime.end())
    {
        int runtimeId = it->second;
        m_PinUuidToRuntime.erase(it);
        m_PinRuntimeToUuid.erase(runtimeId);
    }
}

void UuidIdManager::UnregisterNodeByRuntimeId(int runtimeId)
{
    auto it = m_NodeRuntimeToUuid.find(runtimeId);
    if (it != m_NodeRuntimeToUuid.end())
    {
        Uuid64 uuid = it->second;
        m_NodeRuntimeToUuid.erase(it);
        m_NodeUuidToRuntime.erase(uuid);
    }
}

void UuidIdManager::UnregisterLinkByRuntimeId(int runtimeId)
{
    auto it = m_LinkRuntimeToUuid.find(runtimeId);
    if (it != m_LinkRuntimeToUuid.end())
    {
        Uuid64 uuid = it->second;
        m_LinkRuntimeToUuid.erase(it);
        m_LinkUuidToRuntime.erase(uuid);
    }
}

void UuidIdManager::UnregisterPinByRuntimeId(int runtimeId)
{
    auto it = m_PinRuntimeToUuid.find(runtimeId);
    if (it != m_PinRuntimeToUuid.end())
    {
        Uuid64 uuid = it->second;
        m_PinRuntimeToUuid.erase(it);
        m_PinUuidToRuntime.erase(uuid);
    }
}

