#pragma once
#include "uuid_generator.h"
#include <map>


/**
 * UUID ID Manager
 * 
 * Manages mapping between:
 * - Persistent UUIDs (ed::Uuid64): Stable across sessions, used for save/load
 * - Runtime IDs (int/ed::NodeId/ed::LinkId): Dynamic, used by imgui-node-editor for fast access
 * 
 * This allows us to:
 * 1. Save nodes/links/pins with UUIDs (persistent)
 * 2. Load and assign new runtime IDs (avoiding conflicts)
 * 3. Lookup entities by either UUID or runtime ID
 */
class UuidIdManager
{
public:
    UuidIdManager();
    
    // ========== UUID Generation (uses internal UuidGenerator) ==========
    
    // Generate new UUID (sequential by default for determinism)
    Uuid64 GenerateUuid();
    
    // ========== Mapping: UUID <-> Runtime ID ==========
    
    // Register a node: UUID -> Runtime ID
    void RegisterNode(const Uuid64& uuid, int runtimeId);
    
    // Register a link: UUID -> Runtime ID  
    void RegisterLink(const Uuid64& uuid, int runtimeId);
    
    // Register a pin: UUID -> Runtime ID
    void RegisterPin(const Uuid64& uuid, int runtimeId);
    
    // ========== Lookup: UUID -> Runtime ID ==========
    
    // Get runtime ID from node UUID (returns -1 if not found)
    int GetNodeRuntimeId(const Uuid64& uuid) const;
    
    // Get runtime ID from link UUID (returns -1 if not found)
    int GetLinkRuntimeId(const Uuid64& uuid) const;
    
    // Get runtime ID from pin UUID (returns -1 if not found)
    int GetPinRuntimeId(const Uuid64& uuid) const;
    
    // ========== Lookup: Runtime ID -> UUID ==========
    
    // Get UUID from node runtime ID (returns invalid UUID {0,0} if not found)
    Uuid64 GetNodeUuid(int runtimeId) const;
    
    // Get UUID from link runtime ID (returns invalid UUID {0,0} if not found)
    Uuid64 GetLinkUuid(int runtimeId) const;
    
    // Get UUID from pin runtime ID (returns invalid UUID {0,0} if not found)
    Uuid64 GetPinUuid(int runtimeId) const;
    
    // ========== Validation ==========
    
    // Check if node UUID is registered
    bool HasNode(const Uuid64& uuid) const;
    
    // Check if link UUID is registered
    bool HasLink(const Uuid64& uuid) const;
    
    // Check if pin UUID is registered
    bool HasPin(const Uuid64& uuid) const;
    
    // ========== Management ==========
    
    // Clear all mappings (e.g., when loading a new graph)
    void Clear();
    
    // Unregister specific entities (when deleting nodes/links)
    void UnregisterNode(const Uuid64& uuid);
    void UnregisterLink(const Uuid64& uuid);
    void UnregisterPin(const Uuid64& uuid);
    
    // Also support unregister by runtime ID
    void UnregisterNodeByRuntimeId(int runtimeId);
    void UnregisterLinkByRuntimeId(int runtimeId);
    void UnregisterPinByRuntimeId(int runtimeId);
    
    // ========== Statistics ==========
    
    size_t GetNodeCount() const { return m_NodeUuidToRuntime.size(); }
    size_t GetLinkCount() const { return m_LinkUuidToRuntime.size(); }
    size_t GetPinCount() const { return m_PinUuidToRuntime.size(); }
    
    // Get direct access to UUID generator
    UuidGenerator& GetUuidGenerator() { return m_UuidGen; }

private:
    UuidGenerator m_UuidGen;
    
    // Node mappings
    std::map<Uuid64, int> m_NodeUuidToRuntime;
    std::map<int, Uuid64> m_NodeRuntimeToUuid;
    
    // Link mappings
    std::map<Uuid64, int> m_LinkUuidToRuntime;
    std::map<int, Uuid64> m_LinkRuntimeToUuid;
    
    // Pin mappings
    std::map<Uuid64, int> m_PinUuidToRuntime;
    std::map<int, Uuid64> m_PinRuntimeToUuid;
};

