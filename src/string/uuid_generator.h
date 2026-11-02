#pragma once
#include <cstdint>
#include <string>
#include <random>
#include <sstream>
#include <iomanip>

// UUID classes in global namespace to avoid conflict with 'namespace ed = ax::NodeEditor;'

/**
 * 64-bit UUID stored as two 32-bit words for microcontroller compatibility
 * Format: 0x50626ea1b7c7646 (high:low pair)
 */
struct Uuid64
{
    uint32_t high;  // Upper 32 bits
    uint32_t low;   // Lower 32 bits
    
    constexpr Uuid64() : high(0), low(0) {}
    constexpr Uuid64(uint32_t h, uint32_t l) : high(h), low(l) {}
    
    // Comparison operators for use in maps/sets (highly optimized)
    bool operator==(const Uuid64& other) const { return high == other.high && low == other.low; }
    bool operator!=(const Uuid64& other) const { return high != other.high || low != other.low; }
    bool operator<(const Uuid64& other) const 
    { 
        if (high != other.high) return high < other.high;
        return low < other.low;
    }
    
    // Check if valid (non-zero)
    bool IsValid() const { return high != 0 || low != 0; }
    
    // Convert to single uint64_t (for platforms that support it)
    uint64_t ToUint64() const { return (static_cast<uint64_t>(high) << 32) | low; }
    
    // Create from uint64_t
    static Uuid64 FromUint64(uint64_t value)
    {
        return Uuid64(static_cast<uint32_t>(value >> 32), static_cast<uint32_t>(value & 0xFFFFFFFF));
    }
    
    // Convert to standard UUID string format (with dashes)
    // Note: This creates a 128-bit UUID by zero-padding the upper 64 bits
    // Format: 00000000-0000-0000-HHHHHHHH-LLLLLLLL
    std::string ToStandardUuidString() const;
    
    // Parse from standard UUID format (e.g., "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d")
    // Extracts 64 bits from 128-bit UUID (takes last 64 bits by default)
    static Uuid64 FromStandardUuidString(const std::string& uuidStr, bool takeLast64 = true);
};

/**
 * UUID Generator for creating unique identifiers
 * Supports both 32-bit and 64-bit (dual 32-bit word) UUID generation
 * Format: 0x50626ea, 0x1b7c7646 (hexadecimal 32-bit integers)
 */
class UuidGenerator
{
public:
    UuidGenerator();
    
    // ========== 32-bit UUID Methods ==========
    
    // Generate a random 32-bit UUID
    uint32_t GenerateRandom();
    
    // Generate a sequential UUID (increments from seed)
    uint32_t GenerateSequential();
    
    // Convert UUID to hex string (e.g., "0x50626ea")
    static std::string ToHexString(uint32_t uuid);
    
    // Parse hex string to UUID (supports "0x50626ea" or "50626ea")
    static uint32_t FromHexString(const std::string& hexString);
    
    // Check if a UUID is valid (non-zero)
    static bool IsValid(uint32_t uuid);
    
    // Reset sequential counter
    void ResetSequential(uint32_t seed = 0x1000000);
    
    // Set random seed for deterministic generation
    void SetRandomSeed(uint32_t seed);
    
    // Get current sequential counter value
    uint32_t GetCurrentSequential() const { return m_SequentialCounter; }
    
    // ========== 64-bit UUID Methods (Dual 32-bit Words) ==========
    
    // Generate a random 64-bit UUID (two 32-bit words)
    Uuid64 GenerateRandom64();
    
    // Generate a sequential 64-bit UUID (two 32-bit words)
    Uuid64 GenerateSequential64();
    
    // Convert Uuid64 to hex string (e.g., "0x50626ea1b7c7646")
    static std::string ToHexString64(const Uuid64& uuid);
    
    // Parse hex string to Uuid64 (supports "0x50626ea1b7c7646" or "50626ea1b7c7646")
    static Uuid64 FromHexString64(const std::string& hexString);
    
    // Reset sequential counter for 64-bit UUIDs
    void ResetSequential64(uint32_t highSeed = 0x1000000, uint32_t lowSeed = 0);
    
    // Get current 64-bit sequential counter value
    Uuid64 GetCurrentSequential64() const { return m_SequentialCounter64; }

private:
    std::mt19937 m_RandomGenerator;
    std::uniform_int_distribution<uint32_t> m_Distribution;
    uint32_t m_SequentialCounter;
    Uuid64 m_SequentialCounter64;
};
