#include "uuid_generator.h"
#include <algorithm>
#include <cctype>
#include <cstring>

// ========== Uuid64 Methods ==========

std::string Uuid64::ToStandardUuidString() const
{
    // Format: 00000000-0000-0000-HHHHHHHH-LLLLLLLL
    // Zero-pad upper 64 bits, use our 64 bits as lower half
    char buffer[37];  // 36 chars + null terminator
    snprintf(buffer, sizeof(buffer),
             "00000000-0000-0000-%08x-%08x",
             high, low);
    return std::string(buffer);
}

Uuid64 Uuid64::FromStandardUuidString(const std::string& uuidStr, bool takeLast64)
{
    if (uuidStr.empty())
        return Uuid64(0, 0);
    
    // Remove dashes and validate format
    std::string cleaned;
    cleaned.reserve(32);
    
    for (char c : uuidStr)
    {
        if (c == '-')
            continue;
        if (!std::isxdigit(static_cast<unsigned char>(c)))
            return Uuid64(0, 0);  // Invalid character
        cleaned += c;
    }
    
    // Standard UUID should have 32 hex digits (128 bits)
    if (cleaned.size() != 32)
    {
        // If it's shorter, try to parse what we have
        if (cleaned.size() <= 16)
        {
            // Short enough to fit in 64 bits
            try
            {
                if (cleaned.size() <= 8)
                {
                    uint32_t low = static_cast<uint32_t>(std::stoull(cleaned, nullptr, 16));
                    return Uuid64(0, low);
                }
                else
                {
                    size_t splitPos = cleaned.size() - 8;
                    uint32_t high = static_cast<uint32_t>(std::stoull(cleaned.substr(0, splitPos), nullptr, 16));
                    uint32_t low = static_cast<uint32_t>(std::stoull(cleaned.substr(splitPos), nullptr, 16));
                    return Uuid64(high, low);
                }
            }
            catch (const std::exception&)
            {
                return Uuid64(0, 0);
            }
        }
    }
    
    // Extract 64 bits from 128-bit UUID
    try
    {
        if (takeLast64)
        {
            // Take last 64 bits (last 16 hex digits)
            std::string last64 = cleaned.substr(16);
            uint32_t high = static_cast<uint32_t>(std::stoull(last64.substr(0, 8), nullptr, 16));
            uint32_t low = static_cast<uint32_t>(std::stoull(last64.substr(8, 8), nullptr, 16));
            return Uuid64(high, low);
        }
        else
        {
            // Take first 64 bits (first 16 hex digits)
            std::string first64 = cleaned.substr(0, 16);
            uint32_t high = static_cast<uint32_t>(std::stoull(first64.substr(0, 8), nullptr, 16));
            uint32_t low = static_cast<uint32_t>(std::stoull(first64.substr(8, 8), nullptr, 16));
            return Uuid64(high, low);
        }
    }
    catch (const std::exception&)
    {
        return Uuid64(0, 0);
    }
}

UuidGenerator::UuidGenerator()
    : m_RandomGenerator(std::random_device{}())
    , m_Distribution(0x1000000, 0xFFFFFFFF)  // Start from 0x1000000 to ensure reasonable length
    , m_SequentialCounter(0x1000000)
    , m_SequentialCounter64(0x1000000, 0)
{
}

uint32_t UuidGenerator::GenerateRandom()
{
    return m_Distribution(m_RandomGenerator);
}

uint32_t UuidGenerator::GenerateSequential()
{
    return m_SequentialCounter++;
}

std::string UuidGenerator::ToHexString(uint32_t uuid)
{
    std::stringstream ss;
    ss << "0x" << std::hex << uuid;
    return ss.str();
}

uint32_t UuidGenerator::FromHexString(const std::string& hexString)
{
    if (hexString.empty())
        return 0;
    
    std::string cleaned = hexString;
    
    // Remove "0x" or "0X" prefix if present
    if (cleaned.size() >= 2 && cleaned[0] == '0' && 
        (cleaned[1] == 'x' || cleaned[1] == 'X'))
    {
        cleaned = cleaned.substr(2);
    }
    
    // Parse hex string
    uint32_t result = 0;
    try
    {
        result = static_cast<uint32_t>(std::stoull(cleaned, nullptr, 16));
    }
    catch (const std::exception&)
    {
        return 0;  // Invalid format
    }
    
    return result;
}

bool UuidGenerator::IsValid(uint32_t uuid)
{
    return uuid != 0;
}

void UuidGenerator::ResetSequential(uint32_t seed)
{
    m_SequentialCounter = seed;
}

void UuidGenerator::SetRandomSeed(uint32_t seed)
{
    m_RandomGenerator.seed(seed);
}

// ========== 64-bit UUID Methods (Dual 32-bit Words) ==========

Uuid64 UuidGenerator::GenerateRandom64()
{
    uint32_t high = m_Distribution(m_RandomGenerator);
    uint32_t low = m_Distribution(m_RandomGenerator);
    return Uuid64(high, low);
}

Uuid64 UuidGenerator::GenerateSequential64()
{
    Uuid64 result = m_SequentialCounter64;
    
    // Increment with carry (low word first, then high word)
    m_SequentialCounter64.low++;
    if (m_SequentialCounter64.low == 0)
    {
        // Overflow in low word, increment high word
        m_SequentialCounter64.high++;
    }
    
    return result;
}

std::string UuidGenerator::ToHexString64(const Uuid64& uuid)
{
    std::stringstream ss;
    ss << "0x" << std::hex << uuid.high << std::setw(8) << std::setfill('0') << uuid.low;
    return ss.str();
}

Uuid64 UuidGenerator::FromHexString64(const std::string& hexString)
{
    if (hexString.empty())
        return Uuid64(0, 0);
    
    std::string cleaned = hexString;
    
    // Remove "0x" or "0X" prefix if present
    if (cleaned.size() >= 2 && cleaned[0] == '0' && 
        (cleaned[1] == 'x' || cleaned[1] == 'X'))
    {
        cleaned = cleaned.substr(2);
    }
    
    // Handle strings shorter than 16 hex digits
    if (cleaned.size() <= 8)
    {
        // Short string - treat as low word only
        try
        {
            uint32_t low = static_cast<uint32_t>(std::stoull(cleaned, nullptr, 16));
            return Uuid64(0, low);
        }
        catch (const std::exception&)
        {
            return Uuid64(0, 0);
        }
    }
    
    // Split into high and low parts
    try
    {
        size_t splitPos = cleaned.size() - 8;
        std::string highStr = cleaned.substr(0, splitPos);
        std::string lowStr = cleaned.substr(splitPos);
        
        uint32_t high = highStr.empty() ? 0 : static_cast<uint32_t>(std::stoull(highStr, nullptr, 16));
        uint32_t low = static_cast<uint32_t>(std::stoull(lowStr, nullptr, 16));
        
        return Uuid64(high, low);
    }
    catch (const std::exception&)
    {
        return Uuid64(0, 0);
    }
}

void UuidGenerator::ResetSequential64(uint32_t highSeed, uint32_t lowSeed)
{
    m_SequentialCounter64 = Uuid64(highSeed, lowSeed);
}

