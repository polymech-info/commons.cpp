#pragma once

#include "constants.hpp"
#include "security/security_defaults.hpp"
#include <map>
#include <string>

namespace media::settings_types {

struct ProviderEntry {
    std::string api_key;
    std::string base_url;
    std::string default_model;
    /// Credential selection mode: "auto" (api_key wins; OAuth fallback),
    /// "api_key" (settings key only), "oauth" (OAuth token only).
    /// Empty string treated as "auto".
    std::string auth_mode;
};

using ProviderMap = std::map<std::string, ProviderEntry>;

/// `settings.json["security"]["secureStorage"]["sessions"]`.
/// Policy/GPO can later clamp these fields, but the user settings shape is
/// intentionally simple and mirrors the secure-storage document backend.
struct SessionStorageSettings {
    std::string backend = pm::security::k_session_storage_backend_default;  ///< secure-storage
    std::string root;                                                       ///< empty = default config_dir/sessions
    std::string protection = pm::security::k_session_storage_protection_default; ///< plain | signed | encrypted | encrypted+up
    int max_sessions = pm::security::k_session_storage_max_sessions_default;
    int prune_keep_latest = 0;                                              ///< 0 = no automatic prune
};

/// Canonical `settings.json["chat"]` shape. Runtime provider/model selection must come from
/// explicit chat fields or command/tool overrides; provider rows supply credentials.
/// `base_url` is persisted for router=`custom` (per preset or global chat).
struct ChatProviderSettings {
    std::string router;
    std::string base_url;
    std::string api_key;
    std::string model;
    int timeout_ms = 180'000;
    int max_iterations = 8;
    bool planner_enabled = true;
    /// Optional dedicated planner router/model. Empty string means "inherit from `router`/`model`",
    /// preserving legacy behaviour. When set, the planner LLM call uses these instead of the main
    /// chat router/model — useful for routing the cheap pre-selection pass to a faster/cheaper
    /// router (e.g. `composer-2-fast`) while the main agent runs on a stronger model.
    std::string planner_router;
    std::string planner_model;
    /// Optional dedicated AI consent reviewer router/model. Empty string means
    /// inherit the effective planner router/model, which itself may inherit the
    /// main chat router/model.
    std::string security_router;
    std::string security_model;
    std::string image_provider;
    std::string image_model;
    std::string image_recognition_provider;
    std::string image_recognition_model;
    std::string video_provider;
    std::string video_model;
    /// Dedicated OCR routing, separate from the general image-recognition slot.
    /// Allows pairing a specialist OCR model (e.g. PaddleOCR-VL, ONNX PaddleOCR)
    /// independently of the general vision provider used for image understanding.
    /// Supported providers: "llama" (GGUF VLM), "onnx" (PaddleOCR pipeline), cloud ids.
    /// Empty means "fall back to image_recognition_provider/model for OCR tasks".
    std::string ocr_provider;
    std::string ocr_model;
    // Audio — Speech-to-Text and Text-to-Speech provider/model/voice selection.
    // stt_provider / stt_model  : tanit, elevenlabs, openrouter, or whisper.
    // tts_provider / tts_model  : tanit, elevenlabs, openrouter, vibevoice, or moss.
    // tts_voice_id              : ElevenLabs UUID, or an OpenRouter voice such as eve.
    // vibevoice_model / _tokenizer / _voice : GGUF paths for the local vibevoice engine.
    //   Used when tts_provider="vibevoice".  CLI/xblox block params override these.
    std::string stt_provider;
    std::string stt_model;
    std::string tts_provider;
    std::string tts_model;
    std::string tts_voice_id;
    std::string vibevoice_model;     ///< Path to vibevoice-realtime-*.gguf
    std::string vibevoice_tokenizer; ///< Path to tokenizer.gguf
    std::string vibevoice_voice;     ///< Path to voice-*.gguf (realtime-0.5B) or empty
    /// LLM HTTP endpoint mode → /chat/completions ("completion") or /responses ("responses")
    /// or OpenAI Realtime WS ("realtime"). Default is the global knob pm::llm::k_default_api_mode
    /// in constants.hpp.
    std::string api_mode = pm::llm::k_default_api_mode;
    /// Dedicated router/model for Realtime API (/v1/realtime voice) sessions.
    /// Empty = use pm::llm::k_default_realtime_router / k_default_realtime_model
    /// (openai/gpt-realtime). Text chat router/model is NOT inherited — it is
    /// reserved for the delegated "brain" agent (/responses) inside VoiceAgent.
    std::string realtime_router;
    std::string realtime_model;
    /// Built-in Realtime voice (marin/cedar/alloy/…). Empty = server default.
    /// Locked once the session emits audio, so it's applied at session creation.
    std::string realtime_voice;
};

/// Policy applied when the user-selected audio/video device is absent at runtime.
enum class DeviceAbsentPolicy : uint8_t {
    fallback_to_default = 0, ///< Silently fall back to the OS-default device.
    fail                = 1, ///< Return an error instead of opening a different device.
};

/// Persistent user overrides for the default audio/video capture/playback devices.
/// Stored under settings.json["custom"]["audio_video_devices"].
/// Empty strings mean "use the system/OS default".
struct AudioVideoDeviceSettings {
    std::string       audio_input_device;   ///< Capture (microphone) device name substring.
    std::string       audio_output_device;  ///< Playback (speaker) device name substring.
    std::string       video_capture_device; ///< Camera device name substring.
    std::string       audio_input_source = "mic"; ///< "mic", "desktop", or "mix".
    std::string       desktop_audio_device; ///< Loopback/render device substring.
    float             mic_gain     = 1.0f;  ///< Linear microphone gain.
    float             desktop_gain = 1.0f;  ///< Linear desktop/loopback gain.
    DeviceAbsentPolicy absent_policy = DeviceAbsentPolicy::fallback_to_default;
};

/// Persistent Voice Command Center options. Stored under
/// settings.json["custom"]["voice_commands"].
struct VoiceCommandSettings {
    bool        enabled = true;
    std::string wake_phrase = "Tanit";
    std::string route = "trigger"; ///< "trigger" | "agent"
    std::string filter = "auto";   ///< "auto" | "off" | "deepfilter" | "gtcrn"
    std::string filter_model;
    bool        post_filter = false;
    /// Wet/dry mix for DeepFilter / GTCRN. 0 = original, 1 = full filter.
    float       filter_blend = 1.0f;
    std::string provider;          ///< empty = chat STT setting / whisper
    std::string model;
    std::string language = "auto";
    /// Local whisper.cpp: `"gpu"` (default) or `"cpu"`. GPU load failure
    /// falls back to CPU until the next listen start, which retries GPU.
    std::string backend = "gpu";
    /// Dedicated listen mic. Empty falls back to Audio & Video
    /// `audio_input_device`, then the OS default.
    std::string audio_input_device;
};

} // namespace media::settings_types
