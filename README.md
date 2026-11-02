# pm-commons

Portable primitives for Tanit and other PolyMech apps: UTF-8 strings, 32/64-bit ids, path policy, URI parsing, gitignore matching, magic-byte sniffing, a dynamic loader, PATH lookup, task ids, a scheduler claim file, and a length-prefixed IPC frame.

The static library does not replace the host copies in `src/` yet. Those stay until a call site links `pm-commons-lib`. It also does not replace `packages/vfs.cpp` (that package still has its own path copy), `packages/ipc` (sockets and a JSON library), or the Win32 app resolver.

`operator bool` on `pm::commons::Error` is true on failure.

## Build and test

From `packages/commons.cpp`:

```text
npm run build:cpp
npm test
```

From the repo root:

```text
npm run build:cpp:commons
npm run test:pm-commons
```

The test binary is `build/dev/pm-commons` (`pm-commons.exe` on Windows), then `build/release/`. Set `PM_COMMONS_CLI` to point the tests at another binary. Tests run with the package directory as the working directory.

Configure uses `node ../../scripts/cmake.mjs` so Windows Ninja gets the MSVC environment. Do not call raw `cmake` for this package.

## CLI

One process. Success is one JSON object on stdout and exit 0. Failure is `{"ok":false,"error","code","status"}` and exit 1. A missing argument exits 2.

```text
pm-commons string lower AbC
{"ok":true,"value":"abc"}

pm-commons path sanitize ../etc
{"ok":false,"error":"EFORBIDDEN: path traversal","code":"EFORBIDDEN","status":403}

pm-commons uri private http://127.0.0.1/x
{"ok":true,"private":true,"reason":"loopback address"}

pm-commons which hello --path fixtures/bin --ext .cmd --file
```

Subcommands: `string`, `uuid`, `path`, `uri`, `fs`, `library`, `which`, `task`, `claim`, `ipc`.

## Integration

The host links the static library. It does not spawn `pm-commons` and it does not compile `cli/`.

```cmake
if(NOT TARGET pm-commons-lib)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/packages/commons.cpp
                   ${CMAKE_CURRENT_BINARY_DIR}/pm-commons-lib EXCLUDE_FROM_ALL)
endif()
target_link_libraries(${HOST_TARGET} PRIVATE pm-commons-lib)
```

Put that inside the feature flag that owns the caller. Link every host target that calls the library. The second target must see `if(NOT TARGET pm-commons-lib)`.

The host includes `pm/commons/commons.hpp` (or one header under `pm/commons/`). It passes paths, clocks, and a process-alive hook for scheduler claims. It does not copy the jail, the matcher, or the URI checks back into `src/`.

Sibling packages in this tree (`packages/audio.cpp`, `packages/video.cpp`) can opt in without becoming a dependency of a standalone checkout:

```cmake
option(PM_AUDIO_LINK_COMMONS "Link sibling packages/commons.cpp" OFF)
```

`PM_VIDEO_LINK_COMMONS` is the same switch. Both default off. When on, they include `packages/commons.cpp/cmake/host-layout.cmake` and link `pm-commons-lib`. A clone of audio or video alone does not fetch commons, JSON, or a Windows SDK through this package.

`npm run build:cpp:commons` and `npm run test:pm-commons` from the repo root exercise this package without building tanit.

Tanit compiles these `.cpp` files into `pm-media`. It does not link `pm-commons-lib`. `src/core/path_sanitizer.cpp` is gone; `media::path` comes from `src/path/path.cpp`. The other host copies (`string_utils.cpp`, `library_utils.cpp`, `uri.cpp`, the fs filters) are still compiled too, under their original namespaces. VFS, audio, and video do not use this package. HTTP, curl, Boost.URL, libmagic, and jq are not part of these sources. `validate_path_spec_for_input_selection` calls the host's `media::is_http_url`. The standalone executable supplies a prefix check so its CLI links.

## What is intentionally absent

- Sockets, an HTTP client, and `cpp-httplib`. `src/lib/net/http_client.cpp` and `src/core/url_fetch.cpp` stay in the host.
- nlohmann JSON inside `pm-commons-lib`. The CLI uses it only to print results. Claim files and IPC frames use a small fixed encoder.
- Win32 types in public headers. `LoadLibrary` is a Windows translation unit; Android, Linux, and macOS use `dlopen` (`src/library/library_posix.cpp`). This tree was not cross-compiled for those targets.
- A second path policy. `media::path` is the original sanitizer, including its `std::regex` checks and the Windows wide helpers. `normalize_local_path` returns native separators.
- Gitignore case folding is an argument (`case_fold`), not an `#ifdef`.
- Windows App Paths, the registry, Start Menu scan, and `NH_Parameter` in `src/types.h`.
- libmagic. `fs::probe_bytes` matches a fixed signature table.
- The jq field walker in `src/core/async_iterator.cpp`.
- A process spawner. PATH lookup is `process::which`. Spawn is a follow-up.
