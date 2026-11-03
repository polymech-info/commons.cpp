# Follow-ups

The contract is README.md. This list is the order to take next.

`media::zip_store` lives in `src/fs/zip_store.cpp`. Settings archive and the installer extract verb include `fs/zip_store.hpp`. `pm-media` links `pm-commons-lib`; it does not compile a second copy.

1. Tanit compiles `packages/commons.cpp/src` straight into `pm-media` (security compiles `src/path/path.cpp` only). `pm-commons-lib` stays the standalone test library. Next, drop the host copies once each package file is the original body: `src/string_utils.cpp`, `src/utilities/uuid_generator.cpp`, and `src/fs/filters`. Leave `src/core/uri.cpp` (Boost) and the PATH half of `src/core/app_resolver.cpp` until those dependencies move with the file. `packages/vfs.cpp/src/commons` still has its own path copy.
2. Pass `process::which` a PATHEXT list from the host on Windows. The registry, App Paths, Start Menu, and package-family scan stay in `app_resolver.cpp`.
3. Scheduler claims already take a process-alive hook. The host should pass its existing liveness check when it links the library. Do not pull a process snapshot into this package.
4. Task handlers (`settings_prewarm`, manifests, index cleanup, ipc prune) stay in `src/tasks`. This package only owns the stable id table.
5. Optional nlohmann slice for `async_iterator` and task-option JSON. jq stays a host dependency. Do not put it in the default static library.
6. HTTP fetch (`http_client`, `url_fetch`) belongs in a later net package. It needs sockets and curl, which this library does not link.
7. `packages/ipc` can adopt `pm::commons::ipc` for the frame and keep its own transport. `src/ipc/ipc_serve.cpp` stays a host server.
8. CLI11 schema helpers and a process runner (spawn, not `which`) once a caller needs them. Parent options stay on the executable, not in the library.
9. `src/types.h` `NH_Parameter` stays in the host. Only `Uuid64` moved.
10. Magic-byte sniff is the portable probe. libmagic and `magic.mgc` stay with the host file tool.
