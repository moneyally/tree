# Third-party licenses

Tree uses the following open-source libraries. Full license texts are in each
crate's source distribution.

| Library | License |
| --- | --- |
| openmls | MIT |
| openmls_rust_crypto | MIT |
| openmls_libcrux_crypto | MIT |
| openmls_basic_credential | MIT |
| openmls_traits | MIT |
| thiserror | MIT OR Apache-2.0 |
| openmls_sqlite_storage | MIT |
| rusqlite | MIT |
| argon2 | MIT OR Apache-2.0 |
| zeroize | Apache-2.0 OR MIT |
| serde | MIT OR Apache-2.0 |
| serde_json | MIT OR Apache-2.0 |

Compiled into the binary through `rusqlite` (feature
`bundled-sqlcipher-vendored-openssl`):

| Component | License |
| --- | --- |
| SQLCipher (via libsqlite3-sys, MIT) | BSD-3-Clause (Zetetic LLC) |
| SQLite | Public domain |
| OpenSSL 3 (via openssl-src, MIT/Apache-2.0) | Apache-2.0 |

Kotlin apps (`apps/desktop`, `apps/android`), QR codes:

| Library | License |
| --- | --- |
| ZXing core (`com.google.zxing:core` 3.5.4) | Apache-2.0 |
| CameraX (`androidx.camera:*` 1.4.2, Android only) | Apache-2.0 |

Transitive dependencies are listed in `Cargo.lock`. A generated, complete notice
file will be added before the first release.
