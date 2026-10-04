# Tree Media Protocol v1

This document defines the Stage 1C media lifecycle implemented on
claude/full-messenger-v1.

## Security boundary

- The sender generates a fresh 256-bit media key for every attachment.
- The attachment manifest binds attachment_id, MLS message_id, group id,
  MLS epoch, media type, filename, MIME type, plaintext size, chunk geometry,
  preview policy, view policy and the nonce base.
- The manifest is encrypted before upload. The server therefore receives only
  an encrypted manifest blob plus transport geometry needed to enforce limits.
- The media key is never uploaded to the server. It is carried inside the
  MLS application message in a MediaEnvelope.
- The envelope contains a SHA-256 key commitment over the manifest commitment
  and media key. Changing the message, group, epoch, manifest or key breaks
  the commitment.
- Each media chunk uses AES-256-GCM with a nonce derived from a per-file
  random 64-bit nonce base and the chunk index. The manifest commitment and
  chunk index are authenticated data.
- The server verifies chunk SHA-256 and geometry but never decrypts a chunk.
- Encrypted preview data uses a key derived separately from the media key.
- Decrypted media buffers use zeroizing storage in the Rust core.

## Upload

1. Client creates the MLS message id.
2. Client creates and commits the media manifest to that id and current epoch.
3. Client creates the random media key.
4. Client encrypts the manifest.
5. Client initializes a resumable server media object.
6. Client encrypts and uploads chunks independently.
7. Client optionally encrypts a thumbnail/preview.
8. Client finalizes the object.
9. Client sends the MediaEnvelope through MLS using the pre-selected message id.

An upload can leave an orphaned encrypted object if the later MLS send fails.
The normal retention purge removes it; this is preferable to exposing a
plaintext rollback path.

## Display lifecycle

MediaLifecycle exposes:

Hidden -> Preview -> Opening -> Open

and terminal states:

Consumed and Expired.

For View Once, the item is not consumed merely because the user tapped it.
The caller must confirm successful decryption/open. A decryption failure can
therefore be retried.

For Timed media, the timer starts at successful open confirmation, not at
receipt time. UI countdowns and animated effects consume remaining_seconds
and are not security primitives.

## View Once synchronization

A successful View Once open can emit an authenticated MLS MediaViewEvent.
Other devices persist a local consumed marker and can refuse to open the
attachment.

This synchronization is not a mathematical atomic exactly-once guarantee
against two devices opening the same item concurrently while offline. E2EE
clients cannot make that decision through a trusted plaintext server without
changing the privacy model. The implementation therefore uses first-observed
consumption state and local enforcement.

## Server API

- POST /v1/media — initialize an encrypted object.
- POST /v1/media/{media_id}/chunks — upload/replace one ciphertext chunk.
- POST /v1/media/{media_id} — finalize after all chunks exist.
- GET /v1/media/{media_id} — fetch encrypted manifest/transport metadata.
- GET /v1/media/{media_id}/chunks/{index} — fetch one ciphertext chunk.

The media capability is a random bearer secret and is required in the
X-Tree-Media-Capability header. Chunk uploads additionally require the
authenticated device to be the device that initialized the object.

## Client API

tree-client::Session provides:

- send_media
- decode_media_message
- download_media_chunk
- decrypt_media_preview
- new_media_view
- confirm_media_open
- media_was_consumed

The app layer should render the core state with the desired UX: blur/hidden
preview, fullscreen/pinch zoom, countdown ring, moving-star/particle
animation, and expired/consumed placeholders.

## Limits

The default server accepts encrypted media up to 64 MiB and chunks up to
1 MiB. The core defaults to 256 KiB chunks. The media manifest limits the
chunk count to 65,535.

## Non-goals

No client-side feature can prevent screenshots, screen recording, or a second
camera from capturing content that a legitimate recipient can already see.
Expiry removes the client's usable key/plaintext/cache state; it cannot erase
copies already made outside the application.
