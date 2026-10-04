# Tree Media Composer / Editor — Stage 1C

## 목적

Stage 1C media는 "파일을 암호화해서 보내는 기능"만 구현하지 않는다. 사용자가 사진/영상/음성을 보내기 전에 기기 안에서 편집하고, 미리 보고, 설명을 붙이고, 보기 정책을 선택한 뒤 최종 결과만 E2EE blob으로 전송한다.

v5의 원칙인 **기기 안 처리**, **사진·영상 설명**, **view-once**, **자동 다운로드/파일 크기 제한**을 유지한다.

## 편집 파이프라인

```text
원본 선택/촬영
  -> local MediaComposerState
  -> non-destructive MediaEditPlan
  -> local renderer (Android/iOS/Desktop)
  -> preview render
  -> user confirmation
  -> final plaintext bytes
  -> per-file MediaKey
  -> encrypted chunks + encrypted preview
  -> MLS MediaEnvelope
  -> server ciphertext-only blob
```

원본은 서버로 보내지 않는다. 편집 명세도 서버에 보낼 필요가 없다. 서버는 암호문, 크기, 청크 번호, 해시 같은 전송 검증 정보만 본다.

## 편집 API

### 기본

- `MediaComposerState::new(width, height)`
- `MediaEditPlan::push(EditOperation)`
- `MediaEditPlan::undo()`
- `MediaEditPlan::redo()`
- `MediaEditPlan::validate()`
- `MediaEditPlan::set_caption()`
- `Session::media_composer()`
- `Session::send_composed_media()`

### EditOperation

- Crop
- Rotate 0/90/180/270
- RotateBy -180..180
- FlipHorizontal / FlipVertical
- Adjust: brightness, contrast, saturation, sharpness, warmth, blur
- Draw: brush width, opacity, pressure/sensitivity, smoothing, rotation
- AddText: 위치, 크기, 투명도, 회전, bold/italic
- AddSticker: 위치, 배율, 회전

모든 수치는 bounded validation을 거친다. 실제 픽셀 연산은 플랫폼 렌더러가 담당한다.

## UX

### 보내기 전 화면

1. 원본 전체 화면
2. 상단: 뒤로 / 원본 / 실행취소 / 다시실행
3. 하단: 자르기 / 회전 / 조정 / 그리기 / 텍스트 / 스티커 / 가리기
4. 캡션 입력
5. 보기 정책: 계속 보기 / N초 후 만료 / 한 번 보기
6. 미리보기
7. 보내기

### 이미지 보기

- 핀치 줌
- 더블탭 줌
- 팬
- 전체화면
- 영상 재생/일시정지
- 보기 타이머는 UI 표현일 뿐 보안 결정은 MediaLifecycle이 담당

### 타이머

- 수신 시가 아니라 **성공적인 open/confirm_open 이후** 시작
- countdown / progress ring / moving-star animation은 UI 전용
- 만료 시 decrypted buffer, thumbnail cache, temporary file, media key를 즉시 purge
- view-once는 성공적인 open 후 consumed event를 MLS 메시지로 동기화
- 실패한 복호화는 view-once를 소비하지 않는다.

## 보안

- 파일마다 독립적인 MediaKey
- manifest + group + epoch + message id에 key commitment binding
- chunk별 AEAD와 AAD
- preview는 별도 HKDF-derived key
- 서버에는 MediaKey가 없음
- 서버에는 decrypt/view/plaintext endpoint가 없음
- preview도 plaintext로 서버에 업로드하지 않음
- 파일 이름/MIME/캡션/편집 내용은 E2EE envelope 영역에서 관리
- 서버의 media capability는 임시 blob 접근 제어용이며 암호키가 아니다.
- decoder는 플랫폼에서 리소스 제한을 적용해야 한다.
- view-once는 스크린샷/촬영/외부 복사를 암호학적으로 막는 기능이 아니다.

## API 경계

Rust Core:
- 상태 머신
- manifest
- edit recipe validation
- encryption/decryption
- lifecycle
- secure buffers
- consumed event

Platform SDK:
- camera/gallery picker
- pixel/video renderer
- GPU drawing
- text layout/font
- hardware decoder
- full-screen viewer
- gesture handling
- animation

Server:
- opaque upload session
- chunk storage
- manifest ciphertext storage
- capability validation
- expiry garbage collection

## 이후 구현 순서

1. Core editor schema/validation
2. client composer/send API
3. server resumable ciphertext blob
4. encrypted preview
5. view-once + timer
6. consumed synchronization
7. platform renderer bindings
8. integration tests
9. fuzz/resource-limit tests
10. CI + external crypto review gate
