# 트리 서버 실행 (리눅스 / Hetzner)

서버는 암호문을 받아서 전달만 한다. 대화 내용·키는 모른다.
구성: `tree-server`(Rust) + `Caddy`(HTTPS 인증서 자동). DB는 SQLite 파일 하나(도커 볼륨).

## 준비

1. 도메인의 DNS A(그리고 AAAA) 레코드를 서버 IP로 맞춘다.
2. 방화벽에서 80, 443(TCP), 443(UDP)을 연다.
3. 도커 설치 (Ubuntu):
   ```sh
   curl -fsSL https://get.docker.com | sh
   ```

## 처음 실행

```sh
git clone https://github.com/moneyally/tree.git
cd tree/deploy
cp .env.example .env

# 운영자 토큰 만들기. TOKEN은 따로 안전한 곳에 보관한다 (git·.env에 넣지 않음).
TOKEN=$(openssl rand -hex 32); echo "$TOKEN"
printf %s "$TOKEN" | sha256sum      # 이 해시값만 .env의 ADMIN_TOKEN_SHA256에 넣는다

nano .env                           # TREE_DOMAIN, ADMIN_TOKEN_SHA256 채우기
docker compose up -d --build
```

확인:

```sh
curl https://도메인/healthz          # {"status":"ok"}
docker compose ps                    # tree-server가 healthy
```

## 운영 기능 적용/해제

```sh
curl https://도메인/v1/features
curl -X POST -H "X-Tree-Admin: $TOKEN" https://도메인/v1/features/server.signups/release   # 신규 가입 멈춤
curl -X POST -H "X-Tree-Admin: $TOKEN" https://도메인/v1/features/server.signups/apply     # 다시 받음
```

## 업데이트

```sh
cd tree && git pull && cd deploy && docker compose up -d --build
```

## 백업

DB는 볼륨 `tree_tree-data` 안에 있다. 잠깐 멈추고 복사한다.

```sh
docker compose stop tree-server
docker run --rm -v tree_tree-data:/data -v "$PWD":/backup busybox tar czf /backup/tree-data.tgz -C /data .
docker compose start tree-server
```

백업 파일은 암호화해서 다른 곳에 둔다. 대화 내용은 없지만 계정·기기 목록이 들어 있다.

## 로그

```sh
docker compose logs -f tree-server
```

로그에는 요청 종류·결과 코드·처리 시간만 남는다. IP·메시지·키는 남기지 않는다.
Caddyfile에 `log`를 켜지 말 것 (IP가 디스크에 남는다).
접속 기록 보관 의무가 있는지는 **변호사 확인 필요**.

## 설정값

`.env.example`에 전부 있다. 바꾼 뒤 `docker compose up -d`.
