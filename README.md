# T08 — 패스키로 잠긴 나만의 공간

**결과물:** https://t08-passkey-intro.vercel.app/  
**소스 저장소:** https://github.com/junyeong-lab/t08-passkey-intro

## 1. 어떤 인증 기술로 구현했는가

WebAuthn 패스키 방식으로 구현했습니다. 프런트엔드는 `index.html`, 서버 인증 처리는 Supabase Edge Function(Deno)의 `supabase/functions/t08-passkey/index.ts`에 직접 작성했습니다. 서버 측 WebAuthn 검증에는 **`@simplewebauthn/server@14.0.3` 라이브러리**를 사용하고, 계정·공개키·질문·세션·가상 메모는 Supabase PostgreSQL에 저장합니다. 외부 로그인 인증 서비스에 전체 인증을 맡긴 방식이 아니라 **라이브러리를 활용한 직접 구현**입니다. 비밀번호 입력 칸은 사용하지 않습니다.

## 2. 왜 이 방식을 선택했는가

기존 T01의 공개 Home/About 소개는 로그인 없이 유지하고, 가상 비공개 메모 3건은 **인증 성공 후에만 서버가 전송**하도록 했습니다. HTML에 비공개 본문을 미리 넣고 화면에서만 숨기면 소스 보기로 노출될 수 있기 때문입니다. 패스키는 개인키를 기기/패스키 관리자에 보관하고, 서버에는 서명을 확인하는 **공개키**만 저장하므로 비밀번호를 서버에 저장할 필요가 없습니다.

## 3. 어느 파일에 어떤 인증 흐름을 구현했는가

| 흐름 | 화면 및 서버 코드 위치 |
| --- | --- |
| 패스키 등록·추가 | `index.html` 등록 UI → `supabase/functions/t08-passkey/index.ts`의 `register-options`, `register-verify` |
| 패스키 로그인 | `index.html` 로그인 UI → 같은 Edge Function의 `login-options`, `login-verify` |
| 로그아웃 | `index.html` 로그아웃 UI → 같은 Edge Function의 `logout` |
| 비공개 자료 조회 | `index.html` 인증 후 자료 화면 → 같은 Edge Function의 `GET ?op=private` |

**계정 간 접근 차단 위치(C41):** `supabase/functions/t08-passkey/index.ts`의 `handle()`에서 `GET ?op=private-for` 요청의 대상 계정과 로그인된 계정이 다르면 **HTTP 403**으로 거절합니다. `GET ?op=private`는 URL의 다른 계정 ID가 아닌 인증된 세션 소유 계정의 자료만 반환합니다.

## 4. 인증과 보안 검증 기록

**등록·개인키 보호(C20·C22·C23)**  
서버가 등록 질문을 생성·보관하고, 브라우저는 `register-verify`에 `flowId`와 WebAuthn `response`를 보냅니다. 실제 등록 요청 및 **HTTP 201**을 확인했습니다. 요청에는 `attestationObject`, `authenticatorData`, `clientDataJSON`, `publicKey` 등 공개키 관련 데이터가 있었고 **개인키 전송 필드는 없었습니다**. 원시 바이너리 전체를 별도 분석한 것은 아닙니다.

등록 질문 두 개의 서버 저장값 비교 지문(각 MD5 앞 12자)은 `demo-c23` 기준 **`9fdda62c84f1` / `a1eaa5fd8256`**으로 서로 달랐습니다. 서버 `t08_passkeys.public_key_b64url`에 실제 저장된 `demo-c23`의 공개키 값은 다음과 같습니다. **이는 개인키나 비밀번호가 아니라 서명 검증용 공개키입니다.**

```text
pQECAyYgASFYIEKOmU22FkVlchdD4zJJsUHWAxfR5qnqFCXhnftvZUYPIlggnF0ztmCWk0F8JzVupUQeFNceNFfYY1YWmJAQV89i0d4
```

**저장 위치(C26)**  
갤럭시 **Google 비밀번호 관리자**에서 해당 사이트의 `demo-a`, `demo-b` 패스키 항목을 확인했습니다. `demo-b`는 해당 관리자를 통한 인증 성공을 확인했습니다. `demo-a`는 PC의 QR 코드를 갤럭시로 스캔하는 교차 기기 인증을 사용했으며, 현재 서버에 남은 패스키와 관리자에 표시된 항목의 Credential ID 일치는 별도로 확인되지 않았습니다.

**로그인 질문과 세션(C28·C32)**  
`demo-a` 로그인 질문 두 개의 비교 지문(MD5 앞 12자)은 **`931b4e9d3dca` / `81e24bf8ac5b`**로 서로 달랐습니다. 로그인 시 기기 서명을 서버에 저장된 공개키로 검증합니다. 성공하면 **32바이트 난수 세션 토큰**을 발급하며, 브라우저 현재 탭의 `sessionStorage`에 토큰을, 서버 DB에는 토큰의 **SHA-256 해시**를 저장합니다. 유효기간은 **30분**이며, 로그아웃 시 세션을 폐기합니다. 로그아웃 후 같은 세션의 비공개 요청은 HTTP 401로 거절됐습니다. 실제 토큰 값은 제출하지 않습니다.

**패스키 관리(C43·C46)**  
목록에는 패스키마다 **이름과 등록 날짜**를 표시합니다. 한 계정에 패스키 두 개를 등록했다가 하나를 삭제한 뒤 남은 키로 재로그인했습니다. 마지막 남은 패스키의 서버 삭제는 HTTP 409로 거절하고 화면에서 복구 제약을 안내합니다. **사용 가능한 패스키가 0개가 되면 로그인할 수 없으며, 별도 계정 복구 기능은 없습니다.**

### 필수 보안 검사 4가지 — 정상 요청과 거절 요청 비교(C50)

| 검사 | 정상 요청·응답 | 거절 요청·응답 |
| --- | --- | --- |
| 비로그인 접근 차단 | 패스키 로그인 후 `GET ?op=private` → **HTTP 200**, 본인 가상 자료 3건 | 토큰 없이 `GET ?op=private` → **HTTP 401**, `authentication_required`, 비공개 본문 없음 |
| 다른 계정 자료 접근 차단 | 본인 계정 세션으로 자료 조회 → **HTTP 200**, 본인 3건 | 다른 계정 `account_id`로 `GET ?op=private-for` → **HTTP 403**, `cross_account_denied`; 거절 전후 본인 자료 **3→3건** |
| 사용한 로그인 질문 재사용 차단 | 첫 `POST ?op=login-verify` → **HTTP 200** | 동일 질문·서명을 다시 전송 → **HTTP 409**, `challenge_already_used_or_expired` |
| 패스키 삭제 후 접근 차단 | 첫 키 삭제 후 남은 두 번째 키로 로그인·자료 조회 → **HTTP 200** | 삭제한 첫 번째 Credential ID로 `POST ?op=login-options` 요청 → **HTTP 403** |

마지막 검사의 HTTP 403은 **삭제된 키를 지정한 로그인 질문 발급 거절** 결과이며, 삭제된 개인키로 서명 검증을 재시도한 결과로 표현하지 않습니다. 등록·로그인 성공 및 거절 응답은 실제 시험 기록을 기준으로 기재했습니다.

## 5. AI와 내 판단 — 3가지 구분 (C53)

① **AI에게 맡긴 일:** WebAuthn 패스키 인증 코드 작성, 오류 점검, 과제 통과 조건과 검증 결과 정리를 맡겼습니다.

② **내가 직접 판단한 일:** PC와 갤럭시에서 패스키 등록·로그인·삭제 및 계정 간 접근 차단을 직접 검증하고, 과제에서 요구한 증빙만 남기기로 결정했습니다.

③ **AI 제안을 따르지 않은 일:** 인증 오류가 발생했을 때 기존 패스키를 무리하게 삭제하거나 재등록하지 않고, 정상 인증이 가능한 기존 PC에서 검증하는 방법을 선택했습니다.

## 6. 아직 막지 못한 경우

**등록된 모든 패스키 기기와 동기화 저장소를 분실하면 계정 복구 수단이 없습니다.** 마지막 패스키 삭제를 서버에서 차단하는 기능은 구현했지만, 기기·관리자 전부를 사용할 수 없는 상황을 복구하는 별도 절차는 구현하지 않았습니다.
