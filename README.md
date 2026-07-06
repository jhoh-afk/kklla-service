# Billywear KKLLA 무료 배포판

무료로 지속 사용하기 위한 Netlify + Neon 버전입니다.

## 구조

- Netlify: 웹사이트 주소와 화면, 서버리스 API
- Neon: 무료 Postgres 데이터베이스

## 필요한 무료 계정

1. GitHub
2. Netlify
3. Neon

## 배포 순서

### 1. Neon DB 만들기

1. https://neon.com 에 가입합니다.
2. New Project를 만듭니다.
3. Connection string을 복사합니다.
4. 연결 문자열은 대략 이런 형태입니다.

```text
postgresql://USER:PASSWORD@HOST.neon.tech/DBNAME?sslmode=require
```

### 2. GitHub에 올리기

이 `kklla-sales-netlify` 폴더 내용을 GitHub 저장소 최상단에 올립니다.

최상단 구조는 이렇게 보여야 합니다.

```text
netlify.toml
package.json
static/
netlify/
README.md
```

### 3. Netlify 배포

1. https://app.netlify.com 에 가입합니다.
2. Add new site > Import an existing project를 선택합니다.
3. GitHub 저장소를 연결합니다.
4. Build command는 비워두거나 `npm install`을 사용합니다.
5. Publish directory는 `static`입니다.
6. Functions directory는 `netlify/functions`입니다.

`netlify.toml`이 있으므로 대부분 자동 인식됩니다.

### 4. Netlify 환경변수 설정

Site configuration > Environment variables에서 아래 값을 추가합니다.

```text
DATABASE_URL=Neon에서 복사한 Postgres 연결 문자열
KKLLA_ADMIN_PASSWORD=관리자 비밀번호
```

관리자 이메일은 고정입니다.

```text
admin@billywear-kklla.kr
```

### 5. 재배포

환경변수를 넣은 뒤 Deploys에서 Trigger deploy를 실행합니다.

완료되면 아래 형태의 주소가 생깁니다.

```text
https://사이트이름.netlify.app
```

이 주소를 직원들에게 전달하면 됩니다.

## 무료 사용 시 주의점

- Neon Free Plan은 저장공간과 월간 사용량 제한이 있습니다.
- Netlify Functions는 요청이 올 때 실행되는 서버리스 구조입니다.
- 직원 3명 규모의 영업관리에는 무료 범위로 시작하기 좋지만, 실사용량이 늘면 유료 전환이 필요할 수 있습니다.
- 정산/계좌 정보가 들어가므로 관리자 비밀번호는 반드시 강하게 설정하세요.
