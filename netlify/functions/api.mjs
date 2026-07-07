import { neon } from "@neondatabase/serverless";
import crypto from "node:crypto";

const SESSION_COOKIE = "kklla_session";
const SESSION_DAYS = 14;
const TODAY = "2026-07-07";

let schemaReady = false;

function sqlClient() {
  if (!process.env.DATABASE_URL) {
    throw apiError(500, "DATABASE_URL 환경변수가 필요합니다.");
  }
  return neon(process.env.DATABASE_URL);
}

function nowIso() {
  return new Date().toISOString();
}

function addDays(dateText, days) {
  const date = new Date(`${dateText.slice(0, 10)}T00:00:00Z`);
  date.setUTCDate(date.getUTCDate() + days);
  return date.toISOString().slice(0, 10);
}

function makeId(prefix) {
  return `${prefix}_${crypto.randomBytes(8).toString("hex")}`;
}

function passwordHash(password) {
  const salt = crypto.randomBytes(16);
  const iterations = 240000;
  const digest = crypto.pbkdf2Sync(password, salt, iterations, 32, "sha256");
  return `pbkdf2_sha256$${iterations}$${salt.toString("hex")}$${digest.toString("hex")}`;
}

function verifyPassword(password, stored) {
  try {
    const [algorithm, iterationsText, saltHex, digestHex] = String(stored || "").split("$");
    if (algorithm !== "pbkdf2_sha256") return false;
    const digest = Buffer.from(digestHex, "hex");
    const actual = crypto.pbkdf2Sync(password, Buffer.from(saltHex, "hex"), Number(iterationsText), digest.length, "sha256");
    return crypto.timingSafeEqual(actual, digest);
  } catch {
    return false;
  }
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function normalizeText(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[\s\-().]/g, "")
    .replace(/당구클럽|당구장|클럽|아카데미|동호회/g, "");
}

function phoneDigits(value) {
  return String(value || "").replace(/\D/g, "");
}

function maskAccountNumber(value) {
  const digits = phoneDigits(value);
  if (!digits) return "";
  if (digits.length <= 4) return "****";
  return `${"*".repeat(Math.max(4, digits.length - 4))}${digits.slice(-4)}`;
}

function duplicateScore(source, target) {
  if (!source || !target || source.id === target.id) return 0;
  let score = 0;
  const sourcePhone = phoneDigits(source.phone);
  const targetPhone = phoneDigits(target.phone);
  const sourceName = normalizeText(source.name);
  const targetName = normalizeText(target.name);
  const sourceAddress = normalizeText(source.address);
  const targetAddress = normalizeText(target.address);

  if (sourcePhone && sourcePhone.length >= 8 && sourcePhone === targetPhone) score += 60;
  if (sourceName && targetName && sourceName === targetName) score += 35;
  if (sourceName && targetName && (sourceName.includes(targetName) || targetName.includes(sourceName))) score += 24;
  if (sourceAddress && targetAddress && (sourceAddress.includes(targetAddress) || targetAddress.includes(sourceAddress))) score += 35;
  if (source.region && source.region === target.region) score += 8;
  return Math.min(score, 100);
}

function serializeUser(row, includePrivate = false) {
  const item = { ...row };
  delete item.password_hash;
  item.workType = item.work_type || "";
  item.bankName = item.bank_name || "";
  item.accountHolder = item.account_holder || "";
  item.accountNumberMasked = maskAccountNumber(item.account_number);
  if (includePrivate) item.accountNumber = item.account_number || "";
  item.existingNetwork = item.existing_network || "";
  item.joinedAt = item.joined_at || "";
  item.approvedAt = item.approved_at || "";
  item.createdAt = item.created_at || "";
  item.updatedAt = item.updated_at || "";
  delete item.work_type;
  delete item.bank_name;
  delete item.account_holder;
  delete item.account_number;
  delete item.existing_network;
  delete item.joined_at;
  delete item.approved_at;
  delete item.created_at;
  delete item.updated_at;
  try {
    item.agreements = JSON.parse(item.agreements || "{}");
  } catch {
    item.agreements = {};
  }
  return item;
}

function serializeAccount(row) {
  return {
    id: row.id,
    name: row.name,
    category: row.category,
    region: row.region,
    address: row.address,
    contactName: row.contact_name || "",
    phone: row.phone || "",
    ownerId: row.owner_id,
    originatorId: row.originator_id,
    status: row.status,
    expectedAmount: Number(row.expected_amount || 0),
    createdAt: row.created_at || "",
    lockUntil: row.lock_until || "",
    updatedAt: row.updated_at || "",
  };
}

function serializeActivity(row) {
  return {
    id: row.id,
    date: row.date,
    repId: row.rep_id,
    accountId: row.account_id,
    type: row.type,
    contact: row.contact || "",
    summary: row.summary,
    nextAction: row.next_action || "",
    nextDate: row.next_date || "",
    locationNote: row.location_note || "",
    createdAt: row.created_at || "",
  };
}

function serializeContract(row) {
  return {
    id: row.id,
    accountId: row.account_id,
    date: row.date,
    amount: Number(row.amount || 0),
    status: row.status,
    originatorId: row.originator_id,
    closerId: row.closer_id,
    managerId: row.manager_id,
    shares: {
      originator: Number(row.originator_share || 0),
      closer: Number(row.closer_share || 0),
      manager: Number(row.manager_share || 0),
    },
    memo: row.memo || "",
    createdAt: row.created_at || "",
    approvedAt: row.approved_at || "",
  };
}

function json(payload, status = 200, headers = {}) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...headers,
    },
  });
}

function apiError(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

function parseCookies(req) {
  const header = req.headers.get("cookie") || "";
  return Object.fromEntries(
    header
      .split(";")
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => {
        const index = part.indexOf("=");
        return [part.slice(0, index), decodeURIComponent(part.slice(index + 1))];
      }),
  );
}

function setCookie(token) {
  const maxAge = SESSION_DAYS * 24 * 60 * 60;
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=${maxAge}`;
}

function clearCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0`;
}

async function ensureSchema(sql) {
  if (schemaReady) return;
  await sql`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      phone TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('manager', 'sales')),
      status TEXT NOT NULL CHECK(status IN ('active', 'pending', 'suspended')),
      region TEXT,
      coverage TEXT,
      work_type TEXT,
      transport TEXT,
      bank_name TEXT,
      account_holder TEXT,
      account_number TEXT,
      existing_network TEXT,
      agreements TEXT,
      joined_at TEXT,
      approved_at TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `;
  await sql`
    CREATE TABLE IF NOT EXISTS accounts (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      category TEXT NOT NULL,
      region TEXT NOT NULL,
      address TEXT NOT NULL,
      contact_name TEXT,
      phone TEXT,
      owner_id TEXT NOT NULL REFERENCES users(id),
      originator_id TEXT NOT NULL REFERENCES users(id),
      status TEXT NOT NULL,
      expected_amount INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      lock_until TEXT,
      updated_at TEXT NOT NULL
    )
  `;
  await sql`
    CREATE TABLE IF NOT EXISTS activities (
      id TEXT PRIMARY KEY,
      date TEXT NOT NULL,
      rep_id TEXT NOT NULL REFERENCES users(id),
      account_id TEXT NOT NULL REFERENCES accounts(id),
      type TEXT NOT NULL,
      contact TEXT,
      summary TEXT NOT NULL,
      next_action TEXT,
      next_date TEXT,
      location_note TEXT,
      created_at TEXT NOT NULL
    )
  `;
  await sql`
    CREATE TABLE IF NOT EXISTS contracts (
      id TEXT PRIMARY KEY,
      account_id TEXT NOT NULL REFERENCES accounts(id),
      date TEXT NOT NULL,
      amount INTEGER NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('pending', 'approved')),
      originator_id TEXT NOT NULL REFERENCES users(id),
      closer_id TEXT NOT NULL REFERENCES users(id),
      manager_id TEXT NOT NULL REFERENCES users(id),
      originator_share INTEGER NOT NULL,
      closer_share INTEGER NOT NULL,
      manager_share INTEGER NOT NULL,
      memo TEXT,
      created_at TEXT NOT NULL,
      approved_at TEXT
    )
  `;
  await sql`
    CREATE TABLE IF NOT EXISTS audit (
      id TEXT PRIMARY KEY,
      date TEXT NOT NULL,
      actor_id TEXT REFERENCES users(id),
      action TEXT NOT NULL,
      detail TEXT NOT NULL
    )
  `;
  await sql`
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL
    )
  `;

  const countRows = await sql`SELECT COUNT(*)::int AS count FROM users`;
  if (countRows[0].count === 0) {
    await seed(sql);
  } else if (process.env.KKLLA_ADMIN_PASSWORD) {
    await sql`
      UPDATE users
      SET password_hash = ${passwordHash(process.env.KKLLA_ADMIN_PASSWORD)}, updated_at = ${nowIso()}
      WHERE id = 'admin'
    `;
  }
  schemaReady = true;
}

async function seed(sql) {
  const adminPassword = process.env.KKLLA_ADMIN_PASSWORD;
  if (!adminPassword) {
    throw apiError(500, "KKLLA_ADMIN_PASSWORD 환경변수가 필요합니다.");
  }
  const timestamp = nowIso();
  const users = [
    ["admin", "관리자", "admin@billywear-kklla.kr", "02-0000-0000", adminPassword, "manager", "active", "본사", "전국", "관리자", "", "", "", "", "", "{}", "2026-06-01", "2026-06-01"],
    ["r1", "강도윤", "doyun@kklla.kr", "010-1200-3481", "sales2026!", "sales", "active", "서울·경기", "서울, 경기 북부", "성과급 영업", "자차", "국민은행", "강도윤", "123456-00-000001", "서울 강남권 당구장 8곳, 3쿠션 동호회 2곳", '{"ownership":true,"settlement":true}', "2026-06-01", "2026-06-01"],
    ["r2", "박민재", "minjae@kklla.kr", "010-8891-1002", "sales2026!", "sales", "active", "영남·충청", "부산, 대구, 대전, 충청", "성과급 영업", "자차", "신한은행", "박민재", "110-000-000002", "부산 동호회, 대전 아카데미 네트워크", '{"ownership":true,"settlement":true}', "2026-06-01", "2026-06-01"],
    ["r3", "이서현", "seohyun@kklla.kr", "010-4114-7720", "sales2026!", "sales", "active", "호남·강원", "전라, 광주, 강원", "프리랜서", "혼합", "우리은행", "이서현", "1002-000-000003", "전주 동호회, 강원 협회 행사 담당자", '{"ownership":true,"settlement":true}', "2026-06-01", "2026-06-01"],
    ["r4", "정하준", "hajun@example.com", "010-3300-9041", "sales2026!", "sales", "pending", "인천·경기 서부", "인천, 부천, 김포", "파트타임", "대중교통", "하나은행", "정하준", "352-0000-000004", "인천 포켓볼 동호회 1곳", '{"ownership":true,"settlement":true}', "2026-07-04", ""],
  ];
  for (const item of users) {
    await sql`
      INSERT INTO users (
        id, name, email, phone, password_hash, role, status, region, coverage,
        work_type, transport, bank_name, account_holder, account_number,
        existing_network, agreements, joined_at, approved_at, created_at, updated_at
      )
      VALUES (
        ${item[0]}, ${item[1]}, ${item[2]}, ${item[3]}, ${passwordHash(item[4])}, ${item[5]}, ${item[6]},
        ${item[7]}, ${item[8]}, ${item[9]}, ${item[10]}, ${item[11]}, ${item[12]}, ${item[13]},
        ${item[14]}, ${item[15]}, ${item[16]}, ${item[17]}, ${timestamp}, ${timestamp}
      )
    `;
  }

  const accounts = [
    ["a1", "강남 브레이크 당구클럽", "당구장", "서울 강남구", "서울 강남구 테헤란로 152 지하1층", "김성우 대표", "010-3412-7781", "r1", "r1", "견적중", 3600000, "2026-06-21", "2026-07-21"],
    ["a2", "부산 큐하우스", "동호회", "부산 해운대구", "부산 해운대구 센텀동로 55 2층", "최민호 총무", "010-8891-6020", "r2", "r2", "계약완료", 2800000, "2026-06-14", "2026-08-01"],
    ["a3", "대전 브릿지 3쿠션 클럽", "당구장", "대전 유성구", "대전 유성구 대학로 88 4층", "오지훈 매니저", "010-5510-2409", "r2", "r2", "샘플 전달", 1900000, "2026-06-28", "2026-07-28"],
    ["a4", "강남 브레이크 클럽", "당구장", "서울 강남구", "서울 강남구 테헤란로152 지하 1층", "김 대표", "010-3412-7781", "r3", "r3", "중복 검토", 3000000, "2026-07-03", "2026-08-02"],
    ["a5", "전주 포켓라인 동호회", "동호회", "전북 전주시", "전북 전주시 완산구 홍산중앙로 18", "문정아 회장", "010-4114-3221", "r3", "r3", "계약 협의", 4400000, "2026-06-19", "2026-07-19"],
    ["a6", "수원 퍼스트캐롬 아카데미", "프로팀", "경기 수원시", "경기 수원시 팔달구 효원로 307 3층", "한태성 감독", "010-7800-4139", "r1", "r1", "접촉중", 5200000, "2026-06-25", "2026-07-25"],
  ];
  for (const item of accounts) {
    await sql`
      INSERT INTO accounts (
        id, name, category, region, address, contact_name, phone, owner_id,
        originator_id, status, expected_amount, created_at, lock_until, updated_at
      )
      VALUES (${item[0]}, ${item[1]}, ${item[2]}, ${item[3]}, ${item[4]}, ${item[5]}, ${item[6]},
        ${item[7]}, ${item[8]}, ${item[9]}, ${item[10]}, ${item[11]}, ${item[12]}, ${timestamp})
    `;
  }

  const activities = [
    ["act1", "2026-07-04", "r1", "a1", "견적 발송", "김성우 대표", "하계 단체복 38벌 기준 견적 전달. 상의 원단과 자수 위치 확인 요청.", "7월 6일 디자인 시안 전달", "2026-07-06", "방문 후 카톡으로 견적서 공유", "2026-07-04T11:10:00"],
    ["act2", "2026-07-03", "r3", "a4", "방문", "김 대표", "신규 방문으로 등록했으나 강남 브레이크 당구클럽과 동일 연락처 확인 필요.", "관리자 중복 검토", "2026-07-05", "같은 지하층 간판 사용", "2026-07-03T16:20:00"],
    ["act3", "2026-07-02", "r2", "a2", "계약 협의", "최민호 총무", "동호회 리그복 31벌 확정. 로고 파일은 메일로 수령.", "입금 확인 후 제작 진행", "2026-07-05", "부산 출장", "2026-07-02T14:30:00"],
    ["act4", "2026-07-01", "r3", "a5", "계약 협의", "문정아 회장", "협회 행사 단체복 제안. 50벌 이상 가능성 있음.", "원단 샘플 2종 발송", "2026-07-07", "전주 미팅", "2026-07-01T17:40:00"],
    ["act5", "2026-06-30", "r2", "a3", "샘플 전달", "오지훈 매니저", "기능성 상의 샘플 전달. 여성 회원 사이즈 요청.", "추가 사이즈표 전송", "2026-07-04", "대전", "2026-06-30T13:12:00"],
    ["act6", "2026-06-29", "r1", "a6", "전화", "한태성 감독", "프로팀 연습복 제안. 하반기 대회 전 교체 검토.", "선수단 사이즈 취합 요청", "2026-07-08", "전화 상담", "2026-06-29T10:05:00"],
  ];
  for (const item of activities) {
    await sql`
      INSERT INTO activities (
        id, date, rep_id, account_id, type, contact, summary, next_action,
        next_date, location_note, created_at
      )
      VALUES (${item[0]}, ${item[1]}, ${item[2]}, ${item[3]}, ${item[4]}, ${item[5]}, ${item[6]},
        ${item[7]}, ${item[8]}, ${item[9]}, ${item[10]})
    `;
  }

  await sql`
    INSERT INTO contracts (
      id, account_id, date, amount, status, originator_id, closer_id, manager_id,
      originator_share, closer_share, manager_share, memo, created_at, approved_at
    )
    VALUES
      ('c1', 'a2', '2026-07-02', 2800000, 'approved', 'r2', 'r2', 'r2', 30, 50, 20, '발굴, 계약, 사후관리가 동일 담당자.', '2026-07-02T18:15:00', '2026-07-02T18:15:00'),
      ('c2', 'a1', '2026-07-04', 3600000, 'pending', 'r1', 'r3', 'r1', 30, 50, 20, '기존 담당자와 최종 견적 담당자가 달라 관리자 확정 필요.', '2026-07-04T12:00:00', NULL)
  `;
  await sql`
    INSERT INTO audit (id, date, actor_id, action, detail)
    VALUES
      ('log1', '2026-07-04T12:00:00', 'admin', '정산 대기 등록', '강남 브레이크 당구클럽 계약 3,600,000원 배분 검토'),
      ('log2', '2026-07-03T16:20:00', 'r3', '중복 의심 거래처 등록', '강남 브레이크 클럽'),
      ('log3', '2026-07-02T18:15:00', 'admin', '정산 승인', '부산 큐하우스 계약 승인')
  `;
}

async function addAudit(sql, actorId, action, detail) {
  await sql`
    INSERT INTO audit (id, date, actor_id, action, detail)
    VALUES (${makeId("log")}, ${nowIso()}, ${actorId}, ${action}, ${detail})
  `;
}

async function currentUser(req, sql) {
  const token = parseCookies(req)[SESSION_COOKIE];
  if (!token) return null;
  const rows = await sql`
    SELECT users.* FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ${hashToken(token)} AND sessions.expires_at > ${nowIso()}
  `;
  return rows[0] || null;
}

async function requireUser(req, sql) {
  const user = await currentUser(req, sql);
  if (!user) throw apiError(401, "로그인이 필요합니다.");
  if (user.status !== "active") throw apiError(403, "활동 가능한 계정이 아닙니다.");
  return user;
}

function requireManager(user) {
  if (user.role !== "manager") throw apiError(403, "관리자 권한이 필요합니다.");
}

async function readJson(req) {
  if (req.method === "GET") return {};
  return req.json().catch(() => {
    throw apiError(400, "JSON 형식이 올바르지 않습니다.");
  });
}

async function handleLogin(req, sql) {
  const data = await readJson(req);
  const email = String(data.email || "").trim().toLowerCase();
  const password = String(data.password || "");
  const rows = await sql`SELECT * FROM users WHERE lower(email) = ${email}`;
  const user = rows[0];
  if (!user || !verifyPassword(password, user.password_hash)) throw apiError(401, "이메일 또는 비밀번호가 올바르지 않습니다.");
  if (user.status === "pending") throw apiError(403, "관리자 승인 대기 중입니다.");
  if (user.status === "suspended") throw apiError(403, "중지된 계정입니다.");
  const token = crypto.randomBytes(32).toString("base64url");
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000).toISOString();
  await sql`
    INSERT INTO sessions (token_hash, user_id, created_at, expires_at)
    VALUES (${hashToken(token)}, ${user.id}, ${nowIso()}, ${expiresAt})
  `;
  await addAudit(sql, user.id, "로그인", `${user.name} 계정 로그인`);
  return json({ user: serializeUser(user) }, 200, { "set-cookie": setCookie(token) });
}

async function handleLogout(req, sql) {
  const token = parseCookies(req)[SESSION_COOKIE];
  if (token) await sql`DELETE FROM sessions WHERE token_hash = ${hashToken(token)}`;
  return json({ ok: true }, 200, { "set-cookie": clearCookie() });
}

async function handleSignup(req, sql) {
  const data = await readJson(req);
  const required = ["name", "phone", "email", "password", "workType", "region", "coverage", "transport", "existingNetwork", "bankName", "accountHolder", "accountNumber"];
  const missing = required.filter((field) => !String(data[field] || "").trim());
  if (missing.length) throw apiError(400, `필수 입력이 빠졌습니다: ${missing.join(", ")}`);
  if (String(data.password).length < 8) throw apiError(400, "비밀번호는 8자 이상이어야 합니다.");
  if (!data.agreeOwnership || !data.agreeSettlement) throw apiError(400, "담당권과 정산 기준 동의가 필요합니다.");
  const email = String(data.email).trim().toLowerCase();
  const phone = String(data.phone).trim();
  const existing = await sql`SELECT id FROM users WHERE lower(email) = ${email} OR regexp_replace(phone, '\\D', '', 'g') = ${phoneDigits(phone)}`;
  if (existing.length) throw apiError(409, "이미 등록된 이메일 또는 휴대폰입니다.");
  const userId = makeId("r");
  await sql`
    INSERT INTO users (
      id, name, email, phone, password_hash, role, status, region, coverage,
      work_type, transport, bank_name, account_holder, account_number,
      existing_network, agreements, joined_at, approved_at, created_at, updated_at
    )
    VALUES (
      ${userId}, ${String(data.name).trim()}, ${email}, ${phone}, ${passwordHash(data.password)}, 'sales', 'pending',
      ${String(data.region).trim()}, ${String(data.coverage).trim()}, ${String(data.workType).trim()},
      ${String(data.transport).trim()}, ${String(data.bankName).trim()}, ${String(data.accountHolder).trim()},
      ${String(data.accountNumber).trim()}, ${String(data.existingNetwork).trim()},
      ${JSON.stringify({ ownership: true, settlement: true })}, ${TODAY}, '', ${nowIso()}, ${nowIso()}
    )
  `;
  await addAudit(sql, userId, "영업사원 가입 신청", `${String(data.name).trim()} · ${String(data.region).trim()}`);
  return json({ ok: true, status: "pending" }, 201);
}

async function handleBootstrap(req, sql, user) {
  let users;
  let accounts;
  let activities;
  let contracts;
  let audit;
  if (user.role === "manager") {
    users = await sql`SELECT * FROM users ORDER BY role, status, name`;
    accounts = await sql`SELECT * FROM accounts ORDER BY name`;
    activities = await sql`SELECT * FROM activities ORDER BY date DESC, created_at DESC LIMIT 250`;
    contracts = await sql`SELECT * FROM contracts ORDER BY date DESC, created_at DESC`;
    audit = await sql`SELECT * FROM audit ORDER BY date DESC LIMIT 120`;
  } else {
    users = await sql`SELECT * FROM users WHERE role = 'sales' AND (status = 'active' OR id = ${user.id}) ORDER BY name`;
    accounts = await sql`SELECT * FROM accounts WHERE owner_id = ${user.id} OR originator_id = ${user.id} ORDER BY name`;
    const accountIds = accounts.map((item) => item.id);
    activities = accountIds.length
      ? await sql`SELECT * FROM activities WHERE rep_id = ${user.id} OR account_id = ANY(${accountIds}) ORDER BY date DESC, created_at DESC LIMIT 250`
      : await sql`SELECT * FROM activities WHERE rep_id = ${user.id} ORDER BY date DESC, created_at DESC LIMIT 250`;
    contracts = await sql`
      SELECT * FROM contracts
      WHERE originator_id = ${user.id} OR closer_id = ${user.id} OR manager_id = ${user.id}
      ORDER BY date DESC, created_at DESC
    `;
    audit = await sql`SELECT * FROM audit WHERE actor_id = ${user.id} ORDER BY date DESC LIMIT 80`;
  }
  return json({
    me: serializeUser(user),
    users: users.map((row) => serializeUser(row)),
    accounts: accounts.map(serializeAccount),
    activities: activities.map(serializeActivity),
    contracts: contracts.map(serializeContract),
    audit,
    today: TODAY,
  });
}

async function handleCreateAccount(req, sql, user) {
  const data = await readJson(req);
  const required = ["name", "category", "region", "address", "ownerId"];
  const missing = required.filter((field) => !String(data[field] || "").trim());
  if (missing.length) throw apiError(400, `필수 입력이 빠졌습니다: ${missing.join(", ")}`);
  const ownerId = user.role === "manager" ? data.ownerId : user.id;
  const owner = await sql`SELECT * FROM users WHERE id = ${ownerId} AND role = 'sales' AND status = 'active'`;
  if (!owner.length) throw apiError(400, "활동중인 영업사원만 담당자로 지정할 수 있습니다.");
  const candidate = {
    name: String(data.name).trim(),
    address: String(data.address).trim(),
    phone: String(data.phone || "").trim(),
    region: String(data.region).trim(),
  };
  const existingRows = await sql`SELECT * FROM accounts`;
  const existingAccounts = existingRows.map(serializeAccount);
  const duplicates = existingAccounts
    .map((account) => ({ account, score: duplicateScore(candidate, account) }))
    .filter((item) => item.score >= 45)
    .sort((a, b) => b.score - a.score);
  const status = duplicates[0]?.score >= 70 ? "중복 검토" : "신규";
  const accountId = makeId("a");
  await sql`
    INSERT INTO accounts (
      id, name, category, region, address, contact_name, phone, owner_id,
      originator_id, status, expected_amount, created_at, lock_until, updated_at
    )
    VALUES (
      ${accountId}, ${candidate.name}, ${String(data.category).trim()}, ${candidate.region}, ${candidate.address},
      ${String(data.contactName || "").trim()}, ${candidate.phone}, ${ownerId}, ${ownerId}, ${status},
      ${Number(data.expectedAmount || 0)}, ${TODAY}, ${addDays(TODAY, 30)}, ${nowIso()}
    )
  `;
  await addAudit(sql, user.id, status === "신규" ? "거래처 등록" : "중복 의심 거래처 등록", candidate.name);
  const rows = await sql`SELECT * FROM accounts WHERE id = ${accountId}`;
  return json({ account: serializeAccount(rows[0]), duplicates: duplicates.slice(0, 5) }, 201);
}

async function handleCreateActivity(req, sql, user) {
  const data = await readJson(req);
  const required = ["date", "repId", "accountId", "type", "summary"];
  const missing = required.filter((field) => !String(data[field] || "").trim());
  if (missing.length) throw apiError(400, `필수 입력이 빠졌습니다: ${missing.join(", ")}`);
  const repId = user.role === "manager" ? data.repId : user.id;
  const reps = await sql`SELECT id FROM users WHERE id = ${repId} AND role = 'sales' AND status = 'active'`;
  if (!reps.length) throw apiError(400, "활동중인 영업사원만 기록할 수 있습니다.");
  const accounts = await sql`SELECT * FROM accounts WHERE id = ${data.accountId}`;
  const account = accounts[0];
  if (!account) throw apiError(404, "거래처를 찾을 수 없습니다.");
  if (user.role !== "manager" && account.owner_id !== user.id) throw apiError(403, "내 담당 거래처에만 활동을 기록할 수 있습니다.");
  const statusMap = {
    방문: "접촉중",
    전화: "접촉중",
    카톡: "접촉중",
    "샘플 전달": "샘플 전달",
    "견적 발송": "견적중",
    "계약 협의": "계약 협의",
    사후관리: "계약완료",
  };
  const activityId = makeId("act");
  await sql`
    INSERT INTO activities (
      id, date, rep_id, account_id, type, contact, summary, next_action,
      next_date, location_note, created_at
    )
    VALUES (
      ${activityId}, ${data.date}, ${repId}, ${data.accountId}, ${data.type}, ${String(data.contact || "").trim()},
      ${String(data.summary).trim()}, ${String(data.nextAction || "").trim()}, ${String(data.nextDate || "").trim()},
      ${String(data.locationNote || "").trim()}, ${nowIso()}
    )
  `;
  await sql`
    UPDATE accounts
    SET status = ${statusMap[data.type] || account.status}, lock_until = ${addDays(data.date, 30)}, updated_at = ${nowIso()}
    WHERE id = ${data.accountId}
  `;
  await addAudit(sql, user.id, "영업 활동 저장", `${account.name} · ${data.type}`);
  const rows = await sql`SELECT * FROM activities WHERE id = ${activityId}`;
  return json({ activity: serializeActivity(rows[0]) }, 201);
}

async function handleCreateContract(req, sql, user) {
  const data = await readJson(req);
  const shares = data.shares || {};
  const originatorShare = Number(shares.originator || 0);
  const closerShare = Number(shares.closer || 0);
  const managerShare = Number(shares.manager || 0);
  if (originatorShare + closerShare + managerShare !== 100) throw apiError(400, "성과 배분 합계는 100%여야 합니다.");
  const accounts = await sql`SELECT * FROM accounts WHERE id = ${data.accountId}`;
  const account = accounts[0];
  if (!account) throw apiError(404, "거래처를 찾을 수 없습니다.");
  if (user.role !== "manager" && account.owner_id !== user.id) throw apiError(403, "내 담당 거래처 계약만 등록할 수 있습니다.");
  const contractId = makeId("c");
  await sql`
    INSERT INTO contracts (
      id, account_id, date, amount, status, originator_id, closer_id, manager_id,
      originator_share, closer_share, manager_share, memo, created_at, approved_at
    )
    VALUES (
      ${contractId}, ${data.accountId}, ${data.date}, ${Number(data.amount)}, 'pending',
      ${data.originatorId}, ${data.closerId}, ${data.managerId}, ${originatorShare}, ${closerShare}, ${managerShare},
      ${String(data.memo || "").trim()}, ${nowIso()}, NULL
    )
  `;
  await sql`
    UPDATE accounts SET status = '계약완료', lock_until = ${addDays(data.date, 60)}, updated_at = ${nowIso()}
    WHERE id = ${data.accountId}
  `;
  await addAudit(sql, user.id, "정산 대기 등록", `${account.name} · ${Number(data.amount).toLocaleString("ko-KR")}원`);
  const rows = await sql`SELECT * FROM contracts WHERE id = ${contractId}`;
  return json({ contract: serializeContract(rows[0]) }, 201);
}

async function handleUpdateUserStatus(req, sql, user, targetId) {
  requireManager(user);
  const data = await readJson(req);
  if (!["active", "pending", "suspended"].includes(data.status)) throw apiError(400, "상태 값이 올바르지 않습니다.");
  if (targetId === user.id) throw apiError(400, "본인 관리자 계정 상태는 변경할 수 없습니다.");
  const rows = await sql`SELECT * FROM users WHERE id = ${targetId}`;
  const target = rows[0];
  if (!target) throw apiError(404, "사용자를 찾을 수 없습니다.");
  const approvedAt = data.status === "active" ? TODAY : target.approved_at;
  await sql`UPDATE users SET status = ${data.status}, approved_at = ${approvedAt}, updated_at = ${nowIso()} WHERE id = ${targetId}`;
  await addAudit(sql, user.id, data.status === "active" ? "영업사원 승인" : "영업사원 중지", `${target.name} · ${target.region}`);
  const updated = await sql`SELECT * FROM users WHERE id = ${targetId}`;
  return json({ user: serializeUser(updated[0]) });
}

async function handleUpdateAccount(req, sql, user, accountId) {
  const data = await readJson(req);
  const rows = await sql`SELECT * FROM accounts WHERE id = ${accountId}`;
  const account = rows[0];
  if (!account) throw apiError(404, "거래처를 찾을 수 없습니다.");
  if (user.role !== "manager" && account.owner_id !== user.id) throw apiError(403, "내 담당 거래처만 수정할 수 있습니다.");
  if (data.ownerId && user.role !== "manager") throw apiError(403, "담당자 변경은 관리자만 가능합니다.");
  if (Object.hasOwn(data, "status")) {
    await sql`UPDATE accounts SET status = ${data.status}, updated_at = ${nowIso()} WHERE id = ${accountId}`;
  }
  if (Object.hasOwn(data, "lockUntil")) {
    await sql`UPDATE accounts SET lock_until = ${data.lockUntil}, updated_at = ${nowIso()} WHERE id = ${accountId}`;
  }
  if (Object.hasOwn(data, "expectedAmount")) {
    await sql`UPDATE accounts SET expected_amount = ${Number(data.expectedAmount)}, updated_at = ${nowIso()} WHERE id = ${accountId}`;
  }
  if (Object.hasOwn(data, "ownerId")) {
    await sql`UPDATE accounts SET owner_id = ${data.ownerId}, updated_at = ${nowIso()} WHERE id = ${accountId}`;
  }
  await addAudit(sql, user.id, "거래처 수정", account.name);
  const updated = await sql`SELECT * FROM accounts WHERE id = ${accountId}`;
  return json({ account: serializeAccount(updated[0]) });
}

async function handleApproveContract(req, sql, user, contractId) {
  requireManager(user);
  const rows = await sql`SELECT * FROM contracts WHERE id = ${contractId}`;
  const contract = rows[0];
  if (!contract) throw apiError(404, "계약을 찾을 수 없습니다.");
  await sql`UPDATE contracts SET status = 'approved', approved_at = ${nowIso()} WHERE id = ${contractId}`;
  const accountRows = await sql`SELECT name FROM accounts WHERE id = ${contract.account_id}`;
  await addAudit(sql, user.id, "정산 승인", `${accountRows[0]?.name || "거래처"} · ${Number(contract.amount).toLocaleString("ko-KR")}원`);
  const updated = await sql`SELECT * FROM contracts WHERE id = ${contractId}`;
  return json({ contract: serializeContract(updated[0]) });
}

async function handleSettlements(req, sql, user, url) {
  const month = url.searchParams.get("month") || TODAY.slice(0, 7);
  let users;
  let contracts;
  if (user.role === "manager") {
    users = await sql`SELECT * FROM users WHERE role = 'sales' ORDER BY name`;
    contracts = await sql`SELECT * FROM contracts WHERE status = 'approved' AND substr(date, 1, 7) = ${month}`;
  } else {
    users = await sql`SELECT * FROM users WHERE id = ${user.id}`;
    contracts = await sql`
      SELECT * FROM contracts
      WHERE status = 'approved' AND substr(date, 1, 7) = ${month}
      AND (originator_id = ${user.id} OR closer_id = ${user.id} OR manager_id = ${user.id})
    `;
  }
  const rows = users.map((salesUser) => {
    let amount = 0;
    let count = 0;
    for (const contract of contracts) {
      let participated = false;
      if (contract.originator_id === salesUser.id) {
        amount += Number(contract.amount) * (Number(contract.originator_share) / 100);
        participated = true;
      }
      if (contract.closer_id === salesUser.id) {
        amount += Number(contract.amount) * (Number(contract.closer_share) / 100);
        participated = true;
      }
      if (contract.manager_id === salesUser.id) {
        amount += Number(contract.amount) * (Number(contract.manager_share) / 100);
        participated = true;
      }
      if (participated) count += 1;
    }
    return { user: serializeUser(salesUser), amount: Math.round(amount), count };
  });
  return json({ month, rows });
}

export default async function handler(req) {
  try {
    const sql = sqlClient();
    await ensureSchema(sql);
    const url = new URL(req.url);
    const path = url.pathname.replace(/^\/\.netlify\/functions\/api/, "/api");
    const method = req.method.toUpperCase();

    if (method === "GET" && path === "/api/health") return json({ ok: true, name: "Billywear KKLLA Netlify API" });
    if (method === "POST" && path === "/api/login") return await handleLogin(req, sql);
    if (method === "POST" && path === "/api/logout") return await handleLogout(req, sql);
    if (method === "POST" && path === "/api/signup") return await handleSignup(req, sql);

    const user = await requireUser(req, sql);
    if (method === "GET" && path === "/api/me") return json({ user: serializeUser(user) });
    if (method === "GET" && path === "/api/bootstrap") return await handleBootstrap(req, sql, user);
    if (method === "GET" && path === "/api/settlements") return await handleSettlements(req, sql, user, url);
    if (method === "POST" && path === "/api/accounts") return await handleCreateAccount(req, sql, user);
    if (method === "POST" && path === "/api/activities") return await handleCreateActivity(req, sql, user);
    if (method === "POST" && path === "/api/contracts") return await handleCreateContract(req, sql, user);

    const userStatusMatch = path.match(/^\/api\/users\/([^/]+)\/status$/);
    if (method === "PATCH" && userStatusMatch) return await handleUpdateUserStatus(req, sql, user, userStatusMatch[1]);
    const accountMatch = path.match(/^\/api\/accounts\/([^/]+)$/);
    if (method === "PATCH" && accountMatch) return await handleUpdateAccount(req, sql, user, accountMatch[1]);
    const approveMatch = path.match(/^\/api\/contracts\/([^/]+)\/approve$/);
    if (method === "PATCH" && approveMatch) return await handleApproveContract(req, sql, user, approveMatch[1]);

    throw apiError(404, "요청한 API를 찾을 수 없습니다.");
  } catch (error) {
    return json({ error: error.message || "서버 오류" }, error.status || 500);
  }
}

export const config = {
  path: "/api/*",
};
