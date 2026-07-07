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
