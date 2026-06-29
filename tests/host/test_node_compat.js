const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const jwt = require("jsonwebtoken");

const version = require("jsonwebtoken/package.json").version;
if (version !== "9.0.3") {
  throw new Error(`Expected jsonwebtoken 9.0.3, got ${version}`);
}

const cli = process.argv[2];
if (!cli) {
  throw new Error("Usage: node test_node_compat.js /path/to/seal_compat_cli");
}

const secret = "super-secret";
const payload = {
  deviceId: "panel-01",
  iss: "issuer-1",
  sub: "device-01",
  aud: "api",
  jti: "jwt-1",
  iat: 100,
  nbf: 90,
  exp: 200,
};

function runCli(args) {
  const result = spawnSync(cli, args, { encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(
      `seal_compat_cli ${args[0]} failed: ${result.stderr || result.stdout}`
    );
  }
  return result.stdout.trim();
}

const nodeToken = jwt.sign(payload, secret, {
  algorithm: "HS256",
  header: { typ: "not-jwt" },
});
assert.equal(runCli(["verify", nodeToken]), "OK");

const lowerTypToken = jwt.sign(payload, secret, {
  algorithm: "HS256",
  header: { typ: "jwt" },
});
assert.equal(runCli(["verify", lowerTypToken]), "OK");

const sealToken = runCli(["sign"]);
const verified = jwt.verify(sealToken, secret, {
  algorithms: ["HS256"],
  clockTimestamp: 150,
  issuer: "issuer-1",
  subject: "device-01",
  audience: "api",
  jwtid: "jwt-1",
  maxAge: "100s",
});

assert.equal(verified.deviceId, "panel-01");
assert.equal(verified.iat, 100);
assert.equal(verified.nbf, 90);
assert.equal(verified.exp, 200);

console.log("node compatibility tests passed");
