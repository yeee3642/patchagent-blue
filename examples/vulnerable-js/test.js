const assert = require("node:assert/strict");
const { parseExpr } = require("./app");

assert.deepEqual(parseExpr("[1, 2]"), [1, 2]);
