// Replays recorded responses (test/fixtures/sources.json.gz) for the golden tests. Keys carry the
// method and body too: OSV's package queries are POSTs that differ only in their bodies.
import { readFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { buildServer, createContext } from "../src/server.mjs";
import { NOW } from "./scenarios.mjs";

export const fixtureKey = (url, init = {}) => {
  const u = new URL(url);
  return `${init.method ?? "GET"} ${u.host}${u.pathname}${u.search}${init.body ? ` ${init.body}` : ""}`;
};

export const loadFixtures = () => JSON.parse(gunzipSync(readFileSync(new URL("./fixtures/sources.json.gz", import.meta.url))).toString("utf8"));

export function replayFetch(fixtures = loadFixtures()) {
  const calls = [];
  const impl = async (url, init) => {
    const key = fixtureKey(url, init);
    calls.push(key);
    const hit = fixtures[key];
    if (!hit) throw new Error(`no fixture for ${key}`);
    return new Response(hit.body, { status: hit.status });
  };
  return { impl, calls };
}

export async function connect(fetchImpl = replayFetch().impl) {
  const server = buildServer(createContext({ fetchImpl, now: () => NOW }));
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "golden", version: "0" });
  await Promise.all([server.connect(a), client.connect(b)]);
  // Like a real client: once the tools are listed, every result is validated against its schema.
  await client.listTools();
  return client;
}

export async function call(client, name, args) {
  const res = await client.callTool({ name, arguments: args });
  return { res, data: res.structuredContent ?? JSON.parse(res.content[0].text) };
}
