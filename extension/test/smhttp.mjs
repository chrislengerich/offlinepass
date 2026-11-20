/**
 * THE SMART-HTTP GIT SERVER (the test fixture): the `git http-backend`
 * CGI behind a minimal Node HTTP server. The env per the request:
 * GIT_PROJECT_ROOT, GIT_HTTP_EXPORT_ALL, PATH_INFO, the QUERY_STRING,
 * the method, the content headers — the CGI's stdin = the request body;
 * the CGI's stdout = the response (the status header + the body).
 *
 * The auth: the Basic — the token must equal FIXTURE_TOKEN or 401.
 */
import http from "node:http";
import { spawn } from "node:child_process";

export const FIXTURE_TOKEN = "test-token-1234";

export function startSmartHttp(gitProjectRoot, port = 0) {
  const server = http.createServer(async (req, res) => {
    // The Basic auth: the token in the password position.
    const auth = req.headers.authorization || "";
    const expected = "Basic " + Buffer.from(`x:${FIXTURE_TOKEN}`).toString("base64");
    if (auth !== expected) {
      res.writeHead(401, { "WWW-Authenticate": 'Basic realm="test"' });
      return res.end("auth required");
    }
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks);

    const env = {
      ...process.env,
      GIT_PROJECT_ROOT: gitProjectRoot,
      GIT_HTTP_EXPORT_ALL: "1",
      PATH_INFO: req.url.split("?")[0],
      QUERY_STRING: (req.url.split("?")[1] || ""),
      REQUEST_METHOD: req.method,
      CONTENT_TYPE: req.headers["content-type"] || "",
      CONTENT_LENGTH: String(body.length),
      REMOTE_ADDR: "127.0.0.1",
      GIT_PROTOCOL: req.headers["git-protocol"] || "",
    };
    const cgi = spawn("git", ["http-backend"], { env });
    let out = [];
    let head = Buffer.alloc(0);
    cgi.stdout.on("data", (d) => {
      out.push(d);
      const buf = Buffer.concat(out);
      const idx = buf.indexOf("\r\n\r\n");
      if (idx >= 0 && res.headersSent === false) {
        const headerText = buf.slice(0, idx).toString();
        for (const line of headerText.split("\r\n")) {
          const i = line.indexOf(":");
          if (i > 0) res.setHeader(line.slice(0, i).trim(), line.slice(i + 1).trim());
        }
        res.writeHead(res.getHeader("Status")?.split(" ")[0] || 200);
        res.write(buf.slice(idx + 4));
      } else if (res.headersSent !== false) {
        res.write(d);
      }
    });
    cgi.stderr.on("data", () => { /* the diagnostics */ });
    if (body.length) cgi.stdin.write(body);
    cgi.stdin.end();
    cgi.on("close", () => { if (res.writableEnded === false) res.end(); });
    req.on("close", () => { try { cgi.kill(); } catch (e) { /* */ } });
  });
  return new Promise((resolve) => server.listen(port, "127.0.0.1", () => resolve({
    server,
    url: `http://127.0.0.1:${server.address().port}/test.git`,
    close: () => server.close(),
  })));
}
