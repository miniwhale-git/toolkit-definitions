// Downloads for the build. Every failure names the URL and the status. Only https, only the
// listed hosts (also after a redirect), a size cap per file, a few tries on a network or server error.

export const ALLOWED_HOSTS = new Set(["raw.githubusercontent.com", "hole.cert.pl", "api.github.com"]);

/** An error that trying again will not fix. */
class Final extends Error {}

/**
 * @param {{ fetchImpl?: typeof fetch, hosts?: Set<string>, tries?: number, delayMs?: number, timeoutMs?: number, log?: (s: string) => void }} [options]
 * @returns {((url: string, maxBytes: number) => Promise<string>) & { bytes: (url: string, maxBytes: number) => Promise<Buffer> }}
 */
export function makeFetcher({ fetchImpl = fetch, hosts = ALLOWED_HOSTS, tries = 3, delayMs = 2000, timeoutMs = 90_000, log = () => {} } = {}) {
  async function once(url, maxBytes) {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:" || !hosts.has(parsed.hostname)) {
      throw new Final(`refusing ${url}: only https from ${[...hosts].join(", ")}`);
    }
    const headers = { "User-Agent": "toolkit-definitions-build" };
    if (parsed.hostname === "api.github.com" && process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
    const response = await fetchImpl(url, { redirect: "follow", headers, signal: AbortSignal.timeout(timeoutMs) });
    if (response.url && !hosts.has(new URL(response.url).hostname)) throw new Final(`${url} redirected to ${response.url}`);
    if (response.status >= 500) throw new Error(`HTTP ${response.status}`);
    if (!response.ok) throw Object.assign(new Final(`${url}: HTTP ${response.status}`), { status: response.status });
    const declared = Number(response.headers.get("content-length"));
    if (declared > maxBytes) throw new Final(`${url}: ${declared} bytes is over the ${maxBytes} byte limit`);
    const chunks = [];
    let size = 0;
    for await (const chunk of response.body) {
      size += chunk.length;
      if (size > maxBytes) throw new Final(`${url}: more than ${maxBytes} bytes`);
      chunks.push(chunk);
    }
    return Buffer.concat(chunks);
  }

  async function bytes(url, maxBytes) {
    let lastError;
    for (let attempt = 1; attempt <= tries; attempt++) {
      try {
        return await once(url, maxBytes);
      } catch (error) {
        if (error instanceof Final) throw error;
        lastError = new Error(`${url}: ${error.cause?.code ?? error.message}`);
        if (attempt < tries) {
          log(`${lastError.message}, trying again`);
          await new Promise((resolve) => setTimeout(resolve, delayMs * attempt));
        }
      }
    }
    throw lastError;
  }

  return Object.assign(async (url, maxBytes) => (await bytes(url, maxBytes)).toString("utf8"), { bytes });
}
