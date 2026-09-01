import { buildErrorBody, sanitizeErrorMessage, sanitizeUpstreamDetails } from "./error.ts";

interface SanitizedUpstreamErrorResponseOptions {
  status: number;
  rawBody: string;
  fallbackMessage: string;
  headers?: Record<string, string>;
}

/**
 * Preserve a provider's JSON error shape while applying the canonical recursive sanitizer.
 * Providers sometimes label plain text as JSON; those bodies use OmniRoute's canonical error
 * envelope so the advertised content type always matches the response bytes.
 */
export function buildSanitizedUpstreamErrorResponse({
  status,
  rawBody,
  fallbackMessage,
  headers,
}: SanitizedUpstreamErrorResponseOptions): Response {
  const trimmedBody = rawBody.trim();

  if (trimmedBody) {
    try {
      const parsedBody: unknown = JSON.parse(trimmedBody);
      const serializedBody = JSON.stringify(sanitizeUpstreamDetails(parsedBody));
      if (serializedBody !== undefined) {
        return new Response(serializedBody, {
          status,
          headers: { ...headers, "Content-Type": "application/json" },
        });
      }
    } catch {
      // Upstreams commonly return text or HTML despite an application/json response header.
      // Treat it as an opaque message and use the canonical JSON envelope below.
    }
  }

  const safeMessage =
    sanitizeErrorMessage(`Upstream error: ${trimmedBody}`)
      .replace(/^Upstream error:\s*/, "")
      .trim() || fallbackMessage;
  return new Response(JSON.stringify(buildErrorBody(status, safeMessage)), {
    status,
    headers: { ...headers, "Content-Type": "application/json" },
  });
}
