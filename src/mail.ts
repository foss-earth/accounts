import type { Mailer } from "./app.js";

/** Sends through a Resend-compatible HTTPS API. The token stays on this process. */
export function httpsMailer(options: { url: string; token: string; from: string; fetch?: typeof fetch }): Mailer {
  const send = options.fetch ?? fetch;
  return {
    async send(message) {
      const response = await send(options.url, {
        method: "POST",
        headers: { authorization: `Bearer ${options.token}`, "content-type": "application/json" },
        body: JSON.stringify({ from: options.from, to: [message.to], subject: message.subject, text: message.text }),
      });
      if (!response.ok) throw new Error(`Mail API returned ${response.status}.`);
    },
  };
}
