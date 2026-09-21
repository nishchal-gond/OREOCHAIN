/**
 * Putting values on the page without letting them become markup.
 *
 * Almost every string this application displays came from somewhere else: a
 * CID and a `kid` from the gateway, a transaction hash and an exporter address
 * from the chain, a refusal code out of a JSON body, a filename out of a
 * manifest that a stranger uploaded. The pages render those next to icons and
 * links, so the natural thing to write is a template literal into
 * `innerHTML` — and that turns every one of those strings into markup that the
 * page will parse.
 *
 * The content security policy this repository ships (`script-src 'self'
 * https:`, no `'unsafe-inline'`) stops the injected markup from running
 * script: an `onerror=` attribute is inline script and is refused. It does not
 * stop the markup from being *there*. A hostile or compromised gateway that
 * can put arbitrary HTML into the page it serves can draw a passphrase box in
 * it, and the passphrase box is the one thing on this site that must never be
 * drawn by anybody but this code. So the escaping is not a second line of
 * defence behind the policy; it is the line, and the policy is behind it.
 *
 * The tag below makes the safe thing the short thing. In
 *
 *     html`<i class="fa-solid fa-box mx-1"></i>${manifestCID}`
 *
 * the literal parts are markup because this file's author wrote them, and
 * every interpolation is escaped because its author is someone else. There is
 * no variant that interpolates a string as markup, on purpose: markup belongs
 * in the literal. Where a fragment genuinely has to be built up in pieces,
 * interpolate the result of another `html` tag and it passes through intact —
 * which is the only way to pass through, and it is visible at the call site.
 */

const SAFE = Symbol("oreochain.safeHtml");

const ESCAPES = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

/**
 * Escape a value for insertion anywhere in a document — text or attribute.
 *
 * Quotes are escaped as well as angle brackets because these templates
 * interpolate into `href="…"` as readily as into text, and a value carrying a
 * double quote escapes an attribute just as surely as one carrying `<`
 * escapes a text node. `&` goes first or it would double-escape the others.
 *
 * `null` and `undefined` render as the empty string rather than as the words
 * "null" and "undefined": a missing block number should leave a gap, not tell
 * the user about a variable.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function escapeHtml(value) {
  if (value === null || value === undefined) return "";
  return String(value).replace(/[&<>"']/g, (char) => ESCAPES[char]);
}

/**
 * Tagged template that escapes every interpolation.
 *
 * @param {TemplateStringsArray} strings
 * @param {...unknown} values
 * @returns {{toString: () => string}} an opaque safe-markup value
 */
export function html(strings, ...values) {
  let out = strings[0];
  for (let i = 0; i < values.length; i += 1) {
    out += isSafeHtml(values[i]) ? values[i].value : escapeHtml(values[i]);
    out += strings[i + 1];
  }
  return safe(out);
}

/**
 * Mark a string as markup this code wrote.
 *
 * For a static fragment with nothing interpolated into it, where the tag would
 * be noise. Never call it on anything that came off the network — there is no
 * legitimate use for that, and the name is meant to be hard to write by
 * accident in a review.
 *
 * @param {string} markup
 */
export function safe(markup) {
  return { [SAFE]: true, value: String(markup), toString: () => String(markup) };
}

/** @param {unknown} value */
export function isSafeHtml(value) {
  return Boolean(value && typeof value === "object" && value[SAFE] === true);
}

/**
 * What to hand to `innerHTML`.
 *
 * A safe value passes through; anything else is escaped. That default is the
 * point of the module: a call site that forgets the tag renders its value as
 * text, which is wrong-looking and harmless, rather than as markup, which is
 * right-looking and a hole.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function toHtml(value) {
  return isSafeHtml(value) ? value.value : escapeHtml(value);
}

/**
 * Join safe fragments into one safe fragment.
 *
 * A list of cards built with the tag becomes an ordinary string the moment it
 * is `.join("")`ed, and an ordinary string is escaped wholesale by `toHtml` —
 * correct, but it renders the markup as text. This is the joining that keeps
 * the guarantee, and it refuses anything in the list that was not built with
 * the tag rather than quietly escaping or quietly trusting it.
 *
 * @param {unknown[]} values
 * @param {string} [separator]
 */
export function joinHtml(values, separator = "") {
  const parts = values.map((value) => {
    if (!isSafeHtml(value)) throw new TypeError("joinHtml takes html`` fragments");
    return value.value;
  });
  return safe(parts.join(separator));
}
