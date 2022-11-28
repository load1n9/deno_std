// Copyright 2018-2022 the Deno authors. All rights reserved. MIT license.
// Copyright Joyent and Node contributors. All rights reserved. MIT license.
// deno-lint-ignore-file no-explicit-any

import {
  ObjectAssign,
  StringPrototypeReplace,
} from "./internal/primordials.mjs";
import assert from "./internal/assert.mjs";
import * as net from "./net.ts";
import { createSecureContext } from "./_tls_common.ts";
import { kStreamBaseField } from "./internal_binding/stream_wrap.ts";
import {
  connResetException,
  ERR_OUT_OF_RANGE,
  ERR_TLS_CERT_ALTNAME_FORMAT,
ERR_TLS_CERT_ALTNAME_INVALID,
} from "./internal/errors.ts";
import { emitWarning } from "./process.ts";
import { debuglog } from "./internal/util/debuglog.ts";
import { constants as TCPConstants, TCP } from "./internal_binding/tcp_wrap.ts";
import {
  constants as PipeConstants,
  Pipe,
} from "./internal_binding/pipe_wrap.ts";
import { EventEmitter } from "./events.ts";
import { kEmptyObject } from "./internal/util.mjs";
import { Buffer } from "./buffer.ts";
const kConnectOptions = Symbol("connect-options");
const kIsVerified = Symbol("verified");
const kPendingSession = Symbol("pendingSession");
const kRes = Symbol("res");

let _debug = debuglog("tls", (fn) => {
  _debug = fn;
});

function onConnectEnd(this: any) {
  // NOTE: This logic is shared with _http_client.js
  if (!this._hadError) {
    const options = this[kConnectOptions];
    this._hadError = true;
    const error: any = connResetException(
      "Client network socket disconnected " +
        "before secure TLS connection was " +
        "established",
    );
    error.path = options.path;
    error.host = options.host;
    error.port = options.port;
    error.localAddress = options.localAddress;
    this.destroy(error);
  }
}

export class TLSSocket extends net.Socket {
  _tlsOptions: any;
  _secureEstablished: boolean;
  _securePending: boolean;
  _newSessionPending: boolean;
  _controlReleased: boolean;
  secureConnecting: boolean;
  _SNICallback: any;
  servername: string | null;
  alpnProtocol: any;
  authorized: boolean;
  authorizationError: any;
  [kRes]: any;
  [kIsVerified]: boolean;
  [kPendingSession]: any;
  [kConnectOptions]: any;
  ssl: any;
  _start: any;
  constructor(socket: any, opts: any = kEmptyObject) {
    const tlsOptions = { ...opts };

    let hostname = tlsOptions?.secureContext?.servername;
    hostname = opts.host;
    tlsOptions.hostname = hostname;

    const _cert = tlsOptions?.secureContext?.cert;
    const _key = tlsOptions?.secureContext?.key;

    let caCerts = tlsOptions?.secureContext?.ca;
    if (typeof caCerts === "string") caCerts = [caCerts];
    tlsOptions.caCerts = caCerts;

    super({
      handle: _wrapHandle(tlsOptions, socket),
      ...opts,
      manualStart: true, // This prevents premature reading from TLS handle
    });
    if (socket) {
      this._parent = socket;
    }
    this._tlsOptions = tlsOptions;
    this._secureEstablished = false;
    this._securePending = false;
    this._newSessionPending = false;
    this._controlReleased = false;
    this.secureConnecting = true;
    this._SNICallback = null;
    this.servername = null;
    this.alpnProtocol = null;
    this.authorized = false;
    this.authorizationError = null;
    this[kRes] = null;
    this[kIsVerified] = false;
    this[kPendingSession] = null;

    this.ssl = new class {
      verifyError() {
        return null; // Never fails, rejectUnauthorized is always true in Deno.
      }
    }();

    // deno-lint-ignore no-this-alias
    const tlssock = this;

    /** Wraps the given socket and adds the tls capability to the underlying
     * handle */
    function _wrapHandle(tlsOptions: any, wrap: net.Socket | undefined) {
      let handle: any;

      if (wrap) {
        handle = wrap._handle;
      }

      const options = tlsOptions;
      if (!handle) {
        handle = options.pipe
          ? new Pipe(PipeConstants.SOCKET)
          : new TCP(TCPConstants.SOCKET);
      }

      // Patches `afterConnect` hook to replace TCP conn with TLS conn
      const afterConnect = handle.afterConnect;
      handle.afterConnect = async (req: any, status: number) => {
        try {
          const conn = await Deno.startTls(handle[kStreamBaseField], options);
          tlssock.emit("secure");
          tlssock.removeListener("end", onConnectEnd);
          handle[kStreamBaseField] = conn;
        } catch {
          // TODO(kt3k): Handle this
        }
        return afterConnect.call(handle, req, status);
      };

      (handle as any).verifyError = function () {
        return null; // Never fails, rejectUnauthorized is always true in Deno.
      };
      // Pretends `handle` is `tls_wrap.wrap(handle, ...)` to make some npm modules happy
      // An example usage of `_parentWrap` in npm module:
      // https://github.com/szmarczak/http2-wrapper/blob/51eeaf59ff9344fb192b092241bfda8506983620/source/utils/js-stream-socket.js#L6
      handle._parent = handle;
      handle._parentWrap = wrap;

      return handle;
    }
  }

  _tlsError(err: Error) {
    this.emit("_tlsError", err);
    if (this._controlReleased) {
      return err;
    }
    return null;
  }

  _releaseControl() {
    if (this._controlReleased) {
      return false;
    }
    this._controlReleased = true;
    this.removeListener("error", this._tlsError);
    return true;
  }

  getEphemeralKeyInfo() {
    return {};
  }

  isSessionReused() {
    return false;
  }

  setSession(_session: any) {
    // TODO(kt3k): implement this
  }

  setServername(_servername: any) {
    // TODO(kt3k): implement this
  }

  getPeerCertificate(_detailed: boolean) {
    // TODO(kt3k): implement this
    return {
      subject: "localhost",
      subjectaltname: "IP Address:127.0.0.1, IP Address:::1",
    };
  }
}

function normalizeConnectArgs(listArgs: any) {
  const args = net._normalizeArgs(listArgs);
  const options = args[0];
  const cb = args[1];

  // If args[0] was options, then normalize dealt with it.
  // If args[0] is port, or args[0], args[1] is host, port, we need to
  // find the options and merge them in, normalize's options has only
  // the host/port/path args that it knows about, not the tls options.
  // This means that options.host overrides a host arg.
  if (listArgs[1] !== null && typeof listArgs[1] === "object") {
    ObjectAssign(options, listArgs[1]);
  } else if (listArgs[2] !== null && typeof listArgs[2] === "object") {
    ObjectAssign(options, listArgs[2]);
  }

  return cb ? [options, cb] : [options];
}

let ipServernameWarned = false;

export function Server(options: any, listener: any) {
  return new ServerImpl(options, listener);
}

export class ServerImpl extends EventEmitter {
  listener?: Deno.TlsListener;
  #closed = false;
  constructor(public options: any, listener: any) {
    super();
    if (listener) {
      this.on("secureConnection", listener);
    }
  }

  listen(port: any, callback: any): this {
    const { key, cert } = this.options;

    // TODO(kt3k): Get this from optional 2nd argument.
    const hostname = "localhost";

    this.listener = Deno.listenTls({ port, hostname, cert, key });

    callback?.();
    this.#listen(this.listener);
    return this;
  }

  async #listen(listener: Deno.TlsListener) {
    while (!this.#closed) {
      try {
        // Creates TCP handle and socket directly from Deno.TlsConn.
        // This works as TLS socket. We don't use TLSSocket class for doing
        // this because Deno.startTls only supports client side tcp connection.
        const handle = new TCP(TCPConstants.SOCKET, await listener.accept());
        const socket = new net.Socket({ handle });
        this.emit("secureConnection", socket);
      } catch (e) {
        if (e instanceof Deno.errors.BadResource) {
          this.#closed = true;
        }
        // swallow
      }
    }
  }

  close(cb?: (err?: Error) => void): this {
    if (this.listener) {
      this.listener.close();
    }
    cb?.();
    return this;
  }
}

Server.prototype = ServerImpl.prototype;

export function createServer(options: any, listener: any) {
  return new ServerImpl(options, listener);
}

export function connect(...args: any[]) {
  args = normalizeConnectArgs(args);
  let options = args[0];
  const cb = args[1];
  const allowUnauthorized = getAllowUnauthorized();

  options = {
    rejectUnauthorized: !allowUnauthorized,
    ciphers: DEFAULT_CIPHERS,
    checkServerIdentity,
    minDHSize: 1024,
    ...options,
  };

  if (!options.keepAlive) {
    options.singleUse = true;
  }

  assert(typeof options.checkServerIdentity === "function");
  assert(
    typeof options.minDHSize === "number",
    "options.minDHSize is not a number: " + options.minDHSize,
  );
  assert(
    options.minDHSize > 0,
    "options.minDHSize is not a positive number: " +
      options.minDHSize,
  );

  const context = options.secureContext || createSecureContext(options);

  const tlssock = new TLSSocket(options.socket, {
    allowHalfOpen: options.allowHalfOpen,
    pipe: !!options.path,
    secureContext: context,
    isServer: false,
    requestCert: true,
    rejectUnauthorized: options.rejectUnauthorized !== false,
    session: options.session,
    ALPNProtocols: options.ALPNProtocols,
    requestOCSP: options.requestOCSP,
    enableTrace: options.enableTrace,
    pskCallback: options.pskCallback,
    highWaterMark: options.highWaterMark,
    onread: options.onread,
    signal: options.signal,
    ...options, // Caveat emptor: Node does not do this.
  });

  // rejectUnauthorized property can be explicitly defined as `undefined`
  // causing the assignment to default value (`true`) fail. Before assigning
  // it to the tlssock connection options, explicitly check if it is false
  // and update rejectUnauthorized property. The property gets used by TLSSocket
  // connection handler to allow or reject connection if unauthorized
  options.rejectUnauthorized = options.rejectUnauthorized !== false;

  tlssock[kConnectOptions] = options;

  if (cb) {
    tlssock.once("secureConnect", cb);
  }

  if (!options.socket) {
    // If user provided the socket, it's their responsibility to manage its
    // connectivity. If we created one internally, we connect it.
    if (options.timeout) {
      tlssock.setTimeout(options.timeout);
    }

    tlssock.connect(options, tlssock._start);
  }

  tlssock._releaseControl();

  if (options.session) {
    tlssock.setSession(options.session);
  }

  if (options.servername) {
    if (!ipServernameWarned && net.isIP(options.servername)) {
      emitWarning(
        "Setting the TLS ServerName to an IP address is not permitted by " +
          "RFC 6066. This will be ignored in a future version.",
        "DeprecationWarning",
        "DEP0123",
      );
      ipServernameWarned = true;
    }
    tlssock.setServername(options.servername);
  }

  if (options.socket) {
    tlssock._start();
  }

  tlssock.prependListener("end", onConnectEnd);

  return tlssock;
}

function getAllowUnauthorized() {
  return false;
}

function convertProtocols(protocols: any[]) {
  const lens = new Array(protocols.length);
  const buff = Buffer.allocUnsafe(
    protocols.reduce((p: any, c: any, i: number) => {
      const len = Buffer.byteLength(c);
      if (len > 255) {
        throw new ERR_OUT_OF_RANGE(
          "The byte length of the protocol at index " +
            `${i} exceeds the maximum length.`,
          "<= 255",
          len,
          true,
        );
      }
      lens[i] = len;
      return p + 1 + len;
    }),
  );

  let offset = 0;
  for (let i = 0, c = protocols.length; i < c; i++) {
    buff[offset++] = lens[i];
    buff.write(protocols[i], offset);
    offset += lens[i];
  }
  return buff;
}

export function convertALPNProtocols(protocols: any, out: any) {
  // If protocols is Array - translate it into buffer
  if (Array.isArray(protocols)) {
    out.ALPNProtocols = convertProtocols(protocols);
  } else if (protocols instanceof Uint8Array) {
    // Copy new buffer not to be modified by user.
    out.ALPNProtocols = Buffer.from(protocols);
  } else if (ArrayBuffer.isView(protocols)) {
    out.ALPNProtocols = Buffer.from(protocols.buffer.slice(
      protocols.byteOffset,
      protocols.byteOffset + protocols.byteLength,
    ));
  }
}

function unfqdn(host: string): string {
  return StringPrototypeReplace(host, /[.]$/, "");
}
// String#toLowerCase() is locale-sensitive so we use
// a conservative version that only lowercases A-Z.
function toLowerCase(c: string) {
  return String.fromCharCode(32 + c.charCodeAt(0));
}

function splitHost(host: string) {
  return unfqdn(host).replace(/[A-Z]/g, toLowerCase).split(".");
}

function check(hostParts: string[], pattern?: string, wildcards?: any) {
  // Empty strings, null, undefined, etc. never match.
  if (!pattern) {
    return false;
  }

  const patternParts = splitHost(pattern);

  if (hostParts.length !== patternParts.length) {
    return false;
  }

  // Pattern has empty components, e.g. "bad..example.com".
  if (patternParts.includes("")) {
    return false;
  }

  // RFC 6125 allows IDNA U-labels (Unicode) in names but we have no
  // good way to detect their encoding or normalize them so we simply
  // reject them.  Control characters and blanks are rejected as well
  // because nothing good can come from accepting them.
  const isBad = (s: string) => /[^\u0021-\u007F]/u.exec(s) !== null;
  if (patternParts.some(isBad)) {
    return false;
  }

  // Check host parts from right to left first.
  for (let i = hostParts.length - 1; i > 0; i -= 1) {
    if (hostParts[i] !== patternParts[i]) {
      return false;
    }
  }

  const hostSubdomain = hostParts[0];
  const patternSubdomain = patternParts[0];
  const patternSubdomainParts = patternSubdomain.split("*");

  // Short-circuit when the subdomain does not contain a wildcard.
  // RFC 6125 does not allow wildcard substitution for components
  // containing IDNA A-labels (Punycode) so match those verbatim.
  if (
    patternSubdomainParts.length === 1 ||
    patternSubdomain.includes("xn--")
  ) {
    return hostSubdomain === patternSubdomain;
  }

  if (!wildcards) {
    return false;
  }

  // More than one wildcard is always wrong.
  if (patternSubdomainParts.length > 2) {
    return false;
  }

  // *.tld wildcards are not allowed.
  if (patternParts.length <= 2) {
    return false;
  }

  const { 0: prefix, 1: suffix } = patternSubdomainParts;

  if (prefix.length + suffix.length > hostSubdomain.length) {
    return false;
  }

  if (!hostSubdomain.startsWith(prefix)) {
    return false;
  }

  if (!hostSubdomain.endsWith(suffix)) {
    return false;
  }

  return true;
}

// This pattern is used to determine the length of escaped sequences within
// the subject alt names string. It allows any valid JSON string literal.
// This MUST match the JSON specification (ECMA-404 / RFC8259) exactly.
const jsonStringPattern =
  // deno-lint-ignore no-control-regex
  /^"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/;

function splitEscapedAltNames(altNames: string) {
  const result: string[] = [];
  let currentToken = "";
  let offset = 0;
  while (offset !== altNames.length) {
    const nextSep = altNames.indexOf(", ", offset);
    const nextQuote = altNames.indexOf('"', offset);
    if (nextQuote !== -1 && (nextSep === -1 || nextQuote < nextSep)) {
      // There is a quote character and there is no separator before the quote.
      currentToken += altNames.substring(offset, nextQuote);
      const match = jsonStringPattern.exec(altNames.substring(nextQuote));
      if (!match) {
        throw new ERR_TLS_CERT_ALTNAME_FORMAT();
      }
      currentToken += JSON.parse(match[0]);
      offset = nextQuote + match[0].length;
    } else if (nextSep !== -1) {
      // There is a separator and no quote before it.
      currentToken += altNames.substring(offset, nextSep);
      result.push(currentToken);
      currentToken = "";
      offset = nextSep + 2;
    } else {
      currentToken += altNames.substring(offset);
      offset = altNames.length;
    }
  }
  result.push(currentToken);
  return result;
}

export function checkServerIdentity(hostname: string, cert: any) {
  const subject = cert.subject;
  const altNames: string = cert.subjectaltname;
  const dnsNames: string[] = [];
  const ips: string[] = [];

  hostname = "" + hostname;

  if (altNames) {
    const splitAltNames = altNames.includes('"')
      ? splitEscapedAltNames(altNames)
      : altNames.split(", ");
    splitAltNames.forEach((name: string) => {
      if (name.startsWith("DNS:")) {
        dnsNames.push(name.slice(4));
      } else if (name.startsWith("IP Address:")) {
        ips.push(canonicalizeIP(name.slice(11)));
      }
    });
  }

  let valid = false;
  let reason = "Unknown reason";

  hostname = unfqdn(hostname); // Remove trailing dot for error messages.

  if (net.isIP(hostname)) {
    valid = ips.includes(canonicalizeIP(hostname));
    if (!valid) {
      reason = `IP: ${hostname} is not in the cert's list: ` +
        ips.join(", ");
    }
  } else if (dnsNames.length > 0 || subject?.CN) {
    const hostParts = splitHost(hostname);
    const wildcard = (pattern: string) => check(hostParts, pattern, true);

    if (dnsNames.length > 0) {
      valid = dnsNames.some(wildcard);
      if (!valid) {
        reason =
          `Host: ${hostname}. is not in the cert's altnames: ${altNames}`;
      }
    } else {
      // Match against Common Name only if no supported identifiers exist.
      const cn = subject.CN;

      if (cn.isArray()) {
        valid = cn.some(wildcard);
      } else if (cn) {
        valid = wildcard(cn);
      }

      if (!valid) {
        reason = `Host: ${hostname}. is not cert's CN: ${cn}`;
      }
    }
  } else {
    reason = "Cert does not contain a DNS name";
  }

  if (!valid) {
    return new ERR_TLS_CERT_ALTNAME_INVALID(reason, hostname, cert);
  }
}

export const CLIENT_RENEG_LIMIT = 3;
export const CLIENT_RENEG_WINDOW = 600;

// Order matters. Mirrors ALL_CIPHER_SUITES from rustls/src/suites.rs but
// using openssl cipher names instead. Mutable in Node but not (yet) in Deno.
export const DEFAULT_CIPHERS = [
  // TLSv1.3 suites
  "AES256-GCM-SHA384",
  "AES128-GCM-SHA256",
  "TLS_CHACHA20_POLY1305_SHA256",
  // TLSv1.2 suites
  "ECDHE-ECDSA-AES256-GCM-SHA384",
  "ECDHE-ECDSA-AES128-GCM-SHA256",
  "ECDHE-ECDSA-CHACHA20-POLY1305",
  "ECDHE-RSA-AES256-GCM-SHA384",
  "ECDHE-RSA-AES128-GCM-SHA256",
  "ECDHE-RSA-CHACHA20-POLY1305",
].join(":");

export default {
  TLSSocket,
  connect,
  createServer,
  checkServerIdentity,
  CLIENT_RENEG_LIMIT,
  CLIENT_RENEG_WINDOW,
  DEFAULT_CIPHERS,
  convertALPNProtocols,
  unfqdn,
};
