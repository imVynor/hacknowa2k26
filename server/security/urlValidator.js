const dns = require('node:dns');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');

/**
 * Checks if an IPv4 address is in a prohibited private, loopback, link-local,
 * cloud-metadata, multicast, or reserved range.
 */
function isProhibitedIPv4(ip) {
  const parts = ip.split('.').map((p) => Number.parseInt(p, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    return true; // Malformed IPv4 is prohibited
  }

  const [a, b, c] = parts;

  // 0.0.0.0/8 - Current network (this host)
  if (a === 0) return true;

  // 10.0.0.0/8 - Private RFC 1918
  if (a === 10) return true;

  // 100.64.0.0/10 - Shared Address Space (Carrier-Grade NAT)
  if (a === 100 && b >= 64 && b <= 127) return true;

  // 127.0.0.0/8 - Loopback
  if (a === 127) return true;

  // 169.254.0.0/16 - Link-Local / Cloud Metadata (169.254.169.254)
  if (a === 169 && b === 254) return true;

  // 172.16.0.0/12 - Private RFC 1918
  if (a === 172 && b >= 16 && b <= 31) return true;

  // 192.0.0.0/24 - IETF Protocol Assignments
  if (a === 192 && b === 0 && c === 0) return true;

  // 192.0.2.0/24 - TEST-NET-1
  if (a === 192 && b === 0 && c === 2) return true;

  // 192.168.0.0/16 - Private RFC 1918
  if (a === 192 && b === 168) return true;

  // 198.18.0.0/15 - Network benchmark
  if (a === 198 && (b === 18 || b === 19)) return true;

  // 198.51.100.0/24 - TEST-NET-2
  if (a === 198 && b === 51 && c === 100) return true;

  // 203.0.113.0/24 - TEST-NET-3
  if (a === 203 && b === 0 && c === 113) return true;

  // 224.0.0.0/4 - Multicast
  if (a >= 224 && a <= 239) return true;

  // 240.0.0.0/4 - Reserved / Broadcast (including 255.255.255.255)
  if (a >= 240) return true;

  return false;
}

/**
 * Checks if an IPv6 address is in a prohibited range.
 */
function isProhibitedIPv6(ip) {
  const normalized = ip.toLowerCase().trim();

  // Loopback ::1 or 0:0:0:0:0:0:0:1
  if (normalized === '::1' || normalized === '0:0:0:0:0:0:0:1') return true;

  // Unspecified :: or 0:0:0:0:0:0:0:0
  if (normalized === '::' || normalized === '0:0:0:0:0:0:0:0') return true;

  // IPv4-mapped IPv6 (::ffff:127.0.0.1 or ::ffff:7f00:0001)
  if (normalized.startsWith('::ffff:')) {
    const v4Part = normalized.replace('::ffff:', '');
    if (net.isIPv4(v4Part)) {
      return isProhibitedIPv4(v4Part);
    }
  }

  // IPv4-compatible IPv6 (::127.0.0.1)
  if (normalized.startsWith('::') && !normalized.startsWith('::1')) {
    const v4Part = normalized.slice(2);
    if (net.isIPv4(v4Part)) {
      return isProhibitedIPv4(v4Part);
    }
  }

  // Unique Local Address fc00::/7 (fc00... or fd00...)
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true;

  // Link-Local fe80::/10 (fe8, fe9, fea, feb)
  if (/^fe[89ab]/i.test(normalized)) return true;

  // Multicast ff00::/8
  if (normalized.startsWith('ff')) return true;

  // Documentation 2001:db8::/32
  if (normalized.startsWith('2001:db8') || normalized.startsWith('2001:0db8')) return true;

  return false;
}

/**
 * Evaluates whether an IP address is prohibited.
 * @param {string} ip
 * @param {object} [options]
 * @param {boolean} [options.allowLocal=false] - Allows loopback/private for controlled tests
 */
function isProhibitedIP(ip, options = {}) {
  const allowLocal = options.allowLocal !== undefined
    ? Boolean(options.allowLocal)
    : process.env.ALLOW_LOCAL_TARGETS === 'true';

  if (allowLocal) {
    // Even when local targets are allowed for testing, cloud metadata is strictly blocked
    if (ip === '169.254.169.254' || ip.startsWith('169.254.')) {
      return true;
    }
    return false;
  }

  const version = net.isIP(ip);
  if (version === 4) {
    return isProhibitedIPv4(ip);
  }
  if (version === 6) {
    return isProhibitedIPv6(ip);
  }

  // Not a valid IP format
  return true;
}

/**
 * Hostnames that must always be blocked
 */
const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'metadata.google.internal',
  'instance-data',
  'metadata.local'
]);

/**
 * Validates a target URL syntax and ensures it adheres to protocol and destination restrictions.
 * @param {string} urlString
 * @param {object} [options]
 * @param {boolean} [options.allowLocal=false]
 * @returns {Promise<{ valid: boolean, parsedUrl?: URL, resolvedIps?: string[], error?: string }>}
 */
async function validateTargetUrl(urlString, options = {}) {
  const allowLocal = options.allowLocal !== undefined
    ? Boolean(options.allowLocal)
    : process.env.ALLOW_LOCAL_TARGETS === 'true';

  if (!urlString || typeof urlString !== 'string') {
    return { valid: false, error: 'Target URL is required.' };
  }

  let parsed;
  try {
    parsed = new URL(urlString.trim());
  } catch {
    return { valid: false, error: 'Target URL is malformed or invalid.' };
  }

  // Reject URL schemes other than HTTP and HTTPS
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      valid: false,
      error: `Invalid protocol "${parsed.protocol}". Only HTTP and HTTPS endpoints are permitted.`
    };
  }

  // Reject embedded credentials in URL
  if (parsed.username || parsed.password) {
    return {
      valid: false,
      error: 'Embedded user credentials in the target URL are not permitted.'
    };
  }

  const hostname = parsed.hostname.toLowerCase();

  // Check prohibited hostnames
  if (!allowLocal) {
    if (BLOCKED_HOSTNAMES.has(hostname) || hostname.endsWith('.localhost') || hostname.endsWith('.local')) {
      return {
        valid: false,
        error: `Host "${hostname}" is a reserved or local address and cannot be targeted.`
      };
    }
  }

  // Direct IP in hostname
  if (net.isIP(hostname)) {
    if (isProhibitedIP(hostname, { allowLocal })) {
      return {
        valid: false,
        error: `Destination IP "${hostname}" is in a prohibited private, loopback, or metadata range (SSRF protection).`
      };
    }
    return { valid: true, parsedUrl: parsed, resolvedIps: [hostname] };
  }

  // DNS resolution validation
  try {
    const records = await dns.promises.lookup(hostname, { all: true });
    if (!records || records.length === 0) {
      return {
        valid: false,
        error: `Could not resolve hostname "${hostname}".`
      };
    }

    const resolvedIps = records.map((r) => r.address);
    for (const ip of resolvedIps) {
      if (isProhibitedIP(ip, { allowLocal })) {
        return {
          valid: false,
          error: `Hostname "${hostname}" resolves to prohibited destination IP "${ip}" (SSRF protection).`
        };
      }
    }

    return { valid: true, parsedUrl: parsed, resolvedIps };
  } catch (err) {
    return {
      valid: false,
      error: `DNS resolution failed for "${hostname}": ${err.message}`
    };
  }
}

/**
 * Creates custom HTTP/HTTPS agents with DNS rebinding protection.
 * Performs real-time IP validation on every socket lookup before connecting.
 */
function createSafeAgent(protocol, options = {}) {
  const allowLocal = options.allowLocal !== undefined
    ? Boolean(options.allowLocal)
    : process.env.ALLOW_LOCAL_TARGETS === 'true';
  const isHttps = protocol === 'https:';
  const AgentClass = isHttps ? https.Agent : http.Agent;

  return new AgentClass({
    keepAlive: false,
    lookup: (hostname, lookupOpts, callback) => {
      if (typeof lookupOpts === 'function') {
        callback = lookupOpts;
        lookupOpts = {};
      }

      // If hostname is already an IP, validate directly
      const ipVersion = net.isIP(hostname);
      if (ipVersion !== 0) {
        if (isProhibitedIP(hostname, { allowLocal })) {
          return callback(new Error(`Prohibited IP address "${hostname}" blocked (SSRF defense).`));
        }
        if (lookupOpts && lookupOpts.all) {
          return callback(null, [{ address: hostname, family: ipVersion }]);
        }
        return callback(null, hostname, ipVersion);
      }

      dns.lookup(hostname, lookupOpts, (err, address, family) => {
        if (err) return callback(err);

        const addresses = Array.isArray(address)
          ? address.map((a) => (typeof a === 'string' ? { address: a, family: 4 } : a))
          : [{ address, family: family || 4 }];

        for (const item of addresses) {
          const ip = item.address;
          if (isProhibitedIP(ip, { allowLocal })) {
            return callback(
              new Error(`DNS resolution to prohibited IP address "${ip}" blocked (SSRF defense).`)
            );
          }
        }

        if (lookupOpts && lookupOpts.all) {
          return callback(null, addresses);
        }

        const chosenIp = addresses[0]?.address;
        const chosenFamily = addresses[0]?.family || 4;
        return callback(null, chosenIp, chosenFamily);
      });
    }
  });
}

/**
 * Redacts sensitive credentials from headers for safe logging and UI display.
 */
function redactHeaders(headers) {
  if (!headers || typeof headers !== 'object') return {};
  const redacted = {};
  const sensitiveRegex = /authorization|api[-_]?key|auth[-_]?token|bearer|secret|token|password|cookie/i;

  for (const [key, val] of Object.entries(headers)) {
    if (sensitiveRegex.test(key)) {
      if (typeof val === 'string' && val.toLowerCase().startsWith('bearer ')) {
        redacted[key] = 'Bearer ••••••••';
      } else {
        redacted[key] = '••••••••';
      }
    } else {
      redacted[key] = val;
    }
  }
  return redacted;
}

module.exports = {
  isProhibitedIP,
  isProhibitedIPv4,
  isProhibitedIPv6,
  validateTargetUrl,
  createSafeAgent,
  redactHeaders
};
