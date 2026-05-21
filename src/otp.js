// TOTP / HOTP. Ported from Tusk/src/lib/otp.js with minor cleanup.

function leftPad(str, len) {
  while (str.length < len) str = '0' + str;
  return str;
}

function fromBase32(str) {
  str = (str || '').replace(/\s/g, '').replace(/=+$/, '');
  if (!str) return null;
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
  let bin = '';
  for (let i = 0; i < str.length; i++) {
    const ix = alphabet.indexOf(str[i].toLowerCase());
    if (ix < 0) return null;
    bin += leftPad(ix.toString(2), 5);
  }
  const bytes = new Uint8Array(Math.floor(bin.length / 8));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(bin.substr(i * 8, 8), 2);
  }
  return bytes.buffer;
}

function hmacToDigits(hmac, length) {
  let code = hmac.toString();
  code = leftPad(code.substr(code.length - length), length);
  return code;
}

function hmacToSteamCode(hmac) {
  const steamChars = '23456789BCDFGHJKMNPQRTVWXY';
  let code = '';
  for (let i = 0; i < 5; ++i) {
    code += steamChars.charAt(hmac % steamChars.length);
    hmac = Math.floor(hmac / steamChars.length);
  }
  return code;
}

class Otp {
  constructor(params) {
    if (['hotp', 'totp'].indexOf(params.type) < 0) throw new Error('Bad otp type: ' + params.type);
    if (!params.secret) throw new Error('Empty otp secret');
    if (params.algorithm && ['SHA1', 'SHA256', 'SHA512'].indexOf(params.algorithm.toUpperCase()) < 0)
      throw new Error('Bad algorithm');
    this.type = params.type;
    this.secret = params.secret;
    this.issuer = params.issuer;
    this.account = params.account;
    this.algorithm = (params.algorithm || 'SHA1').toUpperCase();
    this.digits = params.digits ? +params.digits : 6;
    this.period = params.period ? +params.period : 30;
    this.counter = params.counter ? +params.counter : 0;
    const key = fromBase32(this.secret);
    if (!key) throw new Error('Bad otp key');
    this.key = key;
  }

  async next() {
    let valueForHashing, timeLeft;
    if (this.type === 'totp') {
      const now = Date.now();
      const epoch = Math.round(now / 1000);
      valueForHashing = Math.floor(epoch / this.period);
      const msPeriod = this.period * 1000;
      timeLeft = msPeriod - (now % msPeriod);
    } else {
      valueForHashing = this.counter;
    }
    const data = new Uint8Array(8).buffer;
    new DataView(data).setUint32(4, valueForHashing);
    const algo = { name: 'HMAC', hash: { name: this.algorithm.replace('SHA', 'SHA-') } };
    const cryptoKey = await crypto.subtle.importKey('raw', this.key, algo, false, ['sign']);
    const sigBuf = await crypto.subtle.sign(algo, cryptoKey, data);
    const sig = new DataView(sigBuf);
    const offset = sig.getInt8(sig.byteLength - 1) & 0xf;
    const hmac = sig.getUint32(offset) & 0x7fffffff;
    const code = this.issuer === 'Steam'
      ? hmacToSteamCode(hmac)
      : hmacToDigits(hmac, this.digits);
    return { code, timeLeft, period: this.period * 1000 };
  }
}

// Build an Otp from arbitrary input: otpauth:// URL, or a bare base32 secret,
// or a "key=value" string used by KeePass entries.
export function makeOtp(value) {
  if (!value) return null;
  const s = value.trim();
  // otpauth://...
  const urlMatch = /^otpauth:\/\/(\w+)(?:\/([^?]+)\?|\?)(.*)/i.exec(s);
  if (urlMatch) {
    const params = { type: urlMatch[1].toLowerCase() };
    const label = decodeURIComponent(urlMatch[2] || '');
    if (label) {
      const parts = label.split(':');
      params.issuer = parts[0].trim();
      if (parts.length > 1) params.account = parts.slice(1).join(':').trim();
    }
    for (const part of urlMatch[3].split('&')) {
      const [k, v = ''] = part.split('=', 2);
      params[k.toLowerCase()] = decodeURIComponent(v);
    }
    return new Otp(params);
  }
  // KeePass otp field as "key=value&key=value"
  if (/[&=]/.test(s) && /key=/i.test(s)) {
    const params = { type: 'totp' };
    for (const part of s.split('&')) {
      const [k, v = ''] = part.split('=', 2);
      const key = k.toLowerCase();
      if (key === 'key') params.secret = v;
      else params[key] = v;
    }
    return new Otp(params);
  }
  // Bare base32 secret
  if (fromBase32(s)) {
    return new Otp({ type: 'totp', secret: s });
  }
  return null;
}

export function isOtpSecret(s) {
  return !!fromBase32(s);
}
