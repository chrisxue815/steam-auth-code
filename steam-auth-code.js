'use strict';

export const TIME_INTERVAL_IN_SEC = 30;
export const TIME_INTERVAL_IN_MS = TIME_INTERVAL_IN_SEC * 1000;
const SPACE_PATTERN = new RegExp(/ /g);

export class AuthCode {
    constructor(authCode, startTime) {
        this.authCode = authCode;
        this.startTime = startTime;
    }
}

export function parseUrlParams() {
    let searchParams = new URLSearchParams(window.location.search);

    // Required. Base64-encoded shared secret
    let secret = searchParams.get('secret');

    // Optional, defaults to system time. Number of milliseconds since epoch
    let time = searchParams.get('time');

    // Optional, defaults to 0. This number of milliseconds will be added to time
    let timeOffset = searchParams.get('timeOffset');

    if (!secret) {
        throw 'Error: you must specify URL parameter secret';
    }
    secret = secret.replace(SPACE_PATTERN, '+');

    timeOffset = timeOffset
        ? parseInt(timeOffset)
        : 0;

    if (time) {
        timeOffset += parseInt(time) - Date.now();
    }

    return {secret, timeOffset};
}

export async function getAuthCode(secret, time) {
    let secretU8 = base64ToU8Array(secret);

    let timeIndex = Math.floor(time / TIME_INTERVAL_IN_MS);
    let startTime = timeIndex * TIME_INTERVAL_IN_MS;
    let timeIndexU64 = f64ToU64(timeIndex);

    let rawCode = await getRawCode(secretU8, timeIndexU64);
    let authCode = getAuthCodeFromRawCode(rawCode);

    return new AuthCode(authCode, startTime);
}

function base64ToU8Array(base64) {
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

function f64ToU64(f64) {
    let u64 = new DataView(new ArrayBuffer(8));

    if (typeof u64.setBigUint64 !== 'undefined' && typeof BigInt !== 'undefined') {
        u64.setBigUint64(0, BigInt(f64), false);
    }
    else {
        // BigInt should be supported everywhere by the year 6053
        u64.setUint32(4, f64, false);
    }

    return u64;
}

async function getRawCode(secret, timeIndex) {
    let algo = {name: "HMAC", hash: "SHA-1"};
    let key = await crypto.subtle.importKey('raw', secret, algo, false, ["sign"]);
    let hmac = await crypto.subtle.sign('HMAC', key, timeIndex);
    hmac = new DataView(hmac);

    let start = hmac.getUint8(19) & 0x0F;
    return hmac.getUint32(start, false) & 0x7FFFFFFF;
}

function getAuthCodeFromRawCode(rawCode) {
    const chars = '23456789BCDFGHJKMNPQRTVWXY';
    let code = '';

    for (let i = 0; i < 5; i++) {
        code += chars.charAt(rawCode % chars.length);
        rawCode /= chars.length;
    }

    return code;
}
