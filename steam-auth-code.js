'use strict';

export const TIME_INTERVAL_IN_SEC = 30;

export async function setAuthCode(el) {
    let msg = '';

    try {
        msg = await setAuthCodeInternal(el);
    }
    catch (e) {
        msg = e;
    }

    document.querySelector(el).textContent = msg;
}

async function setAuthCodeInternal() {
    let searchParams = new URLSearchParams(window.location.search);

    // Required. Base64-encoded shared secret
    let secret = searchParams.get('secret');

    // Optional, defaults to system time. Number of seconds since epoch
    let time = searchParams.get('time');

    // Optional, defaults to 0. This number of seconds will be added to time
    let timeOffset = searchParams.get('timeOffset');

    if (!secret) {
        return 'Error: you must specify URL parameter secret';
    }
    secret = secret.replace(' ', '+');

    time = time
        ? parseInt(time)
        : Math.floor(Date.now() / 1000);

    if (timeOffset) {
        timeOffset = parseInt(timeOffset);
        time += timeOffset;
    }

    return await getAuthCode(secret, time);
}

export async function getAuthCode(secret, time) {
    secret = base64ToU8Array(secret);
    time = f64ToU64(Math.floor(time / TIME_INTERVAL_IN_SEC));

    let rawCode = await getRawCode(secret, time);

    return getAuthCodeFromRawCode(rawCode);
}

function base64ToU8Array(base64) {
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

function f64ToU64(f64) {
    let u64 = new DataView(new ArrayBuffer(8));

    if (typeof BigInt !== 'undefined') {
        u64.setBigUint64(0, BigInt(f64), false);
    }
    else {
        // BigInt should be supported everywhere by the year 6053
        u64.setUint32(4, f64, false);
    }

    return u64;
}

async function getRawCode(secret, time) {
    let algo = {name: "HMAC", hash: "SHA-1"};
    let key = await crypto.subtle.importKey('raw', secret, algo, false, ["sign"]);
    let hmac = await crypto.subtle.sign('HMAC', key, time);
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
