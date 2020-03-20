/*
******************************************************************************************
**
** AcquireWidevineLicenses
**
** An example implementation of Widevine License Proxy
**
** This functon recieves a license request from the Widevine DRM client, and wrap the
** client request into the request to the Google Widevine License Services.
** The request data to the Google Widevine License Services includes DRM key policy
** configuration determined on the server side.
** Once this function receives the response data from the Google Widevine License Services,
** the data will contain the license response, which should be sent back to the Widevine
** DRM client.
**
******************************************************************************************
*/

var http = require('https');
var CryptoJS = require("crypto-js");

module.exports = function (context, req) {
    // Provider = widevine_test
    var provider = "widevine_test";
    var aesSigningKey = "1ae8ccd0e7985cc0b6203a55855a1034afc252980e970ca90e5202689f947ab9";
    var aesSigningIV = "d58ce954203b7c9a9a9d467f59839249";
    // Provider = widevine_test


    context.log('[AcquireWidevineLicenses] Start Call');

    // Google's Widevine License Services
    var urlStaging = "https://license.staging.widevine.com/cenc/getlicense/" + provider;
    var urlProduction = "https://license.widevine.com/cenc/getlicense/" + provider;
    var url = urlStaging;

    var clientRequest = null;
    var template = null;

    // Debug Logs
    //context.log('Request data is:');
    //context.log(req);
    // Debug Logs

    // 400 Bad Request
    if (req.body === undefined) {
        context.res = {
            status: 400,
            body: "400 - Bad Request: No request body."
        };
        return;
    }

    //
    // Handling URL parameters
    //
    if (req.query.Template) {
        template = req.query.Template;
        template = CryptoJS.enc.Utf8.stringify(CryptoJS.enc.Base64.parse(template));
    } else {
        template = "{}"
    }
    context.log('[AcquireWidevineLicenses] Template JSON:', template);

    //
    // Build license request message
    //
    clientRequest = CryptoJS.enc.Base64.stringify(CryptoJS.lib.WordArray.create(req.body));
    var requestJson = JSON.parse(template);
    requestJson = { "provider": provider, ...requestJson};
    requestJson = { "payload": clientRequest, ...requestJson};
    var request = JSON.stringify(requestJson);
    context.log('[AcquireWidevineLicenses] Request JSON:', JSON.stringify(requestJson));

    //
    // Build signed license request message
    //
    var b64Request = CryptoJS.enc.Base64.stringify(CryptoJS.enc.Latin1.parse(request));
    var hash = CryptoJS.SHA1(request);
    var r = encrypt(hash, aesSigningKey, aesSigningIV);
    var b64Signature = CryptoJS.enc.Base64.stringify(r.ciphertext);
    var messageJson = {
        "request": b64Request,
        "signature": b64Signature,
        "signer": provider
    };
    context.log('[AcquireWidevineLicenses] Response JSON', JSON.stringify(messageJson));

    //
    // Send license request to license server
    //
    context.log('[AcquireWidevineLicenses] Sent HTTP request to', url);
    var postBody = JSON.stringify(messageJson);
    var options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postBody)
        }
    };
    var client = http.request(url, options, (res) => {
        context.log('[AcquireWidevineLicenses] HTTP Response:', { StatusCode: res.statusCode, Headers: res.headers });
        let resBody = '';
        res.on("data", (chunk) => { resBody += chunk; });
        res.on("end", () => {
            context.log(resBody);
            let resBodyJson = JSON.parse(resBody);
            if (resBodyJson.license !== undefined) {
                let lic = CryptoJS.enc.Base64.parse(resBodyJson.license);
                let licResBytes = new Buffer(wordArrayToByteArray(lic.words, lic.sigBytes));
                context.res = { status: 200, body: licResBytes };
            } else {
                context.res = { status: 400, body: "400 - Bad Request: " + resBodyJson.status_message };
            }
            context.log('[AcquireWidevineLicenses] End Call');
            context.done();
        });
    });
    client.on("error", (e) => {
        context.log.error(e);
        context.res = { status: 400, body: e };
        context.log('[AcquireWidevineLicenses] End Call');
        context.done();
    });
    client.write(postBody);
    client.end();
    context.log('[AcquireWidevineLicenses] Got HTTP response from', url);
}

function encrypt(plaintext, key, iv) {
    var CryptoJS = require("crypto-js");
    var iv = CryptoJS.enc.Hex.parse(iv);
    var key = CryptoJS.enc.Hex.parse(key);
    var r = CryptoJS.AES.encrypt(plaintext, key, { iv: iv });
    return r;
}

function wordToByteArray(word, length) {
	var ba = [],
		i,
		xFF = 0xFF;
	if (length > 0)
		ba.push(word >>> 24);
	if (length > 1)
		ba.push((word >>> 16) & xFF);
	if (length > 2)
		ba.push((word >>> 8) & xFF);
	if (length > 3)
		ba.push(word & xFF);

	return ba;
}

function wordArrayToByteArray(wordArray, length) {
	var result = [],
		bytes,
		i = 0;
	while (length > 0) {
		bytes = wordToByteArray(wordArray[i], Math.min(4, length));
		length -= bytes.length;
		result.push(bytes);
		i++;
	}
	return [].concat.apply([], result);
}
