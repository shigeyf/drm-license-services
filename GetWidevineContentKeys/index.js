/*
******************************************************************************************
**
** GetWidevineContentKeys
**
** An example implementation of issuing Widevine Content Keys
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


    context.log('[GetWidevineContentKeys] Start Call');

    // Google's Widevine Content Key Services
    var urlStaging = "https://license.staging.widevine.com/cenc/getcontentkey/" + provider;
    var urlProduction = "https://license.widevine.com/cenc/getcontentkey/" + provider;
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

    var requestJson = req.body;
    var request = JSON.stringify(requestJson);
    context.log('[GetWidevineContentKeys] Request JSON:', request);

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
    context.log('[GetWidevineContentKeys] Response JSON:', JSON.stringify(messageJson));

    //
    // Send license request to license server
    //
    context.log('[GetWidevineContentKeys] Sent HTTP request to', url);
    var postBody = JSON.stringify(messageJson);
    var options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postBody)
        }
    };
    var client = http.request(url, options, (res) => {
        context.log('[GetWidevineContentKeys] HTTP Response:', { StatusCode: res.statusCode, Headers: res.headers });
        let resBody = '';
        res.on("data", (chunk) => { resBody += chunk; });
        res.on("end", () => {
            let resBodyJson = JSON.parse(resBody);
            if (resBodyJson.response !== undefined) {
                let response = CryptoJS.enc.Base64.parse(resBodyJson.response);
                context.log('[GetWidevineContentKeys]', resBodyJson.response);
                let responseBytes = Buffer.from(wordArrayToByteArray(response.words, response.sigBytes));
                context.res = { status: 200, body: responseBytes, headers: { 'Content-Type': 'application/json' } };
            } else {
                context.res = { status: 400, body: '400 - Bad Response' };
            }
            context.log('[GetWidevineContentKeys] End Call');
            context.done();
        });
    });
    client.on("error", (e) => {
        context.log.error(e);
        context.res = { status: 400, body: e };
        context.log('[GetWidevineContentKeys] End Call');
        context.done();
    });
    client.write(postBody);
    client.end();
    context.log('[GetWidevineContentKeys] Got HTTP response from', url);
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
