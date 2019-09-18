
function toHexString(byteArray) {
    return Array.from(byteArray, function (byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('')
}
// Convert a hex string to a byte array
function hexToBytes(hexString) {
    var result = [];
    while (hexString.length >= 2) {
        result.push(parseInt(hexString.substring(0, 2), 16));
        hexString = hexString.substring(2, hexString.length);
    }
    return result;
}

function insert_rnd_bundle() {
    Rust.bp7.then(function (bp7) {
        var b = bp7.rnd_bundle_now();
        var bid = bp7.bid_from_bundle(b);
        console.log('inserting random bundle: ', bid);
        var cbor = bp7.encode_to_cbor(b)
        document.getElementById("hexout").textContent = toHexString(cbor);
        document.getElementById("hexout").onclick = function () {
            window.open("http://cbor.me/?bytes=" + toHexString(cbor));
        };
        document.getElementById("outlen").textContent = cbor.length;
    });
}



function show_msg(buf) {
    Rust.bp7.then(function (bp7) {
        var b = bp7.decode_from_cbor(buf)
        var bid = bp7.bid_from_bundle(b);
        var payload = bp7.payload_from_bundle(b);
        var sender_eid = bp7.sender_from_bundle(b);
        var recepient_eid = bp7.recipient_from_bundle(b);
        var timestamp = bp7.timestamp_from_bundle(b);
        var msg_str = String.fromCharCode.apply(null, payload)
        alert("From: " + sender_eid + "\nTo: " + recepient_eid + "\nCreation Time: " + timestamp + "\nMessage: \n" + msg_str);
    });
}

// copyTextToClipboard code from https://stackoverflow.com/questions/400212/how-do-i-copy-to-the-clipboard-in-javascript
function copyTextToClipboard(text) {
    var textArea = document.createElement("textarea");

    //
    // *** This styling is an extra step which is likely not required. ***
    //
    // Why is it here? To ensure:
    // 1. the element is able to have focus and selection.
    // 2. if element was to flash render it has minimal visual impact.
    // 3. less flakyness with selection and copying which **might** occur if
    //    the textarea element is not visible.
    //
    // The likelihood is the element won't even render, not even a
    // flash, so some of these are just precautions. However in
    // Internet Explorer the element is visible whilst the popup
    // box asking the user for permission for the web page to
    // copy to the clipboard.
    //

    // Place in top-left corner of screen regardless of scroll position.
    textArea.style.position = 'fixed';
    textArea.style.top = 0;
    textArea.style.left = 0;

    // Ensure it has a small width and height. Setting to 1px / 1em
    // doesn't work as this gives a negative w/h on some browsers.
    textArea.style.width = '2em';
    textArea.style.height = '2em';

    // We don't need padding, reducing the size if it does flash render.
    textArea.style.padding = 0;

    // Clean up any borders.
    textArea.style.border = 'none';
    textArea.style.outline = 'none';
    textArea.style.boxShadow = 'none';

    // Avoid flash of white box if rendered for any reason.
    textArea.style.background = 'transparent';


    textArea.value = text;

    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();

    try {
        var successful = document.execCommand('copy');
        var msg = successful ? 'successful' : 'unsuccessful';
        console.log('Copying text command was ' + msg);
    } catch (err) {
        console.log('Oops, unable to copy');
    }

    document.body.removeChild(textArea);
}

function send_msg() {
    console.log("send new message");
    var sender_eid = document.getElementById("sender").value;;
    var receiver_eid = document.getElementById("receiver").value;
    var msg = document.getElementById("msg").value;
    console.log(sender_eid + " " + receiver_eid + " " + msg);
    Rust.bp7.then(function (bp7) {
        var b = bp7.new_std_bundle_now(sender_eid, receiver_eid, msg);
        if (bp7.valid_bundle(b)) {
            var bid = bp7.bid_from_bundle(b);
            var cbor = bp7.encode_to_cbor(b)
            document.getElementById("hexout").textContent = toHexString(cbor);
            document.getElementById("hexout").onclick = function () {
                window.open("http://cbor.me/?bytes=" + toHexString(cbor));
            };
            document.getElementById("outlen").textContent = cbor.length;
            document.getElementById("copy").onclick = function () {
                copyTextToClipboard(document.getElementById("hexout").textContent);
            };
        } else {
            console.log("fatal error creating new bundle!");
        }
    });
}