// The MIT License (MIT)

// Copyright (c) 2014 skoranga

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.


// ---------------------------------------------------------------------//
// ---------------------------------------------------------------------//
// The code was modified by ridesolo@protonmail.com to include TXT record
// ---------------------------------------------------------------------//
// ---------------------------------------------------------------------//

'use strict';

var util = require('util'),
    path = require('path'),
    shell = require('shelljs'),
    debug = require('debug')('dns-sync');

//source - http://stackoverflow.com/questions/106179/regular-expression-to-match-dns-hostname-or-ip-address
var ValidHostnameRegex = new RegExp("^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$");

function isValidHostName(hostname) {
    return ValidHostnameRegex.test(hostname);
}
/**
 * Resolve hostname to IP address,
 * returns null in case of error
 */
module.exports = {
    lookup: function lookup(hostname) {
        return module.exports.resolve(hostname);
    },
    resolve: function resolve(hostname, type) {
        var nodeBinary = process.execPath;
        if (type !== 'TXT' && !isValidHostName(hostname)) {
            throw Error('Invalid hostname:' + hostname);
        }

        var scriptPath = path.join(__dirname, "./dns-lookup-script");
        var response,
            cmd = util.format('"%s" "%s" %s %s', nodeBinary, scriptPath, hostname, type || '');

        response = shell.exec(cmd, {silent: true});
        if (response && response.code === 0) {
            return JSON.parse(response.stdout);
        }
        throw Error('hostname', "fail to resolve hostname " + hostname);
    }
};
