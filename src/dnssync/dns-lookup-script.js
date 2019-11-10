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

var dns = require('dns'),
    debug = require('debug')('dns-sync'),
    name, type, fn;

for (var i = 0; i < process.argv.length; i++) {
    if (process.argv[i].indexOf('dns-lookup-script') >= 0) {
        name = process.argv[i + 1];
        type = process.argv[i + 2];
        fn = type ? dns.resolve.bind(dns, name, type) : dns.lookup.bind(dns, name);
        break;
    }
}

fn(function(err, ip) {
    if (err) {
        debug(err);
        process.exit(1);
    } else {
        debug(name, 'resolved to', ip);
        process.stdout.write(JSON.stringify(ip));
    }
});