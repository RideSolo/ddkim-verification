
var Signature = require( 'dkim-signature' );
var Key = require( 'dkim-key' );
var crypto = require( 'crypto' );
// var DKIMkey = require( 'dkim' );
var NodeRsa = require( 'node-rsa' );
var dnsSync = require('./dnssync/dns-sync');
var dkimKey = require( 'dkim-key' );
var ed25519id = require('ed25519-id');
var ed25519noble = require('./noble-ed25519/index');

var DKIM= {};
/** @type {String} */
DKIM.NONE = 'NONE'
/** @type {String} */
DKIM.OK = 'OK'
/** @type {String} */
DKIM.TEMPFAIL = 'TEMPFAIL'
/** @type {String} */
DKIM.PERMFAIL = 'PERMFAIL'



function parse(_eml)
{
  var obj={};
  obj.eml = _eml; 
  splitMessage(obj);
  splitHeaderLines(obj);

  obj.signature = Signature.parse(obj.json['dkim-signature'][1]);
  obj.signature.headers.push('dkim-signature');
  
  obj.bodyCanonicalAlgo = obj.signature.canonical.split( '/' ).pop();
  obj.headerCanonicalAlgo = obj.signature.canonical.split( '/' ).shift();

  obj.signatureAlgo =obj.signature.algorithm.toUpperCase();
  obj.algo = obj.signature.algorithm.split('-').shift().toUpperCase();
  obj.hashingAlgo = obj.signature.algorithm.split( '-' ).pop().toUpperCase();

  if(obj.algo === 'ED25519') parseEd25519Signature(obj);
  else if(obj.algo === 'RSA') obj.signatureHex = '0x' + obj.signature.signature.toString('hex');

  canonicalizeBody(obj);
  canonicalizeHeader(obj);

  obj.canonicalizedBodyHex   = '0x' + Buffer.from(obj.canonicalizedBody, 'utf8').toString('hex');
  obj.canonicalizedHeaderHex = '0x' + Buffer.from(obj.canonicalizedHeader, 'utf8').toString('hex');
  obj.bhHex = '0x' + obj.signature.hash.toString('hex');

  // compute body hash to check
  obj.canonicalizedBodyHash = '0x' + crypto.createHash(obj.hashingAlgo).update(obj.canonicalizedBody).digest().toString('hex');
  obj.canonicalizedHeaderHash = '0x' + crypto.createHash(obj.hashingAlgo).update(obj.canonicalizedHeader).digest().toString('hex');
  
  delete obj.eml;
  delete obj.body; 
  delete obj.headers;
  delete obj.headerLines;
  delete obj.json;

  return obj;
}

function parseEd25519Signature( obj) {
  var s = ed25519noble.SignResult.fromHex(obj.signature.signature);

  obj.signature.ed = {};
  obj.signature.ed.r = {};
  
  obj.signature.ed.r.x = '0x'+s.r.x.toString(16);
  obj.signature.ed.r.y = '0x'+s.r.y.toString(16);
  obj.signature.ed.s = '0x'+s.s.toString(16);
}

function splitMessage(obj) {
  // split email into headers and body
  // empty header section when email begins with CR?LF
  // or when email doesn't contain 2*CR?LF
  var match = obj.eml.match(/^\r?\n|((?:\r?\n)){2}/),
      headers = match && obj.eml.substr(0, match.index) || '',
      body = match && obj.eml.substr(match.index + match[0].length) || obj.eml;
  if (match && match[1]) {
    // make sure last header before body includes trailing newline
    headers = headers + match[1];
  }
  obj.headers = headers;
  obj.body = body;
};

function splitHeaderLines(obj) {
  var headerLines = obj.headers.split(/\r?\n|\r/), i;
  // join lines
  for (i = headerLines.length - 1; i >= 0; i--) {
      if (i && headerLines[i].match(/^\s/)) {
        headerLines[i - 1] += '\r\n' + headerLines.splice(i, 1);

      }
  }
  obj.headerLines = headerLines;

  var headersKeyLine= {};
  headerLines.forEach(function(line) {
    var index = line.indexOf(":");

    headersKeyLine[line.substr(0, index).toLowerCase()]= [ line.substr(0, index) , line.substr(index+1)];
  });
  
  obj.json = headersKeyLine;
}

function canonicalizeBody(obj) {
  if( obj.bodyCanonicalAlgo === 'simple' ) {
    obj.canonicalizedBody = obj.body.replace( /(\r\n)+$/g, '' ) + '\r\n';
  }
  else if(obj.bodyCanonicalAlgo === 'relaxed') {
      obj.canonicalizedBody = obj.body
      // Ignore all whitespace at the end of lines.
      .replace( /[\x20\x09]+(?=\r\n)/gm, '' )
      // Reduce all sequences of WSP within a line to a single SP
      .replace( /[\x20\x09]+/gm, ' ' )
      // Ignore all empty lines at the end of the message body.
      .replace( /(\r\n)+$/g, '' ) + '\r\n';
  } else {
    throw Error('Body canonicalization algorithm not recognized');
  }
}

function canonicalizeHeader(obj) {
  obj.canonicalizedHeader = [];
  if(obj.headerCanonicalAlgo ==='relaxed') {
    var headers_json = JSON.parse(JSON.stringify(obj.json));
    for(var i=0;i<obj.signature.headers.length;i++)
    {
      if(obj.signature.headers[i].toLowerCase().slice(0,2)!=='x-')
      {
        var value = headers_json[obj.signature.headers[i].toLowerCase()];
        if(value != null){
          // remove any sequence of WSP at line start
          
          value[1] = value[1]
          .replace(/^(\r|\n|\s)+/, '' )
          .replace(/^([\x20\x09])+/,'')
          // Unfold all header field continuation lines
          .replace( /\r\n/g, ' ' ) //(?=[\x20\x09])
          // Convert all sequences of one or more WSP characters to a single SP
          .replace( /[\x20\x09]+/g, ' ' )
          // Devare all WSP characters at the end of each unfolded header field
          .replace( /[\x20\x09]+$/g, '' );

          if( 'dkim-signature' === obj.signature.headers[i].toLowerCase()) {
            value[1] = value[1].replace( /b=([^;]*)/, 'b=' );
          }
          obj.canonicalizedHeader.push(obj.signature.headers[i].toLowerCase() + ":" + value[1]);
        }
        delete headers_json[obj.signature.headers[i].toLowerCase()];
      }
    }
    obj.canonicalizedHeader = obj.canonicalizedHeader.join(`\r\n`);
  }
  else if(obj.headerCanonicalAlgo ==='simple') {
    var headers_json = JSON.parse(JSON.stringify(obj.json));
    for(var i=0;i<obj.signature.headers.length;i++)
    {
      if(obj.signature.headers[i].toLowerCase().slice(0,2)!=='x-')
      {
        var value = headers_json[obj.signature.headers[i].toLowerCase()];
        if(value != null){
          if( 'dkim-signature' === obj.signature.headers[i].toLowerCase()) {
            value[1] = value[1].replace( /b=([^;]*)/, 'b=' );
          }
          obj.canonicalizedHeader.push(headers_json[obj.signature.headers[i].toLowerCase()][0] + ":" + value[1]);
        }
        delete headers_json[obj.signature.headers[i].toLowerCase()];
      }
    }
    obj.canonicalizedHeader = obj.canonicalizedHeader.join(`\r\n`);
  } else {
    throw Error('Header canonicalization algorithm not recognized')
  }
}


// function verifySig(obj,callback) {
//   DKIMkey.getKey( obj.signature.domain, obj.signature.selector, ( error, key ) => {
//     if( error != null ) {
//       result.error = error;
//       result.status = error.code;
      
//     }
//     var pubKey = '-----BEGIN PUBLIC KEY-----\n' +
//     key.key.toString( 'base64' ) +
//     '\n-----END PUBLIC KEY-----'

//     var res = crypto.createVerify(obj.signatureAlgo)
//       .update( obj.canonicalizedHeader )
//       .verify( pubKey, obj.signature.signature , 'base64');

//       var result = {};
//       result.res = res;
//       result.key  = "0x" + key.key.toString('hex');
//       result.data = obj;

//       return callback( error, result);
//   });
// }


function parseKeyRecord(records) {
  var error;
  var keys = records.map(( record ) => {
      try { return dkimKey.parse(record.join( '' ))}
      catch( e ) { return null }
  }).filter(( value ) => {
      return value != null
  })

  if( !keys.length ) {
    error = new Error( 'No key for signature' )
    error.code = DKIM.PERMFAIL
    throw error;
  }

  if( keys.length > 1 ) {
    error = new Error( 'Ambiguous key selection' )
    error.code = DKIM.TEMPFAIL
    throw error;
  }

  key = keys.shift()

  // If the result returned from the query does not adhere to the
  // format defined in this specification, the Verifier MUST ignore
  // the key record and return PERMFAIL (key syntax error).
  if( key == null || !Buffer.isBuffer( key.key ) ) {
    error = new Error( 'No public key found' )
    error.code = DKIM.PERMFAIL
    throw error;
  }
  return key;
}

function parseKey(key) {
  var pubKey = '-----BEGIN PUBLIC KEY-----\n' +
  key.key.toString( 'base64' ) +
  '\n-----END PUBLIC KEY-----'

  if(key.type.toLowerCase().includes('rsa'))
  { 
    var rsaKey = new NodeRsa();
    rsaKey.importKey(pubKey);
    var publicComponents = rsaKey.exportKey('components-public');     
    
    var exp = publicComponents.e.toString(16);
    if((exp.length % 2) == 1) exp = '0' + exp;

    var mod = publicComponents.n.toString('hex');
    if((mod.length % 2) == 1) mod = '0' + exp;
    key.rsa = {}
    key.rsa.exponent = '0x' + exp;
    key.rsa.modulus  = '0x' + mod;
    key.rsa.pubKey = pubKey;

  } else if(key.type === 'ed25519') {
    key.pubKey = pubKey
    key.key = ed25519id.parse(ed25519id.stringify(key.key));

    var p = ed25519noble.Point.fromHex(key.key);
    var s = ed25519noble.SignResult.fromHex(obj.signature.signature);
    key.ed = {};
    
    key.ed.px = p.x;
    key.ed.py = p.y;

    key.ed.pxh = '0x'+p.x.toString(16);
    key.ed.pyh = '0x'+p.y.toString(16);

    key.ed.lhs = {};

    key.ed.headerHash = '0x' + ed25519noble.hashNumberSync(
        s.r.encode(), 
        p.encode(),
        crypto.createHash(obj.hashingAlgo).update(obj.canonicalizedHeader).digest()
      ).toString(16);

    var lhs = ed25519noble.BASE_POINT.multiply(s.s);

    key.ed.lhs.x = '0x'+ lhs.x.toString(16);
    key.ed.lhs.y = '0x'+ lhs.y.toString(16);

  } else {
    error = new Error( 'No public key found' )
    error.code = DKIM.PERMFAIL;
    throw error;
  }
}

function getKeySync(obj) {
  var error;
  
  var domain = obj.signature.selector + '._domainkey.' + obj.signature.domain;
  var key =  parseKeyRecord(dnsSync.resolve( domain, 'TXT'));
  parseKey(parseKey);

  return key;
}

function verifySig(obj,key) {
  switch(obj.algo) {
    case 'RSA':
      return crypto.createVerify(obj.signatureAlgo)
        .update( obj.canonicalizedHeader )
        .verify( key.rsa.pubKey, obj.signature.signature , 'base64');
    break;
    case 'ED25519':
      return ed25519noble.verifySync(
        obj.signature.signature,
        crypto.createHash(obj.hashingAlgo).update(obj.canonicalizedHeader).digest(),
        key.key);
     //return ed25519.Verify(Buffer.from(obj.canonicalizedHeaderHash.slice(2),'hex'),obj.signature.signature,obj.key.key)
    break;
    default:
      error = new Error('Undefined Signature Scheme');
      error.code = DKIM.PERMFAIL;
      throw error;
  }
  return false;
}

module.exports = {
  parse,
  verifySig,
  getKeySync
}
