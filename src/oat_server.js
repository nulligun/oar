import axios from "axios";
let config = require('config');
let restify = require('restify');
let server = restify.createServer();
let rsa = require('jsrsasign');
let fs = require('fs');

let sig = new rsa.Signature({"alg": config.get('app.key_algo')});

let data = '';
try {
	data = fs.readFileSync(config.get('app.key_file'), 'utf8');
} catch(e) {
	console.log('Error:', e.stack);
}

sig.init(data, config.get('app.key_password'));

function parse_oa_string(oa_string)
{
	let mode = 'key';
	let key = '';
	let value = '';
	let valuePos = 0;
	let quotedString = false;
	let results = {};
	for (let i = 0; i < oa_string.length; i++) {
		let char = oa_string.substr(i, 1);
		if (mode === 'key') {
			if (char === '=') {
				key = key.trim();
				mode = 'value';
				valuePos = 0;
				quotedString = false;
			} else {
				key = key + char;
			}
		} else if (mode === 'value') {
			if (char === '"') {
				if (valuePos === 0) {
					quotedString = true;
				} else {
					if (!quotedString) {
						value = value + char;
					} else {
						quotedString = false;
					}
				}
			} else if (char === ';') {
				if (quotedString) {
					value = value + char;
				} else {
					mode = 'key';
					results[key] = value.trim();
					key = '';
					value = '';
				}
			} else {
				value = value + char;
			}
			valuePos = valuePos + 1;
		}
	}

	if (key !== '') {
		results[key] = value.trim();
	}
	return results;
}

function get_oa_entries(address, records)
{
	let result = [];
	records.forEach((r) => {
		let record = r.data.replace(/^"|"$/, '').replace(/\"\"/, '');
		if (record.substr(0, 4).toLowerCase() == 'oa1:')
		{
			let rec = record.substr(4).trim();
			let matches = rec.match(/^(.*?) (.*)"$/);
			let currency = matches[1].toLowerCase();
			let properties = parse_oa_string(matches[2]);
			result.push({currency: currency, domain: address, txt: record, properties: properties});
		}
	});

	return result;
}

function oa_sign_result(result)
{
	sig.updateString(JSON.stringify(result));
	let sigValueHex = sig.sign();

	return sigValueHex;
}

function lookup(request, response, next) {
	let address = request.body.address;

	axios.get('https://dns.google.com/resolve', {params: {name: address, type: 'TXT'}}).then((res) => {
		let result = {};
		result['status'] = res.data.Status;
		if (res.data.Status === 1) {
			result['message'] = 'DNS Query Format Error';
		} else if (res.data.Status === 2) {
			result['message'] = 'Server failed to complete the DNS request';
		} else if (res.data.Status === 3) {
			result['message'] = 'Domain name does not exist';
		} else if (res.data.Status === 4) {
			result['message'] = 'Function not implemented';
		} else if (res.data.Status === 5) {
			result['message'] = 'The server refused to answer for the query';
		} else if (res.data.Status === 6) {
			result['message'] = 'Name that should not exist, does exist';
		} else if (res.data.Status === 7) {
			result['message'] = 'RRset that should not exist, does exist';
		} else if (res.data.Status === 8) {
			result['message'] = 'Server not authoritative for the zone';
		} else if (res.data.Status === 9) {
			result['message'] = 'Name not in zone';
		} else if (res.data.Status !== 0) {
			result['message'] = 'Unknown error: ' + res.data.Status;
		}
		result['googledns'] = res.data.RD && res.data.RA;
		result['dnssec_valid'] = res.data.AD;

		if ('Answer' in res.data) {
			result['records'] = get_oa_entries(address, res.data.Answer);
		} else {
			result['records'] = [];
		}

		response.send({payload: result, signature: oa_sign_result(result)});
		next();
	});
}

server.use(restify.plugins.bodyParser());
server.post('/lookup', lookup);

server.listen(config.get("app.port"), function () {
	console.log('%s listening at %s', server.name, server.url);
});