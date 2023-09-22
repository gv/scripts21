#!/usr/bin/env node

/*
  Prints every leaf value in JSON file on a single line prepended by all the
  keys leading to it. Pipe through grep to find out which keys contain 
  matching values
*/

const fs = require('fs');

printTable();

function printTable() {
	if(process.argv.length <= 2) {
		console.error(`USAGE: ${process.argv[1]} JSON_FILE ...`);
		process.exit(1);
	}
	for(let i = 2; i < process.argv.length; i++) {
		printFile(process.argv[i]); 
	}
}

function printFile(path) {
	fs.readFile(path, function(e, content) {
		if(e) {
			console.error(path, e);
			return;
		}
		try {
			var d = JSON.parse(content.toString("utf-8"));
		} catch(e) {
			console.error(path, e);
			return;
		}
		printObject([path], d);
	});
}

function printObject(prefix, d) {
	try {
		if(typeof d != "string" && typeof d != "number") {
			for(var k in d)
				printObject(prefix.concat(k), d[k]);
			return;
		}
	} catch(e) {}
	console.log(prefix.join(" "), d);
}
