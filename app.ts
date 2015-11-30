import nmap = require('./index');

var scan = new nmap.("google.com");
scan.on('error', function(err){
	console.log(err);
	console.log(scan.rawData);
});
scan.on('complete', function(data){
	logHost(data[0]);
});
console.log(scan.command);
scan.startScan();
function logHost(host : nmap.nodenmap.host){
	console.log(host);
}
