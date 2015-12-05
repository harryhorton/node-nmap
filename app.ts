import nmap = require('./index');

var scan = new nmap.nodenmap.queuedScan("google.com 192.168.0.1-10", function(data){
	console.log(data);
	console.log(scan.percentComplete());
});

scan.on('complete', function(data){
	console.log(data);
});
scan.startRunScan();
