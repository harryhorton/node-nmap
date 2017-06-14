var nmap = require('./node-nmap');
var scan = new nmap.OsAndPortScan("192.168.0.1-12");
//scan.runActionOnError = true;
//scan.saveErrorsToResults =true;
console.log('scan starting');
scan.on('complete', function (data) {
    console.log(JSON.stringify(data, null, 4));
    console.log("total scan time" + scan.scanTime);
});

scan.on('error', function (data) {
    console.log(JSON.stringify(data,null, 2));
    console.log("total scan time" + scan.scanTime);
});

scan.startScan();
//# sourceMappingURL=app.js.map