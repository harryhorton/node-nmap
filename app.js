var nmap = require('./index');
var scan = new nmap.nodenmap.QueuedNmapScan("google.com 192.168.0.1-10", '-O', function (data) {
    console.log(data);
    console.log(scan.percentComplete());
});
scan.singleScanTimeout = 5000;
//scan.runActionOnError = true;
//scan.saveErrorsToResults =true;
scan.on('complete', function (data) {
    console.log(data);
    console.log("total scan time" + scan.scanTime);
});
scan.startRunScan();
//# sourceMappingURL=app.js.map