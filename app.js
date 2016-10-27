var nmap = require('./index');
var scan = new nmap.nodenmap.QuickScan("192.168.0.1-10");
//scan.runActionOnError = true;
//scan.saveErrorsToResults =true;
console.log('scan starting');
scan.on('complete', function (data) {
    console.log(data);
    console.log("total scan time" + scan.scanTime);
});
scan.startScan();
//# sourceMappingURL=app.js.map