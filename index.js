/*
 * NodeJS <-> NMAP interface
 * Author:  John Horton
 * Purpose: Create an interface for NodeJS applications to make use of NMAP installed on the local system.
 */
var __extends = (this && this.__extends) || function (d, b) {
    for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p];
    function __() { this.constructor = d; }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
};
///<reference path="./typings/node/node.d.ts" />
var child_process = require('child_process');
var spawn = child_process.spawn;
var events = require('events');
var Queue = require('queued-up');
var xml2js = require('xml2js');
var nodenmap;
(function (nodenmap) {
    nodenmap.nmapLocation = "nmap";
    var NmapScan = (function (_super) {
        __extends(NmapScan, _super);
        function NmapScan(range, inputArguments) {
            _super.call(this);
            this.command = [];
            this.nmapoutputXML = "";
            this.range = [];
            this.arguments = ['-oX', '-'];
            this.rawData = '';
            this.cancelled = false;
            this.scanTime = 0;
            this.error = null;
            this.scanTimeout = 0;
            this.commandConstructor(range, inputArguments);
            this.initializeChildProcess();
        }
        NmapScan.prototype.startTimer = function () {
            var _this = this;
            this.timer = setInterval(function () {
                _this.scanTime += 10;
                if (_this.scanTime >= _this.scanTimeout && _this.scanTimeout !== 0) {
                    _this.killChild();
                }
            }, 10);
        };
        NmapScan.prototype.stopTimer = function () {
            clearInterval(this.timer);
        };
        NmapScan.prototype.commandConstructor = function (range, additionalArguments) {
            if (additionalArguments) {
                if (!Array.isArray(additionalArguments)) {
                    additionalArguments = additionalArguments.split(' ');
                }
                this.command = this.arguments.concat(additionalArguments);
            }
            else {
                this.command = this.arguments;
            }
            if (!Array.isArray(range)) {
                range = range.split(' ');
            }
            this.range = range;
            this.command = this.command.concat(this.range);
        };
        NmapScan.prototype.killChild = function () {
            this.cancelled = true;
            if (this.child) {
                this.child.kill();
            }
        };
        NmapScan.prototype.initializeChildProcess = function () {
            var _this = this;
            this.startTimer();
            this.child = spawn(nodenmap.nmapLocation, this.command);
            process.on('SIGINT', this.killChild);
            process.on('uncaughtException', this.killChild);
            process.on('exit', this.killChild);
            this.child.stdout.on("data", function (data) {
                if (data.indexOf("percent") > -1) {
                }
                else {
                    _this.rawData += data;
                }
            });
            this.child.on('error', function (err) {
                _this.killChild();
                if (err.code === 'ENOENT') {
                    _this.emit('error', 'NMAP not found at command location: ' + nodenmap.nmapLocation);
                }
                else {
                    _this.emit('error', err.Error);
                }
            });
            this.child.stderr.on("data", function (err) {
                _this.error = err.toString();
            });
            this.child.on("close", function () {
                process.removeListener('SIGINT', _this.killChild);
                process.removeListener('uncaughtException', _this.killChild);
                process.removeListener('exit', _this.killChild);
                if (_this.error) {
                    _this.emit('error', _this.error);
                }
                else if (_this.cancelled === true) {
                    _this.emit('error', "Over scan timeout " + _this.scanTimeout);
                }
                else {
                    _this.rawDataHandler(_this.rawData);
                }
            });
        };
        NmapScan.prototype.startScan = function () {
            this.child.stdin.end();
        };
        NmapScan.prototype.cancelScan = function () {
            this.killChild();
            this.emit('error', "Scan cancelled");
        };
        NmapScan.prototype.scanComplete = function (results) {
            this.scanResults = results;
            this.stopTimer();
            this.emit('complete', this.scanResults);
        };
        NmapScan.prototype.rawDataHandler = function (data) {
            var _this = this;
            var results;
            //turn NMAP's xml output into a json object
            xml2js.parseString(data, function (err, result) {
                if (err) {
                    _this.emit('error', "Error converting XML to JSON in xml2js: " + err);
                }
                else {
                    _this.rawJSON = result;
                    results = _this.convertRawJsonToScanResults(_this.rawJSON, function (err) {
                        _this.emit('error', "Error converting raw json to cleans can results: " + err + ": " + _this.rawJSON);
                    });
                    _this.scanComplete(results);
                }
            });
        };
        NmapScan.prototype.convertRawJsonToScanResults = function (xmlInput, onFailure) {
            var tempHostList = [];
            if (!xmlInput['nmaprun']['host']) {
                //onFailure("There was a problem with the supplied NMAP XML");
                return tempHostList;
            }
            ;
            try {
                xmlInput = xmlInput['nmaprun']['host'];
                //Create a new object for each host found
                for (var hostLoopIter = 0; hostLoopIter < xmlInput.length; hostLoopIter++) {
                    //create the temphost object for each host.
                    tempHostList[hostLoopIter] = {
                        hostname: null,
                        ip: null,
                        mac: null,
                        openPorts: []
                    };
                    //Check if the hostname is avaialble.  \r\n or \n is what will return if not available.
                    if (xmlInput[hostLoopIter]['hostnames'][0] !== "\r\n" && xmlInput[hostLoopIter]['hostnames'][0] !== "\n") {
                        tempHostList[hostLoopIter].hostname = xmlInput[hostLoopIter]['hostnames'][0]['hostname'][0]['$']['name'];
                    }
                    //For each network address type found
                    for (var addressLoopIter = 0; addressLoopIter < xmlInput[hostLoopIter]["address"].length; addressLoopIter++) {
                        //If IPv4, Mac, or unknown.  Get the type and add it or log the type found.
                        if (xmlInput[hostLoopIter]["address"][addressLoopIter]["$"]["addrtype"] === 'ipv4') {
                            tempHostList[hostLoopIter].ip = xmlInput[hostLoopIter]["address"][addressLoopIter]["$"]["addr"];
                        }
                        else if (xmlInput[hostLoopIter]["address"][addressLoopIter]["$"]["addrtype"] === 'mac') {
                            tempHostList[hostLoopIter].mac = xmlInput[hostLoopIter]["address"][addressLoopIter]["$"]["addr"];
                            tempHostList[hostLoopIter].vendor = xmlInput[hostLoopIter]["address"][addressLoopIter]["$"]["vendor"];
                        }
                        else {
                        }
                    }
                    //check if port list is available
                    if (xmlInput[hostLoopIter]["ports"] && xmlInput[hostLoopIter]["ports"][0]["port"]) {
                        //for each port scanned
                        for (var portLoopIter = 0; portLoopIter < xmlInput[hostLoopIter]["ports"][0]["port"].length; portLoopIter++) {
                            //if the state of the port is open
                            if (xmlInput[hostLoopIter]["ports"][0]["port"][portLoopIter]['state'][0]['$']['state'] === 'open') {
                                tempHostList[hostLoopIter].openPorts[portLoopIter] = {};
                                //Get the port number
                                tempHostList[hostLoopIter].openPorts[portLoopIter].port = parseInt(xmlInput[hostLoopIter]["ports"][0]["port"][portLoopIter]['$']['portid']);
                                //Get the port name
                                if (xmlInput[hostLoopIter]["ports"][0]["port"][portLoopIter]['service']) {
                                    tempHostList[hostLoopIter].openPorts[portLoopIter].service = xmlInput[hostLoopIter]["ports"][0]["port"][portLoopIter]['service'][0]['$']['name'];
                                }
                            }
                        }
                    }
                    if (xmlInput[hostLoopIter].os && xmlInput[hostLoopIter].os[0].osmatch && xmlInput[hostLoopIter].os[0].osmatch[0].$.name) {
                        tempHostList[hostLoopIter].osNmap = xmlInput[hostLoopIter].os[0].osmatch[0].$.name;
                    }
                    else {
                        tempHostList[hostLoopIter].osNmap = null;
                    }
                }
                ;
            }
            catch (e) {
                onFailure(e);
            }
            finally {
                return tempHostList;
            }
        };
        return NmapScan;
    })(events.EventEmitter);
    nodenmap.NmapScan = NmapScan;
    var QuickScan = (function (_super) {
        __extends(QuickScan, _super);
        function QuickScan(range) {
            _super.call(this, range, '-sP');
        }
        return QuickScan;
    })(NmapScan);
    nodenmap.QuickScan = QuickScan;
    var OsAndPortScan = (function (_super) {
        __extends(OsAndPortScan, _super);
        function OsAndPortScan(range) {
            _super.call(this, range, '-O');
        }
        return OsAndPortScan;
    })(NmapScan);
    nodenmap.OsAndPortScan = OsAndPortScan;
    // export class autoDiscover extends NmapScan {
    //     constructor() {
    //         var interfaces = os.networkInterfaces();
    //         var addresses = [];
    //         for (var k in interfaces) {
    //             for (var k2 in interfaces[k]) {
    //                 var address = interfaces[k][k2];
    //                 if (address.family === 'IPv4' && !address.internal) {
    //                     addresses.push(address.address);
    //                 }
    //             }
    //         }
    //         var ip = addresses[0];
    //         var octets = ip.split('.');
    //         octets.pop();
    //         octets = octets.concat('1-254');
    //         var range = octets.join('.');
    //         super(range, '-sV -O');
    //     }
    // }
    var QueuedScan = (function (_super) {
        __extends(QueuedScan, _super);
        function QueuedScan(scanClass, range, args, action) {
            var _this = this;
            if (action === void 0) { action = function () { }; }
            _super.call(this);
            this.scanResults = [];
            this.scanTime = 0;
            this.runActionOnError = false;
            this.saveErrorsToResults = false;
            this.singleScanTimeout = 0;
            this.saveNotFoundToResults = false;
            this._queue = new Queue(function (host) {
                if (args !== null) {
                    _this.currentScan = new scanClass(host, args);
                }
                else {
                    _this.currentScan = new scanClass(host);
                }
                if (_this.singleScanTimeout !== 0) {
                    _this.currentScan.scanTimeout = _this.singleScanTimeout;
                }
                _this.currentScan.on('complete', function (data) {
                    _this.scanTime += _this.currentScan.scanTime;
                    if (data[0]) {
                        data[0].scanTime = _this.currentScan.scanTime;
                        _this.scanResults = _this.scanResults.concat(data);
                    }
                    else if (_this.saveNotFoundToResults) {
                        data[0] = {
                            error: "Host not found",
                            scanTime: _this.currentScan.scanTime
                        };
                        _this.scanResults = _this.scanResults.concat(data);
                    }
                    action(data);
                    _this._queue.done();
                });
                _this.currentScan.on('error', function (err) {
                    _this.scanTime += _this.currentScan.scanTime;
                    var data = { error: err, scanTime: _this.currentScan.scanTime };
                    if (_this.saveErrorsToResults) {
                        _this.scanResults = _this.scanResults.concat(data);
                    }
                    if (_this.runActionOnError) {
                        action(data);
                    }
                    _this._queue.done();
                });
                _this.currentScan.startScan();
            });
            this._queue.add(this.rangeFormatter(range));
            this._queue.on('complete', function () {
                _this.emit('complete', _this.scanResults);
            });
        }
        QueuedScan.prototype.rangeFormatter = function (range) {
            var outputRange = [];
            if (!Array.isArray(range)) {
                range = range.split(' ');
            }
            for (var i = 0; i < range.length; i++) {
                var input = range[i];
                var temprange = range[i];
                if (countCharacterOccurence(input, ".") === 3
                    && input.match(new RegExp("-", "g")) !== null
                    && !input.match(/^[a-zA-Z]+$/)
                    && input.match(new RegExp("-", "g")).length === 1) {
                    var firstIP = input.slice(0, input.indexOf("-"));
                    var network;
                    var lastNumber = input.slice(input.indexOf("-") + 1);
                    var firstNumber;
                    var newRange = [];
                    for (var j = firstIP.length - 1; j > -1; j--) {
                        if (firstIP.charAt(j) === ".") {
                            firstNumber = firstIP.slice(j + 1);
                            network = firstIP.slice(0, j + 1);
                            break;
                        }
                    }
                    for (var iter = firstNumber; iter <= lastNumber; iter++) {
                        newRange.push(network + iter);
                    }
                    //replace the range/host string with array
                    temprange = newRange;
                }
                outputRange = outputRange.concat(temprange);
            }
            function countCharacterOccurence(input, character) {
                var num = 0;
                for (var k = 0; k < input.length; k++) {
                    if (input.charAt(k) === character) {
                        num++;
                    }
                }
                return num;
            }
            return outputRange;
        };
        QueuedScan.prototype.startRunScan = function (index) {
            if (index === void 0) { index = 0; }
            this.scanResults = [];
            this._queue.run(0);
        };
        QueuedScan.prototype.startShiftScan = function () {
            this.scanResults = [];
            this._queue.shiftRun();
        };
        QueuedScan.prototype.pause = function () {
            this._queue.pause();
        };
        QueuedScan.prototype.resume = function () {
            this._queue.resume();
        };
        QueuedScan.prototype.next = function (iterations) {
            if (iterations === void 0) { iterations = 1; }
            return this._queue.next(iterations);
        };
        QueuedScan.prototype.shift = function (iterations) {
            if (iterations === void 0) { iterations = 1; }
            return this._queue.shift(iterations);
        };
        QueuedScan.prototype.results = function () {
            return this.scanResults;
        };
        QueuedScan.prototype.shiftResults = function () {
            this._queue.shiftResults();
            return this.scanResults.shift();
        };
        QueuedScan.prototype.index = function () {
            return this._queue.index();
        };
        QueuedScan.prototype.queue = function (newQueue) {
            if (Array.isArray(newQueue)) {
                return this._queue.queue(newQueue);
            }
            else {
                return this._queue.queue();
            }
        };
        QueuedScan.prototype.percentComplete = function () {
            return Math.round(((this._queue.index() + 1) / this._queue.queue().length) * 100);
        };
        return QueuedScan;
    })(events.EventEmitter);
    nodenmap.QueuedScan = QueuedScan;
    var QueuedNmapScan = (function (_super) {
        __extends(QueuedNmapScan, _super);
        function QueuedNmapScan(range, additionalArguments, actionFunction) {
            if (actionFunction === void 0) { actionFunction = function () { }; }
            _super.call(this, NmapScan, range, additionalArguments, actionFunction);
        }
        return QueuedNmapScan;
    })(QueuedScan);
    nodenmap.QueuedNmapScan = QueuedNmapScan;
    var QueuedQuickScan = (function (_super) {
        __extends(QueuedQuickScan, _super);
        function QueuedQuickScan(range, actionFunction) {
            if (actionFunction === void 0) { actionFunction = function () { }; }
            _super.call(this, QuickScan, range, null, actionFunction);
        }
        return QueuedQuickScan;
    })(QueuedScan);
    nodenmap.QueuedQuickScan = QueuedQuickScan;
    var QueuedOsAndPortScan = (function (_super) {
        __extends(QueuedOsAndPortScan, _super);
        function QueuedOsAndPortScan(range, actionFunction) {
            if (actionFunction === void 0) { actionFunction = function () { }; }
            _super.call(this, OsAndPortScan, range, null, actionFunction);
        }
        return QueuedOsAndPortScan;
    })(QueuedScan);
    nodenmap.QueuedOsAndPortScan = QueuedOsAndPortScan;
})(nodenmap = exports.nodenmap || (exports.nodenmap = {}));
exports = nodenmap;
//# sourceMappingURL=index.js.map