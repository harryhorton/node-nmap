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
var os = require('os');
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
            this.error = null;
            this.commandConstructor(range, inputArguments);
            this.initializeChildProcess();
        }
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
        NmapScan.prototype.initializeChildProcess = function () {
            var _this = this;
            this.child = spawn(nodenmap.nmapLocation, this.command);
            process.on('SIGINT', function () {
                _this.child.kill();
            });
            process.on('uncaughtException', function (err) {
                _this.child.kill();
            });
            process.on('exit', function () {
                _this.child.kill();
            });
            this.child.stdout.on("data", function (data) {
                if (data.indexOf("percent") > -1) {
                    console.log(data.toString());
                }
                else {
                    _this.rawData += data;
                }
            });
            this.child.stderr.on("data", function (err) {
                _this.error = err.toString();
            });
            this.child.on("close", function () {
                if (_this.error) {
                    _this.emit('error', _this.error);
                }
                else {
                    _this.rawDataHandler(_this.rawData);
                }
            });
        };
        NmapScan.prototype.startScan = function () {
            this.child.stdin.end();
        };
        NmapScan.prototype.scanComplete = function (results) {
            this.scanResults = results;
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
                        _this.emit('error', "Error converting raw json to cleans can results: " + err);
                    });
                    _this.scanComplete(results);
                }
            });
        };
        NmapScan.prototype.convertRawJsonToScanResults = function (xmlInput, onFailure) {
            var tempHostList = [];
            if (!xmlInput['nmaprun']['host']) {
                onFailure("There was a problem with the supplied NMAP XML");
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
                                tempHostList[hostLoopIter].openPorts[portLoopIter].service = xmlInput[hostLoopIter]["ports"][0]["port"][portLoopIter]['service'][0]['$']['name'];
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
    var quickScan = (function (_super) {
        __extends(quickScan, _super);
        function quickScan(range) {
            _super.call(this, range, '-sV');
        }
        return quickScan;
    })(NmapScan);
    nodenmap.quickScan = quickScan;
    var osAndPortScan = (function (_super) {
        __extends(osAndPortScan, _super);
        function osAndPortScan(range) {
            _super.call(this, range, '-O');
        }
        return osAndPortScan;
    })(NmapScan);
    nodenmap.osAndPortScan = osAndPortScan;
    var autoDiscover = (function (_super) {
        __extends(autoDiscover, _super);
        function autoDiscover() {
            var interfaces = os.networkInterfaces();
            var addresses = [];
            for (var k in interfaces) {
                for (var k2 in interfaces[k]) {
                    var address = interfaces[k][k2];
                    if (address.family === 'IPv4' && !address.internal) {
                        addresses.push(address.address);
                    }
                }
            }
            var ip = addresses[0];
            var octets = ip.split('.');
            octets.pop();
            octets = octets.concat('1-254');
            var range = octets.join('.');
            _super.call(this, range, '-sV -O');
        }
        return autoDiscover;
    })(NmapScan);
    nodenmap.autoDiscover = autoDiscover;
})(nodenmap = exports.nodenmap || (exports.nodenmap = {}));
exports = nodenmap;
//# sourceMappingURL=index.js.map