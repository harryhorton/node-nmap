
/*
 * NodeJS <-> NMAP interface
 * Author:  John Horton
 * Purpose: Create an interface for NodeJS applications to make use of NMAP installed on the local system.
 */

///<reference path="./typings/node/node.d.ts" />
import child_process = require('child_process');
import execSync = child_process.execSync;
import exec = child_process.exec;
import spawn = child_process.spawn;
import fs = require('fs');
import events = require('events');
import os = require('os');
import Queue = require('queued-up');
var xml2js = require('xml2js');

export module nodenmap {
    export interface host{
        hostname:string;
        ip:string;
        mac:any;
        openPorts: Array<port>;
        osNmap: string;
    }
    export interface port {
        port: number;
        service: string;
    }
    export var nmapLocation = "nmap";

    export class NmapScan extends events.EventEmitter {

        command: string[] = [];
        private nmapoutputXML: string = "";
        range: string[] = [];
        arguments: string[] = ['-oX', '-'];
        rawData: string ='';
        rawJSON: any;
        child: any;
        error: string = null;
        scanResults:host[];
        constructor(range: any, inputArguments?: any) {
            super();
            this.commandConstructor(range, inputArguments);
            this.initializeChildProcess();
        }

        private commandConstructor(range: any, additionalArguments?: any) {
            if (additionalArguments) {
                if (!Array.isArray(additionalArguments)) {
                    additionalArguments = additionalArguments.split(' ');
                }
                this.command = this.arguments.concat(additionalArguments);
            }else{
                this.command = this.arguments;
            }

            if (!Array.isArray(range)) {
                range = range.split(' ');
            }
            this.range = range;
            this.command = this.command.concat(this.range);
        }
        private initializeChildProcess() {
            this.child = spawn(nmapLocation, this.command);

            process.on('SIGINT', () => {
                this.child.kill();
            });
            process.on('uncaughtException', (err) => {
                this.child.kill();
            });
            process.on('exit', () => {
                this.child.kill();
            });
            this.child.stdout.on("data", (data) => {
                if (data.indexOf("percent") > -1) {
                    console.log(data.toString());
                } else {
                    this.rawData += data;
                }

            });

            this.child.stderr.on("data", (err) => {
                this.error = err.toString();
            });

            this.child.on("close", () => {
                if (this.error) {
                    this.emit('error', this.error);
                } else {
                    this.rawDataHandler(this.rawData);
                }
            });
        }
        startScan() {
            this.child.stdin.end();
        }
        scanComplete(results:host[]){
            this.scanResults = results;
            this.emit('complete', this.scanResults);
        }
        private rawDataHandler(data) {
            var results : host[];
            //turn NMAP's xml output into a json object
            xml2js.parseString(data, (err, result) => {
                if (err) {
                    this.emit('error', "Error converting XML to JSON in xml2js: "+err);
                } else {
                    this.rawJSON = result;
                    results = this.convertRawJsonToScanResults(this.rawJSON, (err) => {
                        this.emit('error', "Error converting raw json to cleans can results: " + err);
                    });
                    this.scanComplete(results);
                }

            });

        }
        private convertRawJsonToScanResults(xmlInput, onFailure):host[] {
            var tempHostList = [];
            if (!xmlInput['nmaprun']['host']) {
                onFailure("There was a problem with the supplied NMAP XML");
                return tempHostList;
            };
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
                        } else if (xmlInput[hostLoopIter]["address"][addressLoopIter]["$"]["addrtype"] === 'mac') {
                            tempHostList[hostLoopIter].mac = xmlInput[hostLoopIter]["address"][addressLoopIter]["$"]["addr"];
                        } else {

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
                        tempHostList[hostLoopIter].osNmap = xmlInput[hostLoopIter].os[0].osmatch[0].$.name
                    } else {
                        tempHostList[hostLoopIter].osNmap = null;
                    }

                };
            } catch (e) {
                onFailure(e);
            } finally {
                return tempHostList;
            }
        }
    }
    export class quickScan extends NmapScan{
        constructor(range:any){
            super(range, '-sV');
        }
    }
    export class osAndPortScan extends NmapScan{
        constructor(range:any){
            super(range, '-O');
        }
    }
    export class autoDiscover extends NmapScan{
        constructor(){
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
            super(range, '-sV -O');
        }
    }
}

exports = nodenmap;



