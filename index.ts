
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
    export interface host {
        hostname: string;
        ip: string;
        mac: any;
        openPorts: Array<port>;
        osNmap: string;
        scanTime?:number;
        error?:string;
    }
    export interface port {
        port: number;
        service: string;
    }
    export var nmapLocation = "nmap";

    export class NmapScan extends events.EventEmitter {

        command: string[] = [];
        private nmapoutputXML: string = "";
        private timer;
        range: string[] = [];
        arguments: string[] = ['-oX', '-'];
        rawData: string = '';
        rawJSON: any;
        child: any;
        cancelled:boolean = false;
        scanTime: number = 0;
        error: string = null;
        scanResults: host[];
        scanTimeout: number = 0;
        constructor(range: any, inputArguments?: any) {
            super();
            this.commandConstructor(range, inputArguments);
            this.initializeChildProcess();
        }
        private startTimer(){
            
            this.timer = setInterval(()=>{
                this.scanTime += 10;
                if(this.scanTime >= this.scanTimeout && this.scanTimeout !== 0){
                    this.killChild();
                }
            },10);
        }
        private stopTimer(){
            clearInterval(this.timer);
        }
        private commandConstructor(range: any, additionalArguments?: any) {
            if (additionalArguments) {
                if (!Array.isArray(additionalArguments)) {
                    additionalArguments = additionalArguments.split(' ');
                }
                this.command = this.arguments.concat(additionalArguments);
            } else {
                this.command = this.arguments;
            }

            if (!Array.isArray(range)) {
                range = range.split(' ');
            }
            this.range = range;
            this.command = this.command.concat(this.range);
        }
        private killChild(){
            this.cancelled = true;
            this.child.kill();
        }
        private initializeChildProcess() {
            this.startTimer();
            this.child = spawn(nmapLocation, this.command);
            process.on('SIGINT', this.killChild);
            process.on('uncaughtException', this.killChild);
            process.on('exit', this.killChild);
            this.child.stdout.on("data", (data) => {
                if (data.indexOf("percent") > -1) {
                    console.log(data.toString());
                }else{
                    this.rawData += data;
                }

            });

            this.child.stderr.on("data", (err) => {
                this.error = err.toString();
                console.log("error found:" + this.error);
            });

            this.child.on("close", () => {
                
                process.removeListener('SIGINT',this.killChild);
                process.removeListener('uncaughtException',this.killChild);
                process.removeListener('exit',this.killChild);
                
                if (this.error) {
                    this.emit('error', this.error);
                } else if(this.cancelled === true){
                    this.emit('error', "Over scan timeout " + this.scanTimeout);
                } else {
                    this.rawDataHandler(this.rawData);
                }
            });
        }
        startScan() {
            this.child.stdin.end();
        }
        cancelScan(){
            this.killChild();
            this.emit('error', "Scan cancelled");
        }
        private scanComplete(results: host[]) {
            this.scanResults = results;
            this.stopTimer();
            this.emit('complete', this.scanResults);
        }
        private rawDataHandler(data) {
            var results: host[];
            //turn NMAP's xml output into a json object
            xml2js.parseString(data, (err, result) => {
                if (err) {
                    this.emit('error', "Error converting XML to JSON in xml2js: " + err);
                } else {
                    this.rawJSON = result;
                    results = this.convertRawJsonToScanResults(this.rawJSON, (err) => {
                        console.log(this.rawJSON);
                        this.emit('error', "Error converting raw json to cleans can results: " + err + ": " + this.rawJSON);

                    });
                    this.scanComplete(results);
                }

            });

        }
        private convertRawJsonToScanResults(xmlInput, onFailure): host[] {
            var tempHostList = [];
            if (!xmlInput['nmaprun']['host']) {
                //onFailure("There was a problem with the supplied NMAP XML");
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
    export class QuickScan extends NmapScan {
        constructor(range: any) {
            super(range, '-sP');
        }
    }
    export class OsAndPortScan extends NmapScan {
        constructor(range: any) {
            super(range, '-O');
        }
    }
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
    
    

    export class QueuedScan extends events.EventEmitter {
        private _queue: Queue;
        scanResults: host[] = [];
        scanTime: number = 0;
        currentScan;
        runActionOnError: boolean = false;
        saveErrorsToResults: boolean = false;
        singleScanTimeout: number = 0;
        saveNotFoundToResults: boolean = false;
        constructor(scanClass: any, range: any, args: any[], action: Function = () => { }) {
            super();


            this._queue = new Queue((host) => {

                if (args !== null) {
                    this.currentScan = new scanClass(host, args);
                } else {
                    this.currentScan = new scanClass(host);
                }
                if(this.singleScanTimeout !== 0){
                    this.currentScan.scanTimeout = this.singleScanTimeout;
                }

                this.currentScan.on('complete', (data) => {
                    this.scanTime += this.currentScan.scanTime;
                    if(data[0]){
                        data[0].scanTime = this.currentScan.scanTime;
                        this.scanResults = this.scanResults.concat(data);
                    }else if(this.saveNotFoundToResults){
                            data[0] = {
                                error: "Host not found",
                                scanTime: this.currentScan.scanTime
                            }
                            this.scanResults = this.scanResults.concat(data);
                        
                    }
                    
                    
                    
                    action(data);
                    this._queue.done();
                });
                this.currentScan.on('error', (err) => {
                    this.scanTime += this.currentScan.scanTime;
                    
                    var data = {error: err, scanTime: this.currentScan.scanTime}
                    
                    
                    if(this.saveErrorsToResults){
                        this.scanResults = this.scanResults.concat(data);
                    }
                    if(this.runActionOnError){
                        action(data);    
                    }
                    
                    this._queue.done();
                });

                this.currentScan.startScan();
            });

            this._queue.add(this.rangeFormatter(range));

            this._queue.on('complete', () => {
                this.emit('complete', this.scanResults);
                
            });
        }

        private rangeFormatter(range) {
            var outputRange = [];
            if (!Array.isArray(range)) {
                range = range.split(' ');
            }

            for (var i = 0; i < range.length; i++) {
                var input = range[i];
                var temprange = range[i];
                if (countCharacterOccurence(input, ".") === 3
                    && !input.match(/^[a-zA-Z]+$/)
                    && input.match(new RegExp("-", "g")).length === 1
                ) {
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
        }
        startRunScan(index: number = 0) {
            this.scanResults = [];
            this._queue.run(0);
        }
        startShiftScan() {
            this.scanResults = [];
            this._queue.shiftRun();
        }
        pause() {
            this._queue.pause();
        }
        resume() {
            this._queue.resume();
        }
        next(iterations: number = 1) {
            return this._queue.next(iterations);
        }
        shift(iterations: number = 1) {
            return this._queue.shift(iterations);
        }
        results() {
            return this.scanResults;
        }
        shiftResults() {
            this._queue.shiftResults();
            return this.scanResults.shift();
        }
        index() {
            return this._queue.index();
        }
        queue(newQueue?: any[]): any[] {

            if (Array.isArray(newQueue)) {
                return this._queue.queue(newQueue);

            } else {
                return this._queue.queue();
            }
        }
        percentComplete() {
            return Math.round(((this._queue.index() + 1) / this._queue.queue().length) * 100);
        }
    }
    export class QueuedNmapScan extends QueuedScan {
        constructor(range: any, additionalArguments?: any, actionFunction: Function = () => { }) {
            super(NmapScan, range, additionalArguments, actionFunction);
        }
    }
    export class QueuedQuickScan extends QueuedScan {
        constructor(range: any, actionFunction: Function = () => { }) {
            super(QuickScan, range, null, actionFunction);
        }
    }
    export class QueuedOsAndPortScan extends QueuedScan {
        constructor(range: any, actionFunction: Function = () => { }) {
            super(OsAndPortScan, range, null, actionFunction);
        }
    }
}

exports = nodenmap;



