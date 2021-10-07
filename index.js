/*
 * NodeJS <-> NMAP interface
 * Author:  John Horton
 * Purpose: Create an interface for NodeJS applications to make use of NMAP installed on the local system.
 */

const child_process = require('child_process');
const execSync = child_process.execSync;
const exec = child_process.exec;
const spawn = child_process.spawn;
const fs = require('fs');
const EventEmitter = require('events').EventEmitter;
const os = require('os');
const Queue = require('queued-up');
const xml2js = require('xml2js');


/**
 *
 * @param {*} xmlInput
 * @param {*} onFailure
 * @returns {host[]} - Array of hosts
 */
function convertRawJsonToScanResults(xmlInput) {
  let tempHostList = [];

  if (!xmlInput.nmaprun.host) {
    //onFailure("There was a problem with the supplied NMAP XML");
    return tempHostList;
  };

  xmlInput = xmlInput.nmaprun.host;

  tempHostList = xmlInput.map((host) => {
    const newHost = {
      hostname: null,
      ip: null,
      mac: null,
      openPorts: null,
      osNmap: null
    }

    //Get hostname
    if (host.hostnames && host.hostnames[0] !== "\r\n" && host.hostnames[0] !== "\n") {
      newHost.hostname = host.hostnames[0].hostname[0].$.name
    }

    //get addresses
    host.address.forEach((address) => {
      const addressType = address.$.addrtype
      const addressAdress = address.$.addr
      const addressVendor = address.$.vendor

      if (addressType === 'ipv4') {
        newHost.ip = addressAdress
      } else if (addressType === 'mac') {
        newHost.mac = addressAdress
        newHost.vendor = addressVendor
      }
    })

    //get ports
    if (host.ports && host.ports[0].port) {
      const portList = host.ports[0].port

      const openPorts = portList.filter((port) => {
        return (port.state[0].$.state === 'open')
      })

      newHost.openPorts = openPorts.map((portItem) => {
        // console.log(JSON.stringify(portItem, null, 4))
        let portObject = {}

        const port = parseInt(portItem.$.portid)
        const protocol = portItem.$.protocol

        if(port) portObject.port = port
        if(protocol) portObject.protocol = protocol

        if (portItem.service) {
          const service = portItem.service[0].$.name
          const tunnel = portItem.service[0].$.tunnel
          const method = portItem.service[0].$.method
          const product = portItem.service[0].$.tunnel

          if(service) portObject.service = service
          if(tunnel) portObject.tunnel = tunnel
          if(method) portObject.method = method
          if(product) portObject.product = product
        }

        return portObject
      })
    }

    if (host.os && host.os[0].osmatch && host.os[0].osmatch[0].$.name) {
      newHost.osNmap = host.os[0].osmatch[0].$.name
    }
    return newHost
  })

  return tempHostList;
}


class NmapScan extends EventEmitter {
  constructor(range, inputArguments) {
    super();
    this.command = [];
    this.nmapoutputXML = "";
    this.timer;
    this.range = [];
    this.arguments = ['-oX', '-'];
    this.rawData = '';
    this.rawJSON;
    this.child;
    this.cancelled = false;
    this.scanTime = 0;
    this.error = null;
    this.scanResults;
    this.scanTimeout = 0;
    this.commandConstructor(range, inputArguments);
    this.initializeChildProcess();
  }

  startTimer() {
    this.timer = setInterval(() => {
      this.scanTime += 10;
      if (this.scanTime >= this.scanTimeout && this.scanTimeout !== 0) {
        this.killChild();
      }
    }, 10);
  }

  stopTimer() {
    clearInterval(this.timer);
  }

  commandConstructor(range, additionalArguments) {
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

  killChild() {
    this.cancelled = true;
    if (this.child) {
      this.child.kill();

    }
  }

  initializeChildProcess() {
    this.startTimer();
    this.child = spawn(nmap.nmapLocation, this.command);
    process.on('SIGINT', this.killChild);
    process.on('uncaughtException', this.killChild);
    process.on('exit', this.killChild);
    this.child.stdout.on("data", (data) => {
      if (data.indexOf("percent") > -1) {
        // console.log(data.toString());
      } else {
        this.rawData += data;
      }

    });

    this.child.on('error', (err) => {
      this.killChild();
      if (err.code === 'ENOENT') {
        this.emit('error', 'NMAP not found at command location: ' + nmap.nmapLocation)
      } else {
        this.emit('error', err.Error)
      }
    })

    this.child.stderr.on("data", (err) => {
      this.error = err.toString();
    });

    this.child.on("close", () => {
      process.removeListener('SIGINT', this.killChild);
      process.removeListener('uncaughtException', this.killChild);
      process.removeListener('exit', this.killChild);

      if (this.error) {
        this.stopTimer();
        this.emit('error', this.error);
      } else if (this.cancelled === true) {
        this.stopTimer();
        this.emit('error', "Over scan timeout " + this.scanTimeout);
      } else {
        this.rawDataHandler(this.rawData);
      }
    });
  }

  startScan() {
    this.child.stdin.end();
  }

  cancelScan() {
    this.killChild();
    this.emit('error', "Scan cancelled");
  }

  scanComplete(results) {
    this.scanResults = results;
    this.stopTimer();
    this.emit('complete', this.scanResults);
  }

  rawDataHandler(data) {
    let results;
    //turn NMAP's xml output into a json object
    xml2js.parseString(data, (err, result) => {
      if (err) {
        this.stopTimer();
        this.emit('error', "Error converting XML to JSON in xml2js: " + err);
      } else {
        this.rawJSON = result;
        results = convertRawJsonToScanResults(this.rawJSON, (err) => {
          this.emit('error', "Error converting raw json to cleans can results: " + err + ": " + this.rawJSON);
        });
        this.scanComplete(results);
      }
    });
  }
}


class QuickScan extends NmapScan {
  constructor(range) {
    super(range, '-sP');
  }
}
class OsAndPortScan extends NmapScan {
  constructor(range) {
    super(range, '-O');
  }
}


class QueuedScan extends EventEmitter {

  constructor(scanClass, range, args, action = () => {}) {
    super();
    this.scanResults = [];
    this.scanTime = 0;
    this.currentScan;
    this.runActionOnError = false;
    this.saveErrorsToResults = false;
    this.singleScanTimeout = 0;
    this.saveNotFoundToResults = false;

    this._queue = new Queue((host) => {

      if (args !== null) {
        this.currentScan = new scanClass(host, args);
      } else {
        this.currentScan = new scanClass(host);
      }
      if (this.singleScanTimeout !== 0) {
        this.currentScan.scanTimeout = this.singleScanTimeout;
      }

      this.currentScan.on('complete', (data) => {
        this.scanTime += this.currentScan.scanTime;
        if (data[0]) {
          data[0].scanTime = this.currentScan.scanTime;
          this.scanResults = this.scanResults.concat(data);
        } else if (this.saveNotFoundToResults) {
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

        let data = {
          error: err,
          scanTime: this.currentScan.scanTime
        }


        if (this.saveErrorsToResults) {
          this.scanResults = this.scanResults.concat(data);
        }
        if (this.runActionOnError) {
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

  rangeFormatter(range) {
    let outputRange = [];
    if (!Array.isArray(range)) {
      range = range.split(' ');
    }

    for (let i = 0; i < range.length; i++) {
      let input = range[i];
      let temprange = range[i];
      if (countCharacterOccurence(input, ".") === 3 &&
        input.match(new RegExp("-", "g")) !== null &&
        !input.match(/^[a-zA-Z]+$/) &&
        input.match(new RegExp("-", "g")).length === 1
      ) {
        let firstIP = input.slice(0, input.indexOf("-"));
        let network;
        let lastNumber = input.slice(input.indexOf("-") + 1);
        let firstNumber;
        let newRange = [];
        for (let j = firstIP.length - 1; j > -1; j--) {
          if (firstIP.charAt(j) === ".") {
            firstNumber = firstIP.slice(j + 1);
            network = firstIP.slice(0, j + 1);
            break;
          }
        }
        for (let iter = firstNumber; iter <= lastNumber; iter++) {
          newRange.push(network + iter);
        }
        //replace the range/host string with array
        temprange = newRange;
      }
      outputRange = outputRange.concat(temprange);
    }

    function countCharacterOccurence(input, character) {
      let num = 0;
      for (let k = 0; k < input.length; k++) {
        if (input.charAt(k) === character) {
          num++;
        }
      }
      return num;
    }
    return outputRange;
  }

  startRunScan(index = 0) {
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

  next(iterations = 1) {
    return this._queue.next(iterations);
  }

  shift(iterations = 1) {
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

  queue(newQueue) {

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

class QueuedNmapScan extends QueuedScan {
  constructor(range, additionalArguments, actionFunction = () => {}) {
    super(NmapScan, range, additionalArguments, actionFunction);
  }
}

class QueuedQuickScan extends QueuedScan {
  constructor(range, actionFunction = () => {}) {
    super(QuickScan, range, null, actionFunction);
  }
}

class QueuedOsAndPortScan extends QueuedScan {
  constructor(range, actionFunction = () => {}) {
    super(OsAndPortScan, range, null, actionFunction);
  }
}

let nmap = {
  nmapLocation: "nmap",
  NmapScan,
  QuickScan,
  OsAndPortScan,
  QueuedScan,
  QueuedNmapScan,
  QueuedQuickScan,
  QueuedOsAndPortScan
}

module.exports = nmap;
