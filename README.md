[![Stories in Ready](https://badge.waffle.io/Johnhhorton/node-nmap.png?label=ready&title=Ready)](https://waffle.io/Johnhhorton/node-nmap)
# Node-NMAP
NPM package enabling your [NodeJs] application to interface with the features of [NMAP].  This package requires that [NMAP] is installed and available to the running node application.

UPDATE: I have rewritten the module in TypeScript.  the .d.ts file is located at /node_modules/node-nmap/index.d.ts.
As a part of this update, there is an additional maping for the namespace/module, as well as a requirement to use `new` for each scan.

Request:  While NmapScan() will accept valid NMAP arguments, the XML to JSON conversion is only checking for specific things.  If there is a common or useful NMAP feature that you would like to see included, please submit an issue and I will work it in.

## Installation
`npm install node-nmap`

## Methods
* NmapScan - This is the core of the package and runs the NMAP command.
* quickScan - Scans supplied hosts without portscan(-sn).  Use for a quick discovery.
* osAndPortScan - Scans for open ports as well as NMAP gathered OS information.
* autoDiscover  - scans as a /24 network range for the local network.  \[only /24 currently, and only finds first interface\]

## Usage

NmapScan is the core function of the package.  It emits two events: `'complete'` and `'error'`.  Both of these events return data.  All methods are easy to set up.  Simply define a variable as one of the methods, and that variable will become a new instance of NmapScan with appropriately set commands. All input accepts either a space separated string, or an array of strings to make it easier to work with a complex set of hosts.  All methods return an array of JSON objects containing information on each host.  Any key without information provided from NMAP is filled as `null`.

The return structure is:

```javascript
[  
    {  
       "hostname":"theHostname",
       "ip":"127.0.0.1",
       "mac":null,
       "openPorts":[  
          {  
             "port":80,
             "service":"http"
          },...  
        ],
       "osNmap":null //note that osNmap is not guaranteed to be correct.
    },...]
```
### Examples

```javascript
var nmap = require('node-nmap');

nmap.nodenmap.nmapLocation = "nmap"; //default

//    Accepts array or comma separated string of NMAP acceptable hosts
var quickscan = new nmap.nodenmap.quickScan('127.0.0.1 google.com');

quickscan.on('complete', function(data){
  console.log(data);
});

quickscan.on('error', function(error){
  console.log(error);
});

quickscan.startScan();
// returns
// [  
//    {  
//       "hostname":"localhost",
//       "ip":"127.0.0.1",
//       "mac":null,
//       "openPorts":[  

//       ],
//       "osNmap":null
//    },
//    {  
//       "hostname":"google.com",
//       "ip":"74.125.21.113",
//       "mac":null,
//       "openPorts":[  

//       ],
//       "osNmap":null
//    }
// ]


//    Accepts array or comma separarted string for custom nmap commands in the second argument.
var nmapscan = new nmap.nodenmap.NmapScan('127.0.0.1 google.com', '-sn');

nmapscan.on('complete',function(data){
  console.log(data);
});
nmapscan.on('error', function(error){
  console.log(error);
});

nmapscan.startScan();

// returns
// [  
//    {  
//       "hostname":"localhost",
//       "ip":"127.0.0.1",
//       "mac":null,
//       "openPorts":[  

//       ],
//       "osNmap":null
//    },
//    {  
//       "hostname":"google.com",
//       "ip":"74.125.21.113",
//       "mac":null,
//       "openPorts":[  

//       ],
//       "osNmap":null
//    }
// ]
var osandports = new nmap.nodenmap.osAndPortScan('google.com');

osandports.on('complete',function(data){
  console.log(data);
});
osandports.on('error', function(error){
  console.log(error);
});

osandports.startScan();

// returns
// [
//    {  
//       "hostname":"google.com",
//       "ip":"74.125.21.113",
//       "mac":null,
//       "openPorts":[  
//          {  
//             "port":80,
//             "service":"http"
//          },
//          {  
//             "port":443,
//             "service":"https"
//          }
//       ],
//       "osNmap":"OpenBSD 4.3"
//    }
// ]
var discover = new nmap.nodenmap.autoDiscover();

discover.on('complete',function(data){
  console.log(data);
});
discover.on('error', function(error){
  console.log(error);
});

discover.startScan();

```

[NMAP]: <https://nmap.org/>
[NPM]: <https://www.npmjs.com/>
[NodeJs]: <https://nodejs.org/en/>
