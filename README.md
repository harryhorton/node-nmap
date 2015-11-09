[![Stories in Ready](https://badge.waffle.io/Johnhhorton/node-nmap.png?label=ready&title=Ready)](https://waffle.io/Johnhhorton/node-nmap)
# Node-NMAP
NPM package enabling your [NodeJs] application to interface with the features of [NMAP].  This package requires that [NMAP] is installed and available to the running node application.

Warning:  Occasionally NMAP will freeze when the application is stopped before a complete scan. \[fix implemented\]

Request:  While runNmap() will accept valid NMAP arguments, the XML to JSON conversion is only checking for specific things.  If there is a common or useful NMAP feature that you would like to see included, please submit an issue and I will work it in.

## Installation
`npm install node-nmap`

## Methods
* runNmap - This is the core of the package and runs the NMAP command.
* quickScan - Scans supplied hosts without portscan(-sn).  Use for a quick discovery.
* osAndPortScan - Scans for open ports as well as NMAP gathered OS information.
* autoDiscover  - scans as a /24 network range for the local network.  \[only /24 currently, and only finds first interface\]

## Usage

runNmap is the core function of the package, which accepts a command, success callback, and failure callback.
All other commands accept onSuccess and onFailure functions as the last 2 parameters passing either the data, or error.

```javascript
var nmap = require('node-nmap');

//    Accepts array or comma separated string of NMAP acceptable hosts
var quickscan = nmap.quickScan('127.0.0.1 google.com');

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


//    Accepts array or comma separarted string for custom nmap commands
var nmapscan = nmap.NmapScan('-sn 127.0.0.1 google.com');

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
var osandports = nmap.osAndPortScan('google.com');

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
var discover = nmap.autoDiscover();

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
