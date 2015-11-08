# Node-NMAP
NPM package enabling your [NodeJs] application to interface with the features of [NMAP].  This package requires that [NMAP] is installed and available to the running node application.

Warning:  Occasionally NMAP will freeze when the application is stopped before a complete scan.

## Installation
`npm install node-nmap`

## Methods
* runNmap - This is the core of the package and runs the NMAP command.
* quickScan - Scans supplied hosts without portscan(-sn).  Use for a quick discovery.
* osAndPortScan - Scans for open ports as well as NMAP gathered OS information.

## Usage
```javascript
var nmap = require('node-nmap');


//    Accepts array or comma separated string of NMAP acceptable hosts
nmap.quickScan('127.0.0.1 google.com', function(returnData){
  console.log(JSON.stringify(returnData));
});
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
nmap.runNMAP('-sn 127.0.0.1 google.com', function(returnData){
  console.log(JSON.stringify(returnData));
});
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
nmap.osAndPortScan('google.com', function(returnData){
	console.log(JSON.stringify(returnData));
});

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
```

[NMAP]: <https://nmap.org/>
[NPM]: <https://www.npmjs.com/>
[NodeJs]: <https://nodejs.org/en/>
