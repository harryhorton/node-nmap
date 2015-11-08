# Node-NMAP
NPM package enabling your [NodeJs] application to interface with the features of [NMAP].  This package requires that [NMAP] is installed and available to the running node application.

## Installation
`npm install node-nmap`

## Methods
* runNmap - This is the core of the package and runs the NMAP command.
* discoverHosts - Scans supplied hosts without portscan(-sn).  Use for a quick discovery


## Usage
```javascript
var nmap = require('node-nmap');

/*
*    Accepts array or comma separated string of NMAP acceptable hosts
*/
nmap.discoverHosts('127.0.0.1 google.com', function(returnData){
  console.dir('returnData');
});

/*
*    Accepts array or comma separarted string for custom nmap commands
*/
nmap.runNmap('-sn 127.0.0.1 google.com', function(returnData){
  console.dir('returnData');
});

```

[NMAP]: <https://nmap.org/>
[NPM]: <https://www.npmjs.com/>
[NodeJs]: <https://nodejs.org/en/>
