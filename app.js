var nmap = require('./index');

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
