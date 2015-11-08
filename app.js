var nmap = require('./index');

/*
*    Accepts array or comma separated string of NMAP acceptable hosts
*/
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
/*
*    Accepts array or comma separarted string for custom nmap commands
*/
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