
/*
 * NodeJS <-> NMAP interface
 * Author:  John Horton
 * Purpose: Create an interface for NodeJS applications to make use of NMAP installed on the local system.
 */

var child_process = require('child_process'),
    execSync = require('child_process').execSync,
    exec = require('child_process').exec,
    fs = require('fs'),
    spawn = require("child_process").spawn,
    colors = require('colors/safe'),
    xml2js = require('xml2js');

//directories
var nmapLocation = ".\\3rdparty\\nmap\\nmap.exe";
//var nmapLocation = "nmap.exe";

function log(type, text, data) {
    if (type === 'info') {
        console.log(colors.green(text + ' ' + data));
    } else if (type === 'data') {
        console.log(colors.grey(text + ' ' + data));
    } else if (type === 'debug') {
        console.log(colors.grey(text + ' ' + data));
    } else if (type === 'error') {
        console.log(colors.grey(text + ' ' + data));
    }
}


/*
*   @desc: converts NMAP XML output to an array of JSON Host objects.
*   @param:  string-XML: input - NMAP XML Output.
*   @return: Array of Host Objects;
*
*/
function hostsXmlToJson(input) {
  log('data', input);
    log('info', 'nmap.js:  hostsCleaup() called: input: ', input);
    var raw = input,
        tempHost = [];

    //Removes everything but the host array.
    raw = raw['nmaprun']['host'];

    //Create a new object for each host found
    for (var i = 0; i < raw.length; i++) {

        //create the temphost object for each host.
        tempHost[i] = {
            hostname: null,
            ip: null,
            mac: null,
            openPorts: []
        };
        //Check if the hostname is avaialble.  \r\n is what will return if non available.
        if (raw[i]['hostnames'][0] !== "\r\n") {
            tempHost[i].hostname = raw[i]['hostnames'][0]['hostname'][0]['$']['name'];
        }
        //For each network address type found
        for (var j = 0; j < raw[i]["address"].length; j++) {

            //If IPv4, Mac, or unknown.  Get the type and add it or log the type found.
            if (raw[i]["address"][j]["$"]["addrtype"] === 'ipv4') {
                tempHost[i].ip = raw[i]["address"][j]["$"]["addr"];
            } else if (raw[i]["address"][j]["$"]["addrtype"] === 'mac') {
                tempHost[i].mac = raw[i]["address"][j]["$"]["addr"];
            } else {
                //If this error shows.  Add the address type found
                log('error',"addresstype unknown." + raw[i]["address"][j]["$"]["addrtype"]);
            }
        }
        //check if port list is available
        if (raw[i]["ports"] && raw[i]["ports"][0]["port"]) {

           //for each port scanned
           for (var k = 0; k < raw[i]["ports"][0]["port"].length; k++) {

               //if the state of the port is open
               if (raw[i]["ports"][0]["port"][k]['state'][0]['$']['state'] === 'open') {
                   tempHost[i].openPorts[k] = {};
                   //Get the port number
                   tempHost[i].openPorts[k].port = raw[i]["ports"][0]["port"][k]['$']['portid'];
                   //Get the port name
                   tempHost[i].openPorts[k].service = raw[i]["ports"][0]["port"][k]['service'][0]['$']['name'];
               }
           }
        }
        if(raw[i].os && raw[i].os[0].osmatch && raw[i].os[0].osmatch[0].$.name){
          tempHost[i].osNmap = raw[i].os[0].osmatch[0].$.name
        }else{
          tempHost[i].osNmap = null;
        }

    };
    return tempHost
}


/*
*   @desc:  runs nmap command to get a list of hosts.  Note that this reruns the
*           NMAP command.
*   @param:  string: range - NMAP compatible IP range,
*            function:  callback
*   @return: Array: List of JSON hosts
*/
function getHosts(range, callback) {
    var standardArgs = ['-oX', '-', '-sn',"--system-dns"];
    var command;
    if(Array.isArray(range)){
      command = standardArgs.concat(range);
    }else{
      command = standardArgs.concat(range.split(' '));
    }
    log('info', 'nmap.js: getHosts() called', command);
     nmap(command, callback);

};

function osDetectionAndPortScan(range, callback){
//--osscan-guess or -O
var standardArgs = ['-oX', '-',"--system-dns", "-O"];
var command;
if(Array.isArray(range)){
  command = standardArgs.concat(range);
}else{
  command = standardArgs.concat(range.split(' '));
}
log('info', 'nmap.js: osDetection() called', range);
 nmap(command, callback);

}

/*
*   @desc:  Runs NMAP command and passes data to callback.
*   @expects:  nmapLocation - to equal an nmap executable
*   @param:  array: command - example
*             ['-oX', '-', '-sn',"--system-dns","192.168.1.1-254"]
*   @returns:  Array of Json Hosts to callback
*/
function nmap(command, callback) {
    log('info', 'nmap.js: nmap() called: ', command);
    var nmapoutputXML ='';
    var nmapOutputJSON;
    var cleanOutputJSON;


    var child = spawn(nmapLocation, command);

    child.stdout.on("data", function (data) {
        nmapoutputXML += data;
    });

    child.stderr.on("data", function (err) {
        log('error',"nmap.js: nmap():child.stderr.on(data) returned error: " + err);
    });

    child.on("close", NMAPRequestDoneHandler);

    //Handler for data once connection is closed.
    function NMAPRequestDoneHandler(code) {
        log('info', 'nmap.js: nmap(): NMAPRequestDoneHandler() called', "");

        //turn NMAP's xml output into a json object
        xml2js.parseString(nmapoutputXML, function (err, result) {
            if (err) {
                log('error',"nmap.js: nmap(): NMAPRequestDoneHandler(): xml2js error:",err);
            }
            nmapOutputJSON = result;
        });
        //hostsCleaup removes the unwanted variables from the json data
        cleanOutputJSON = hostsXmlToJson(nmapOutputJSON);

        callback(cleanOutputJSON);
    }

    child.stdin.end();
}


module.exports = function () {
    return {
        getNmapLocation: nmapLocation,
        setNmapLocation: function (location) {
            nmapLocation = location;
            return nmapLocation;
        },
        osDetectionAndPortScan: osDetectionAndPortScan,
        getHosts: getHosts

    };
}();
