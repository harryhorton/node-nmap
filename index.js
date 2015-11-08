
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
    xml2js = require('xml2js');

var nmapLocation = "nmap.exe";

/*
*   @desc: converts NMAP XML output to an array of JSON Host objects.
*   @param:  string-XML: input - NMAP XML Output.
*   @return: Array of Host Objects;
*
*/
function convertXMLtoJSON(xmlInput) {
    var tempHostList = [];
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
        //Check if the hostname is avaialble.  \r\n is what will return if not available.
        if (xmlInput[hostLoopIter]['hostnames'][0] !== "\r\n") {
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
                    tempHostList[hostLoopIter].openPorts[portLoopIter].port = xmlInput[hostLoopIter]["ports"][0]["port"][portLoopIter]['$']['portid'];
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
    return tempHostList
}


/*
*   @desc:  runs nmap command to get a list of hosts.  Note that this reruns the
*           NMAP command.
*   @param:  string: range - NMAP compatible IP range,
*            function:  callback
*   @return: Array: List of JSON hosts
*/
function discoverHosts(range, callback) {
    var standardArgs = ['-sn', "--system-dns"];
    var command;
    if (Array.isArray(range)) {
        command = standardArgs.concat(range);
    } else {
        command = standardArgs.concat(range.split(' '));
    }

    runNMAP(command, callback);

};

function scanWithPortAndOS(range, callback) {
    //--osscan-guess or -O
    var standardArgs = ["-O"];
    var command;
    if (Array.isArray(range)) {
        command = standardArgs.concat(range);
    } else {
        command = standardArgs.concat(range.split(' '));
    }

    runNMAP(command, callback);

}

/*
*   @desc:  Runs NMAP command and passes data to callback.
*   @expects:  nmapLocation - to equal an nmap executable
*   @param:  array: command - example
*             ['-oX', '-', '-sn',"--system-dns","192.168.1.1-254"]
*   @returns:  Array of Json Hosts to callback
*/
function runNMAP(inputCommand, callback) {
    var standardArguments = ['-oX', '-'];
    var command = [];
    var nmapoutputXML = '';
    var nmapOutputJSON;
    var cleanOutputJSON;
    
    if (!Array.isArray(inputCommand)) {
        inputCommand = inputCommand.split(' ');
    }
    command = command.concat(standardArguments);
    command = command.concat(inputCommand);
    var child = spawn(nmapLocation, command);
    
    child.stdout.on("data", function (data) {
        nmapoutputXML += data;
    });

    child.stderr.on("data", function (err) {

    });

    child.on("close", NMAPRequestDoneHandler);

    //Handler for data once connection is closed.
    function NMAPRequestDoneHandler(code) {
        

        //turn NMAP's xml output into a json object
        xml2js.parseString(nmapoutputXML, function (err, result) {
            if (err) {

            }
            nmapOutputJSON = result;
        });
        //hostsCleaup removes the unwanted variables from the json data
        cleanOutputJSON = convertXMLtoJSON(nmapOutputJSON);
        callback(cleanOutputJSON);
    }

    child.stdin.end();
}


module.exports = function () {
    return {
        NmapLocation: nmapLocation,
        runNMAP: runNMAP,
        setNmapLocation: function (location) {
            nmapLocation = location;
            return nmapLocation;
        },
        osDetectionAndPortScan: scanWithPortAndOS,
        discoverHosts: discoverHosts

    };
} ();
