
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
    xml2js = require('xml2js'),
    events = require('events'),
    os = require('os');

var nmapLocation = "nmap";

/*
*   @desc: converts NMAP XML output to an array of JSON Host objects.
*   @param:  string-XML: input - NMAP XML Output.
*   @return: Array of Host Objects;
*
*/
function convertXMLtoJSON(xmlInput, onFailure) {
    var tempHostList = [];
    if (!xmlInput['nmaprun']['host']) {
        onFailure("There was a problem with the supplied NMAP XML");
        return tempHostList;
    };
    try{
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
    }catch(e){
        onFailure(e);
    }finally{
    return tempHostList;
    }
}


/*
*   @desc:  runs nmap command to get a list of hosts.  Note that this reruns the
*           NMAP command.
*   @param:  string: range - NMAP compatible IP range,
*            function:  callback
*   @return: Array: List of JSON hosts
*/
var quickScan = function(range) {
    var standardArgs = ['-sn', "--system-dns"];
    var command;
    if (Array.isArray(range)) {
        command = standardArgs.concat(range);
    } else {
        command = standardArgs.concat(range.split(' '));
    }
 return NmapScan(command)
};

var scanWithPortAndOS = function(range) {
    //--osscan-guess or -O
    var standardArgs = ["-O"];
    var command;
    if (Array.isArray(range)) {
        command = standardArgs.concat(range);
    } else {
        command = standardArgs.concat(range.split(' '));
    }

    return NmapScan(command);
}

/*
*   @desc:  Runs NMAP command and passes data to callback.
*   @expects:  nmapLocation - to equal an nmap executable
*   @param:  array: command - example
*             ['-oX', '-', '-sn',"--system-dns","192.168.1.1-254"]
*   @returns:  Array of Json Hosts to callback
*/
var NmapScan = function (inputCommand) {
	var standardArguments = ['-oX', '-'];
	var command = [];
	var nmapoutputXML = '';
	if (!Array.isArray(inputCommand)) {
		inputCommand = inputCommand.split(' ');
	}
	command = command.concat(standardArguments);
	command = command.concat(inputCommand);

	function NmapScan() {
		var self = this;

		self.percentComplete = 0;
		self.response = [];
		self.command = command;
		self.startScan = function () {

			var error = null;
			var child = spawn(nmapLocation, command);
			
			process.on('SIGINT', function () {
				child.kill();
			});
			process.on('uncaughtException', function (err) {
				child.kill();
			});
			process.on('exit', function () {
				child.kill();
			});
			
			child.stdout.on("data", function (data) {
                if(data.indexOf("percent") > -1){
                    console.log(data.toString());
                }else{
                    nmapoutputXML += data;
                    
                }
                
				
			});

			child.stderr.on("data", function (err) {
				error = err.toString();
			});

			child.on("close", function () {
				if (error) {
					self.emit('error', error);
				} else {

					NMAPRequestDoneHandler(nmapoutputXML);
				}
			});
			
			child.stdin.end();
 
			//Handler for data once connection is closed.
			function NMAPRequestDoneHandler(XML) {
        
				var nmapOutputJSON;
				//turn NMAP's xml output into a json object
				xml2js.parseString(XML, function (err, result) {
					if (err) {
						self.emit('error', err);
					}
					nmapOutputJSON = result;
                    
				});
				//hostsCleaup removes the unwanted variables from the json data
                
				self.response = convertXMLtoJSON(nmapOutputJSON, function(err){
					self.emit('error', err);
				});
                
				self.emit('complete', self.response);
			}
		};
	}
	NmapScan.prototype = new events.EventEmitter;

	return new NmapScan;
};

var autoDiscover = function() {
    var interfaces = os.networkInterfaces();
    var addresses = [];
    for (var k in interfaces) {
        for (var k2 in interfaces[k]) {
            var address = interfaces[k][k2];
            if (address.family === 'IPv4' && !address.internal) {
                addresses.push(address.address);
            }
        }
    }
    var ip = addresses[0];
    var octets = ip.split('.');
    octets.pop();
    octets = octets.concat('1-254');
    var range = octets.join('.');
    return quickScan(range);
    
}


module.exports = function () {
    return {
        NmapScan: NmapScan,
        setNmapLocation: function (location) {
            nmapLocation = location;
            return nmapLocation;
        },
        osAndPortScan: scanWithPortAndOS,
        quickScan: quickScan,
        autoDiscover:autoDiscover

    };
} ();
