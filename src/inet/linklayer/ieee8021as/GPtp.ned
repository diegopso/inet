//
// @authors: Enkhtuvshin Janchivnyambuu
//           Henning Puttnies
//           Peter Danielis
//           University of Rostock, Germany
// 

package inet.linklayer.ieee8021as;

import inet.applications.contract.IApp;


//
// ieee 802.1as gPTP
//
simple TableGPtp like IApp
{
    parameters:
        string clockModule = default(""); // relative path of a module that implements IClock; optional
        string interfaceTableModule;
        string gPtpNodeType; // @enum("GPtpNodeType"): MASTER_NODE, BRIDGE_NODE, SLAVE_NODE
        string slavePort = default(""); // port for receiving time (empty for MASTER_NODE)
        object masterPorts = default({}); // ports for sending out time (empty for SLAVE_NODE)
        double correctionField @unit(s) = default(0s);
        double rateRatio = default(1);  // initial rate ratio
    gates:
        input socketIn;
        output socketOut;
}

