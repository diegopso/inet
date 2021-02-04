//
// @authors: Enkhtuvshin Janchivnyambuu
//           Henning Puttnies
//           Peter Danielis
//           University of Rostock, Germany
// 

package inet.linklayer.ieee8021as;

import inet.node.ethernet.EthernetSwitch;


module GPtpBridge extends EthernetSwitch
{
    parameters:
        eth[*].typename = "EthernetInterfaceGPtp";
        tableGPtp.typename = "TableGPtp";
        clock.typename = default("SettableClock");
        tableGPtp.gPtpNodeType = "BRIDGE_NODE"; // @enum("gPtpNodeType"): MASTER_NODE, BRIDGE_NODE, SLAVE_NODE
}

