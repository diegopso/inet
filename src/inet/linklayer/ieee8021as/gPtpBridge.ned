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
        eth[*].typename = "EthernetInterfaceGPTP";
        tableGPTP.typename = "TableGPTP";
        clock.typename = default("SettableClock");
        // 11 - Grandmaster, 12 - Bridge, 13 - Slave
        tableGPTP.gPtpNodeType = 12;
}

