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
    submodules:
        tableGPTP: TableGPTP {
            // 11 - Grandmaster, 12 - Bridge, 13 - Slave
            gPtpNodeType = 12;
            @display("p=100,700");
        }
        clockGPTP: Clock {
            @display("p=100,800");
        }
}

