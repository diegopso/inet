//
// @authors: Enkhtuvshin Janchivnyambuu
//           Henning Puttnies
//           Peter Danielis
//           University of Rostock, Germany
// 

package inet.linklayer.ieee8021as;

import inet.node.inet.StandardHost;


module GPtpEndstation extends StandardHost
{
    parameters:
        eth[*].typename = "EthernetInterfaceGPTP";
        tableGPTP.typename = "TableGPTP";
        clockGPTP.typename = "Clock";
}

