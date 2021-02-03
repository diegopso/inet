//
// @authors: Enkhtuvshin Janchivnyambuu
//           Henning Puttnies
//           Peter Danielis
//           University of Rostock, Germany
// 

package inet.linklayer.ieee8021as;

import inet.linklayer.contract.ITableGPTP;


//
// this will be used to store a value of correctionField and rateRatio
//
simple TableGPTP like ITableGPTP
{
    parameters:
        string gPtpNodeType; // @enum("GPtpNodeType"): MASTER_NODE, BRIDGE_NODE, SLAVE_NODE
        double correctionField @unit(s) = default(0s);
        double rateRatio @unit(s) = default(1s);
        double syncReceivedTime @unit(s) = default(0s);
}
