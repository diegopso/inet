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
        // 11 - Grandmaster, 12 - Bridge, 13 - Slave
        int gPtpNodeType; // @enum("gPtpNodeType")
        double correctionField @unit(s) = default(0s);
        double rateRatio @unit(s) = default(1s);
        double syncReceivedTime @unit(s) = default(0s);
}
