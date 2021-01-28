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
        int gPtpNodeType;
        double correctionField = default(0);
        double rateRatio = default(1);
        double syncReceivedTime = default(0);
}
