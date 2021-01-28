//
// @authors: Enkhtuvshin Janchivnyambuu
//           Henning Puttnies
//           Peter Danielis
//           University of Rostock, Germany
// 

package inet.linklayer.ieee8021as;

import inet.linklayer.contract.IClockGPTP;


simple Clock like IClockGPTP
{
    string clockType = default("ConstantDrift");
    int clockDrift = default(0);
}
