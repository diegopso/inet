//
// @authors: Enkhtuvshin Janchivnyambuu
//           Henning Puttnies
//           Peter Danielis
//           University of Rostock, Germany
// 

package inet.linklayer.ieee8021as;

import inet.protocolelement.measurement.IMeasurementLayer;


//
// This module is a part of EthernetInterfaceGPTP compound module and is placed between MAC and Encap/Queue
// Time-aware switch shall have EthernetInterfaceGPTP module instead of standard WiredNIC 
//
simple EtherGPtp like IMeasurementLayer     // KLUDGE: the IMeasurementLayer is a kludge
{
    parameters:
        string portType = default("PASSIVE_PORT");  //  @enum("GPtpPortType"): MASTER_PORT, SLAVE_PORT, PASSIVE_PORT
        double syncInterval @unit(s) = default(0.125s);
        double pdelayInterval @unit(s) = default(1s);
        bool withFcs = default(true);    // add FCS for lower layer outgoing packets
    gates:
        input upperLayerIn; // @labels(EtherFrame);		// Connect to Queue if Queue exists or Encap if Queue doesn't
        output upperLayerOut; // @labels(EtherFrame); 	// Connect to Encap
        input lowerLayerIn; //@labels(EtherFrame);		// Connect to Mac output
        output lowerLayerOut; //@labels(EtherFrame);	// Connect to Mac input
}
