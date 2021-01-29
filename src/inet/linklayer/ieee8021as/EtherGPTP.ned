//
// @authors: Enkhtuvshin Janchivnyambuu
//           Henning Puttnies
//           Peter Danielis
//           University of Rostock, Germany
// 

package inet.linklayer.ieee8021as;

//
// This module is a part of EthernetInterfaceGPTP compound module and is placed between MAC and Encap/Queue
// Time-aware switch shall have EthernetInterfaceGPTP module instead of standard WiredNIC 
//
simple EtherGPTP
{
    parameters:
        // 0-Passive port by default. 2-Master port, 1-Slave port, 0-Passive port
        int portType = default(0);

        double syncInterval @unit(s) = default(0.125s);
        double pdelayInterval @unit(s) = default(1s);
    gates:
        input upperLayerIn; // @labels(EtherFrame);		// Connect to Queue if Queue exists or Encap if Queue doesn't
        output upperLayerOut; // @labels(EtherFrame); 	// Connect to Encap
        input lowerLayerIn; //@labels(EtherFrame);		// Connect to Mac output
        output lowerLayerOut; //@labels(EtherFrame);	// Connect to Mac input
}
