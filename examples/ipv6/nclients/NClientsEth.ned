//
// Copyright (C) 2004 OpenSim Ltd.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//


package inet.examples.ipv6.nclients;

import inet.networklayer.configurator.ipv6.Ipv6FlatNetworkConfigurator;
import inet.node.ipv6.Router6;
import inet.node.ipv6.StandardHost6;
import ned.DatarateChannel;


network NClientsEth
{
    parameters:
        int n;
    types:
        channel fiberline extends DatarateChannel
        {
            delay = 1us;
            datarate = 512Mbps;
        }
        channel ethernetline extends DatarateChannel
        {
            delay = 0.1us;
            datarate = 10Mbps;
        }
    submodules:
        configurator: Ipv6FlatNetworkConfigurator {
            @display("p=100,100;is=s");
        }
        r1: Router6 {
            @display("p=400,100");
        }
        r2: Router6 {
            @display("p=550,100");
        }
        r3: Router6 {
            @display("p=700,100");
        }
        cli[n]: StandardHost6 {
            @display("p=250,100");
        }
        srv: StandardHost6 {
            @display("p=850,100");
        }
    connections:
        for i=0..n-1 {
            cli[i].ethg++ <--> ethernetline <--> r1.ethg++;
        }
        r1.ethg++ <--> ethernetline <--> r2.ethg++;
        r2.ethg++ <--> ethernetline <--> r3.ethg++;
        r3.ethg++ <--> ethernetline <--> srv.ethg++;

        //XXX
        // Mixing ethernet and ppp currently doesn't work, due to a bug in
        // Ipv6FlatNetworkConfigurator::determineGateIndex.
        //
        // r1.pppg++ <--> fiberline <--> r2.pppg++;
        // r2.pppg++ <--> fiberline <--> r3.pppg++;
        // r3.pppg++ <--> fiberline <--> srv.pppg++;
        //
}

