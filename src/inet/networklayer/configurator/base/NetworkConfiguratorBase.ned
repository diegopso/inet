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

package inet.networklayer.configurator.base;

import inet.networklayer.configurator.contract.INetworkConfigurator;

simple NetworkConfiguratorBase like INetworkConfigurator
{
    parameters:
        double minLinkWeight = default(1E-3);
        bool configureIsolatedNetworksSeparatly = default(false);
}

