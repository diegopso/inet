//
// Copyright (C) 2013 OpenSim Ltd.
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

#ifndef __INET_FLATRECEPTIONBASE_H
#define __INET_FLATRECEPTIONBASE_H

#include "inet/physicallayer/wireless/common/base/packetlevel/NarrowbandReceptionBase.h"

namespace inet {

namespace physicallayer {

class INET_API FlatReceptionBase : public NarrowbandReceptionBase
{
  public:
    FlatReceptionBase(const IRadio *receiver, const ITransmission *transmission, const simtime_t startTime, const simtime_t endTime, const Coord& startPosition, const Coord& endPosition, const Quaternion& startOrientation, const Quaternion& endOrientation, Hz centerFrequency, Hz bandwidth);

    virtual W computeMinPower(simtime_t startTime, simtime_t endTime) const = 0;
};

} // namespace physicallayer

} // namespace inet

#endif

