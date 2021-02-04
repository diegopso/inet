//
// @authors: Enkhtuvshin Janchivnyambuu
//           Henning Puttnies
//           Peter Danielis
//           University of Rostock, Germany
// 

#include "TableGPtp.h"

#include "EtherGPtp.h"

namespace inet {

Define_Module(TableGPtp);

void TableGPtp::initialize()
{
    correctionField = par("correctionField");
    rateRatio = par("rateRatio");
    peerDelay = 0;
    receivedTimeSync = 0;
    receivedTimeFollowUp = 0;
}

void TableGPtp::handleGptpCall(cMessage *msg)
{
    Enter_Method("handleGptpCall");

    take (msg);
    //TODO tags?
    for (auto gptp : gptps) {
        gptp.second->handleTableGptpCall(msg->dup());
    }
    delete msg;
}

void TableGPtp::setCorrectionField(clocktime_t cf)
{
    correctionField = cf;
}

clocktime_t TableGPtp::getCorrectionField()
{
    return correctionField;
}

void TableGPtp::setRateRatio(clocktime_t cf)
{
    rateRatio = cf;
}

clocktime_t TableGPtp::getRateRatio()
{
    return rateRatio;
}

void TableGPtp::setPeerDelay(clocktime_t cf)
{
    peerDelay = cf;
}

clocktime_t TableGPtp::getPeerDelay()
{
    return peerDelay;
}

void TableGPtp::setReceivedTimeSync(clocktime_t cf)
{
    receivedTimeSync = cf;
}

clocktime_t TableGPtp::getReceivedTimeSync()
{
    return receivedTimeSync;
}

void TableGPtp::setReceivedTimeFollowUp(clocktime_t cf)
{
    receivedTimeFollowUp = cf;
}

clocktime_t TableGPtp::getReceivedTimeFollowUp()
{
    return receivedTimeFollowUp;
}

void TableGPtp::setReceivedTimeAtHandleMessage(clocktime_t cf)
{
    receivedTimeAtHandleMessage = cf;
}

clocktime_t TableGPtp::getReceivedTimeAtHandleMessage()
{
    return receivedTimeAtHandleMessage;
}

void TableGPtp::setOriginTimestamp(clocktime_t cf)
{
    originTimestamp = cf;
}

clocktime_t TableGPtp::getOriginTimestamp()
{
    return originTimestamp;
}

void TableGPtp::addGptp(EtherGPtp *gptp)
{
    gptps.insert(std::pair<int, EtherGPtp*>(gptp->getId(), gptp));
}

void TableGPtp::removeGptp(EtherGPtp *gptp)
{
    gptps.erase(gptp->getId());
}

}
