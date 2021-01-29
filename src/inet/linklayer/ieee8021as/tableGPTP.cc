//
// @authors: Enkhtuvshin Janchivnyambuu
//           Henning Puttnies
//           Peter Danielis
//           University of Rostock, Germany
// 

#include "tableGPTP.h"

#include "EtherGPTP.h"

namespace inet {

Define_Module(TableGPTP);

void TableGPTP::initialize()
{
    correctionField = par("correctionField");
    rateRatio = par("rateRatio");
    peerDelay = 0;
    receivedTimeSync = 0;
    receivedTimeFollowUp = 0;
}

void TableGPTP::handleGptpCall(cMessage *msg)
{
    Enter_Method("handleGptpCall");

    take (msg);
    //TODO tags?
    for (auto gptp : gptps) {
        gptp.second->handleTableGptpCall(msg->dup());
    }
    delete msg;
}

void TableGPTP::setCorrectionField(clocktime_t cf)
{
    correctionField = cf;
}

clocktime_t TableGPTP::getCorrectionField()
{
    return correctionField;
}

void TableGPTP::setRateRatio(clocktime_t cf)
{
    rateRatio = cf;
}

clocktime_t TableGPTP::getRateRatio()
{
    return rateRatio;
}

void TableGPTP::setPeerDelay(clocktime_t cf)
{
    peerDelay = cf;
}

clocktime_t TableGPTP::getPeerDelay()
{
    return peerDelay;
}

void TableGPTP::setReceivedTimeSync(clocktime_t cf)
{
    receivedTimeSync = cf;
}

clocktime_t TableGPTP::getReceivedTimeSync()
{
    return receivedTimeSync;
}

void TableGPTP::setReceivedTimeFollowUp(clocktime_t cf)
{
    receivedTimeFollowUp = cf;
}

clocktime_t TableGPTP::getReceivedTimeFollowUp()
{
    return receivedTimeFollowUp;
}

void TableGPTP::setReceivedTimeAtHandleMessage(clocktime_t cf)
{
    receivedTimeAtHandleMessage = cf;
}

clocktime_t TableGPTP::getReceivedTimeAtHandleMessage()
{
    return receivedTimeAtHandleMessage;
}

void TableGPTP::setOriginTimestamp(clocktime_t cf)
{
    originTimestamp = cf;
}

clocktime_t TableGPTP::getOriginTimestamp()
{
    return originTimestamp;
}

void TableGPTP::addGptp(EtherGPTP *gptp)
{
    gptps.insert(std::pair<int, EtherGPTP*>(gptp->getId(), gptp));
}

void TableGPTP::removeGptp(EtherGPTP *gptp)
{
    gptps.erase(gptp->getId());
}

}
