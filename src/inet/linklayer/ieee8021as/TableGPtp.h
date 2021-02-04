//
// @authors: Enkhtuvshin Janchivnyambuu
//           Henning Puttnies
//           Peter Danielis
//           University of Rostock, Germany
// 

#ifndef __IEEE8021AS_TABLEGPTP_H_
#define __IEEE8021AS_TABLEGPTP_H_

#include "inet/common/INETDefs.h"
#include "inet/clock/contract/ClockTime.h"
#include "inet/clock/common/ClockTime.h"

namespace inet {

class EtherGPtp;

class TableGPtp : public cSimpleModule
{
    clocktime_t correctionField;
    clocktime_t rateRatio;
    clocktime_t originTimestamp;
    clocktime_t peerDelay;

    // Below timestamps are not drifted and they are in simtime // TODO no! no! nooooo!
    clocktime_t receivedTimeSync;
    clocktime_t receivedTimeFollowUp;

    /* time to receive Sync message before synchronize local time with master */
    clocktime_t timeBeforeSync;

    // This is used to calculate residence time within time-aware system
    // Its value has the time receiving Sync message from master port of other system
    clocktime_t receivedTimeAtHandleMessage;

    // Adjusted time when Sync received
    // For constant drift, setTime = sentTime + delay
    clocktime_t setTime;

    // array of EtherGPTP modules in this node:
    std::map<int, EtherGPtp *> gptps;

  protected:
    virtual void initialize() override;

  public:
    void setCorrectionField(clocktime_t cf);
    void setRateRatio(clocktime_t cf);
    void setPeerDelay(clocktime_t cf);
    void setReceivedTimeSync(clocktime_t cf);
    void setReceivedTimeFollowUp(clocktime_t cf);
    void setReceivedTimeAtHandleMessage(clocktime_t cf);
    void setOriginTimestamp(clocktime_t cf);
    void addGptp(EtherGPtp *gptp);
    void removeGptp(EtherGPtp *gptp);
    void handleGptpCall(cMessage *msg);

    clocktime_t getCorrectionField();
    clocktime_t getRateRatio();
    clocktime_t getPeerDelay();
    clocktime_t getReceivedTimeSync();
    clocktime_t getReceivedTimeFollowUp();
    clocktime_t getReceivedTimeAtHandleMessage();
    clocktime_t getOriginTimestamp();
};

}

#endif
