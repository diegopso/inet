//
// @authors: Enkhtuvshin Janchivnyambuu
//           Henning Puttnies
//           Peter Danielis
//           University of Rostock, Germany
// 

#ifndef __IEEE8021AS_TABLEGPTP_H_
#define __IEEE8021AS_TABLEGPTP_H_

#include "inet/clock/contract/ClockTime.h"
#include "inet/clock/common/ClockTime.h"
#include "inet/clock/model/SettableClock.h"
#include "inet/common/INETDefs.h"
#include "inet/common/clock/ClockUserModuleBase.h"
#include "inet/common/packet/Packet.h"
#include "inet/networklayer/contract/IInterfaceTable.h"
#include "inet/linklayer/ieee8021as/GPtpPacket_m.h"

namespace inet {

class EtherGPtp;

class GPtp : public ClockUserModuleBase
{
    //parameters:
    IInterfaceTable *interfaceTable = nullptr;
    opp_component_ptr<SettableClock> clockGptp;

    GPtpNodeType gPtpNodeType;
    int slavePortId = -1; // interface ID of slave port
    std::set<int> masterPortIds; // interface IDs of master ports
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

    clocktime_t schedulePdelay;
    clocktime_t syncInterval;
    clocktime_t pdelayInterval;

    double pDelayRespInterval;
    double followUpInterval;

    clocktime_t sentTimeSyncSync;

    // self timers:
    ClockEvent* selfMsgSync = nullptr;
    ClockEvent* selfMsgFollowUp = nullptr;
    ClockEvent* selfMsgDelayReq = nullptr;
    ClockEvent* selfMsgDelayResp = nullptr;
    ClockEvent* requestMsg = nullptr;

  protected:
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;

  public:
    void setCorrectionField(clocktime_t cf);
    void setRateRatio(clocktime_t cf);
    void setPeerDelay(clocktime_t cf);
    void setReceivedTimeSync(clocktime_t cf);
    void setReceivedTimeFollowUp(clocktime_t cf);
    void setReceivedTimeAtHandleMessage(clocktime_t cf);
    void setOriginTimestamp(clocktime_t cf);

    void sendPacketToNIC(Packet *packet, int portId);

    void sendSync(clocktime_t value);
    void sendFollowUp();
    void sendPdelayReq();
    void sendPdelayResp(int portId);
    void sendPdelayRespFollowUp(int portId);

    void processSync(const GPtpSync* gptp);
    void processFollowUp(const GPtpFollowUp* gptp);
    void processPdelayReq(const GPtpPdelayReq* gptp);
    void processPdelayResp(const GPtpPdelayResp* gptp);
    void processPdelayRespFollowUp(const GPtpPdelayRespFollowUp* gptp);

    clocktime_t getCorrectionField();
    clocktime_t getRateRatio();
    clocktime_t getPeerDelay();
    clocktime_t getReceivedTimeSync();
    clocktime_t getReceivedTimeFollowUp();
    clocktime_t getReceivedTimeAtHandleMessage();
    clocktime_t getOriginTimestamp();

    clocktime_t getCalculatedDrift(IClock *clock, clocktime_t value) { return CLOCKTIME_ZERO; }
};

}

#endif
