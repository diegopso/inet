//
// @authors: Enkhtuvshin Janchivnyambuu
//           Henning Puttnies
//           Peter Danielis
//           University of Rostock, Germany
//

#ifndef __IEEE8021AS_ETHERGPTP_H_
#define __IEEE8021AS_ETHERGPTP_H_

#include <string>

#include "gPtp.h"
#include "gPtpPacket_m.h"
#include "tableGPTP.h"

#include "inet/clock/model/SettableClock.h"
#include "inet/common/clock/ClockUserModuleBase.h"
#include "inet/linklayer/common/MacAddress.h"
#include "inet/linklayer/ethernet/common/EthernetMacHeader_m.h"
#include "inet/networklayer/common/NetworkInterface.h"

namespace inet {

class EtherGPTP : public ClockUserModuleBase
{
    opp_component_ptr<TableGPTP> tableGptp;
    opp_component_ptr<SettableClock> clockGptp;
    NetworkInterface *nic = nullptr;
    GPtpPortType portType;
    GPtpNodeType nodeType;

    // errorTime is time difference between MAC transmition
    // or receiving time and etherGPTP time
    cMessage* requestMsg = nullptr;

    //clocktime_t receivedTimeAtHandleMessage;
    //clocktime_t residenceTime;

    clocktime_t schedulePdelay;
    //clocktime_t schedulePdelayResp;

    clocktime_t syncInterval;
    clocktime_t pdelayInterval;

    ClockEvent* selfMsgSync = nullptr;
    ClockEvent* selfMsgFollowUp = nullptr;
    ClockEvent* selfMsgDelayReq = nullptr;
    ClockEvent* selfMsgDelayResp = nullptr;

    /* Slave port - Variables is used for Peer Delay Measurement */
    clocktime_t peerDelay;
    clocktime_t receivedTimeResponder;
    clocktime_t receivedTimeRequester;
    clocktime_t transmittedTimeResponder;
    clocktime_t transmittedTimeRequester;   // sending time of last GPtpPdelayReq
    double PDelayRespInterval;
    double FollowUpInterval;

    clocktime_t sentTimeSyncSync;

    /* Slave port - Variables is used for Rate Ratio. All times are drifted based on constant drift */
    // clocktime_t sentTimeSync;
    clocktime_t receivedTimeSyncAfterSync;
    clocktime_t receivedTimeSyncBeforeSync;

    /* Statistics information */
    cOutVector vLocalTime;
    cOutVector vMasterTime;
    cOutVector vTimeDifference;
    cOutVector vTimeDifferenceGMafterSync;
    cOutVector vTimeDifferenceGMbeforeSync;
    cOutVector vRateRatio;
    cOutVector vPeerDelay;

    bool withFcs = true;

protected:
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;

  public:
    EtherGPTP();
    virtual ~EtherGPTP();

    void masterPort(cMessage *msg);
    void slavePort(cMessage *msg);

    void sendSync(clocktime_t value);
    void sendFollowUp();
    void sendPdelayReq();
    void sendPdelayResp();
    void sendPdelayRespFollowUp();

    void processSync(const GPtpSync* gptp);
    void processFollowUp(const GPtpFollowUp* gptp);
    void processPdelayReq(const GPtpPdelayReq* gptp);
    void processPdelayResp(const GPtpPdelayResp* gptp);
    void processPdelayRespFollowUp(const GPtpPdelayRespFollowUp* gptp);

    void handleTableGptpCall(cMessage *msg);

    clocktime_t getCalculatedDrift(IClock *clock, clocktime_t value) { return CLOCKTIME_ZERO; }
};

}

#endif
