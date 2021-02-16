//
// @authors: Enkhtuvshin Janchivnyambuu
//           Henning Puttnies
//           Peter Danielis
//           University of Rostock, Germany
// 

#include "GPtp.h"

#include "GPtpPacket_m.h"

#include "inet/clock/model/SettableClock.h"
#include "inet/common/IProtocolRegistrationListener.h"
#include "inet/common/clock/ClockUserModuleBase.h"
#include "inet/linklayer/common/InterfaceTag_m.h"
#include "inet/linklayer/common/MacAddress.h"
#include "inet/linklayer/common/MacAddressTag_m.h"
#include "inet/linklayer/ethernet/common/Ethernet.h"
#include "inet/linklayer/ethernet/common/EthernetMacHeader_m.h"
#include "inet/networklayer/common/NetworkInterface.h"
#include "inet/physicallayer/wired/ethernet/EthernetPhyHeader_m.h"

namespace inet {

Define_Module(GPtp);

// MAC address:
//   01-80-C2-00-00-02 for TimeSync (ieee 802.1as-2020, 13.3.1.2)
//   01-80-C2-00-00-0E for Announce and Signaling messages, for Sync, Follow_Up, Pdelay_Req, Pdelay_Resp, and Pdelay_Resp_Follow_Up messages
const MacAddress GPtp::GPTP_MULTICAST_ADDRESS("01:80:C2:00:00:0E");

// EtherType:
//   0x8809 for TimeSync (ieee 802.1as-2020, 13.3.1.2)
//   0x88F7 for Announce and Signaling messages, for Sync, Follow_Up, Pdelay_Req, Pdelay_Resp, and Pdelay_Resp_Follow_Up messages

GPtp::~GPtp()
{
    cancelAndDeleteClockEvent(selfMsgDelayReq);
    cancelAndDeleteClockEvent(selfMsgSync);
    cancelAndDeleteClockEvent(requestMsg);
}

void GPtp::initialize(int stage)
{
    ClockUserModuleBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        gPtpNodeType = static_cast<GPtpNodeType>(cEnum::get("GPtpNodeType", "inet")->resolve(par("gPtpNodeType")));
        syncInterval = par("syncInterval");
        pDelayRespInterval = par("pDelayRespInterval");

    }
    if (stage == INITSTAGE_LINK_LAYER) {
        peerDelay = 0;
        receivedTimeSync = 0;
        receivedTimeFollowUp = 0;

        interfaceTable = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);

        const char *str = par("slavePort");
        if (*str) {
            if (gPtpNodeType == MASTER_NODE)
                throw cRuntimeError("Parameter inconsistency: MASTER_NODE with slave port");
            auto nic = CHK(interfaceTable->findInterfaceByName(str));
            slavePortId = nic->getInterfaceId();
            nic->subscribe(transmissionEndedSignal, this);
            nic->subscribe(receptionEndedSignal, this);
        }
        else
            if (gPtpNodeType != MASTER_NODE)
                throw cRuntimeError("Parameter error: Missing slave port for %s", par("gPtpNodeType").stringValue());

        auto v = check_and_cast<cValueArray *>(par("masterPorts").objectValue())->asStringVector();
        if (v.empty() and gPtpNodeType != SLAVE_NODE)
            throw cRuntimeError("Parameter error: Missing any master port for %s", par("gPtpNodeType").stringValue());
        for (const auto& p : v) {
            auto nic = CHK(interfaceTable->findInterfaceByName(p.c_str()));
            int portId = nic->getInterfaceId();
            if (portId == slavePortId)
                throw cRuntimeError("Parameter error: the port '%s' specified both master and slave port", p.c_str());
            masterPortIds.insert(portId);
            nic->subscribe(transmissionEndedSignal, this);
            nic->subscribe(receptionEndedSignal, this);
        }

        correctionField = par("correctionField");

        rateRatio = par("rateRatio");

        registerProtocol(Protocol::gptp, gate("socketOut"), gate("socketIn"));

        /* Only grandmaster in the domain can initialize the synchronization message periodically
         * so below condition checks whether it is grandmaster and then schedule first sync message */
        if(gPtpNodeType == MASTER_NODE)
        {
            // Schedule Sync message to be sent
            selfMsgSync = new ClockEvent("selfMsgSync", GPTP_SELF_MSG_SYNC);

            clocktime_t scheduleSync = syncInterval + 0.01;
            originTimestamp = clock->getClockTime() + scheduleSync;
            scheduleClockEventAfter(scheduleSync, selfMsgSync);
        }
        if(slavePortId != -1)
        {
            vLocalTime.setName("Clock local");
            vMasterTime.setName("Clock master");
            vTimeDifference.setName("Clock difference to neighbor");
            vRateRatio.setName("Rate ratio");
            vPeerDelay.setName("Peer delay");
            vTimeDifferenceGMafterSync.setName("Clock difference to GM after Sync");
            vTimeDifferenceGMbeforeSync.setName("Clock difference to GM before Sync");

            requestMsg = new ClockEvent("requestToSendSync", GPTP_REQUEST_TO_SEND_SYNC);

            // Schedule Pdelay_Req message is sent by slave port
            // without depending on node type which is grandmaster or bridge
            selfMsgDelayReq = new ClockEvent("selfMsgPdelay", GPTP_SELF_MSG_PDELAY_REQ);
            pdelayInterval = par("pdelayInterval");

            schedulePdelay = pdelayInterval;
            scheduleClockEventAfter(schedulePdelay, selfMsgDelayReq);
        }
    }
}

void GPtp::handleSelfMessage(cMessage *msg)
{
    switch(msg->getKind()) {
        case GPTP_SELF_MSG_SYNC:
            // masterport:
            ASSERT(selfMsgSync == msg);
            sendSync(clock->getClockTime());

            /* Schedule next Sync message at next sync interval
             * Grand master always works at simulation time */
            scheduleClockEventAfter(syncInterval, selfMsgSync);
            break;

        case GPTP_SELF_REQ_ANSWER_KIND:
            // masterport:
            sendPdelayResp(check_and_cast<GPtpReqAnswerEvent*>(msg));
            delete msg;
            break;

        case GPTP_SELF_MSG_PDELAY_REQ:
        // slaveport:
            sendPdelayReq(); //TODO on slaveports only
            scheduleClockEventAfter(pdelayInterval, selfMsgDelayReq);
            break;

        default:
            throw cRuntimeError("Unknown self message (%s)%s, kind=%d", msg->getClassName(), msg->getName(), msg->getKind());
    }
}

void GPtp::handleMessage(cMessage *msg)
{
    if (msg->isSelfMessage()) {
        handleSelfMessage(msg);
    }
    else {
        Packet *packet = check_and_cast<Packet *>(msg);
        auto gptp = packet->peekAtFront<GPtpBase>();
        auto gptpTypeCode = gptp->getTypeCode();
        auto incomingNicId = packet->getTag<InterfaceInd>()->getInterfaceId();

        if (incomingNicId == slavePortId) {
            // slave port
            switch (gptpTypeCode) {
                case GPTPTYPE_SYNC:
                    processSync(packet, check_and_cast<const GPtpSync *>(gptp.get()));
                    break;
                case GPTPTYPE_FOLLOW_UP:
                    processFollowUp(packet, check_and_cast<const GPtpFollowUp *>(gptp.get()));
                    // Send a request to send Sync message
                    // through other gPtp Ethernet interfaces
                    if(gPtpNodeType == BRIDGE_NODE)
                        sendSync(clock->getClockTime());
                    break;
                case GPTPTYPE_PDELAY_RESP:
                    processPdelayResp(packet, check_and_cast<const GPtpPdelayResp *>(gptp.get()));
                    break;
                case GPTPTYPE_PDELAY_RESP_FOLLOW_UP:
                    processPdelayRespFollowUp(packet, check_and_cast<const GPtpPdelayRespFollowUp *>(gptp.get()));
                    break;
                default:
                    throw cRuntimeError("Unknown gPTP packet type: %d", (int)(gptpTypeCode));
            }
        }
        else if (masterPortIds.find(incomingNicId) != masterPortIds.end()) {
            // master port
            if(gptp->getTypeCode() == GPTPTYPE_PDELAY_REQ) {
                processPdelayReq(packet, check_and_cast<const GPtpPdelayReq *>(gptp.get()));
            }
            else {
                throw cRuntimeError("Unaccepted gPTP type: %d", (int)(gptpTypeCode));
            }
        }
        else {
            // passive port
            EV_ERROR << "Message " << msg->getClassAndFullName() << " arrived on passive port " << incomingNicId << ", dropped\n";
        }
        delete msg;
    }
}

void GPtp::sendPacketToNIC(Packet *packet, int portId)
{
    auto networkInterface = interfaceTable->getInterfaceById(portId);
    EV_INFO << "Sending " << packet << " to output interface = " << networkInterface->getInterfaceName() << ".\n";
    packet->addTag<InterfaceReq>()->setInterfaceId(portId);
    packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::gptp);
    packet->addTag<DispatchProtocolInd>()->setProtocol(&Protocol::gptp);
    auto protocol = networkInterface->getProtocol();
    if (protocol != nullptr)
        packet->addTagIfAbsent<DispatchProtocolReq>()->setProtocol(protocol);
    else
        packet->removeTagIfPresent<DispatchProtocolReq>();
    send(packet, "socketOut");
}

void GPtp::sendSync(clocktime_t value)
{
    auto packet = new Packet("GPtpSync");
    packet->addTag<MacAddressReq>()->setDestAddress(GPTP_MULTICAST_ADDRESS);
    auto gptp = makeShared<GPtpSync>(); //---- gptp = gPtp::newSyncPacket();
    /* OriginTimestamp always get Sync departure time from grand master */
    if (gPtpNodeType == MASTER_NODE) {
        gptp->setOriginTimestamp(value);
        originTimestamp = value;
    }
    else if(gPtpNodeType == BRIDGE_NODE) {
        gptp->setOriginTimestamp(originTimestamp);
    }

    gptp->setLocalDrift(getCalculatedDrift(clock, syncInterval));
    sentTimeSyncSync = clock->getClockTime();
    gptp->setSentTime(sentTimeSyncSync);
    packet->insertAtFront(gptp);

    for (auto port: masterPortIds)
        sendPacketToNIC(packet->dup(), port);
    delete packet;

    // The sendFollowUp(portId) called by receiveSignal(), when GPtpSync sent
}

void GPtp::sendFollowUp(int portId)
{
    auto packet = new Packet("GPtpFollowUp");
    packet->addTag<MacAddressReq>()->setDestAddress(GPTP_MULTICAST_ADDRESS);
    auto gptp = makeShared<GPtpFollowUp>();
    gptp->setSentTime(clock->getClockTime());
    gptp->setPreciseOriginTimestamp(originTimestamp);

    if (gPtpNodeType == MASTER_NODE)
        gptp->setCorrectionField(0);
    else if (gPtpNodeType == BRIDGE_NODE)
    {
        /**************** Correction field calculation *********************************************
         * It is calculated by adding peer delay, residence time and packet transmission time      *
         * correctionField(i)=correctionField(i-1)+peerDelay+(timeReceivedSync-timeSentSync)*(1-f) *
         *******************************************************************************************/
        gptp->setCorrectionField(correctionField + peerDelay + sentTimeSyncSync - receivedTimeSync);  // TODO revise it!!! see prev. comment, where is the (1-f),  ???
    }
    gptp->setRateRatio(rateRatio);
    packet->insertAtFront(gptp);
    sendPacketToNIC(packet, portId);
}

void GPtp::sendPdelayResp(GPtpReqAnswerEvent* req)
{
    int portId = req->getPortId();
    auto packet = new Packet("GPtpPdelayResp");
    packet->addTag<MacAddressReq>()->setDestAddress(GPTP_MULTICAST_ADDRESS);
    auto gptp = makeShared<GPtpPdelayResp>();
    gptp->setSentTime(clock->getClockTime());
    gptp->setRequestReceiptTimestamp(req->getIngressTimestamp());
    packet->insertAtFront(gptp);
    sendPacketToNIC(packet, portId);
    // The sendPdelayRespFollowUp(portId) called by receiveSignal(), when GPtpPdelayResp sent
}

void GPtp::sendPdelayRespFollowUp(int portId)
{
    auto packet = new Packet("GPtpPdelayRespFollowUp");
    packet->addTag<MacAddressReq>()->setDestAddress(GPTP_MULTICAST_ADDRESS);
    auto gptp = makeShared<GPtpPdelayRespFollowUp>();
    auto now = clock->getClockTime();
    gptp->setSentTime(now);
    gptp->setResponseOriginTimestamp(now);
    packet->insertAtFront(gptp);
    sendPacketToNIC(packet, portId);
}

void GPtp::sendPdelayReq()
{
    auto packet = new Packet("GPtpPdelayReq");
    packet->addTag<MacAddressReq>()->setDestAddress(GPTP_MULTICAST_ADDRESS);
    auto gptp = makeShared<GPtpPdelayReq>();
    gptp->setSentTime(clock->getClockTime());
    gptp->setOriginTimestamp(clock->getClockTime());
    packet->insertAtFront(gptp);
    ASSERT(slavePortId != -1);
    sendPacketToNIC(packet, slavePortId);
    transmittedTimeRequester = clock->getClockTime();
}

void GPtp::processSync(Packet *packet, const GPtpSync* gptp)
{
    // TODO: move synchronization code to processFollowUp()

    clocktime_t origNow = clock->getClockTime();
    clocktime_t sentTimeSync = gptp->getOriginTimestamp();
    clocktime_t residenceTime = origNow - packet->getTag<GPtpIngressTimeInd>()->getArrivalClockTime();
    receivedTimeSyncBeforeSync = origNow;

    /************** Time synchronization *****************************************
     * Local time is adjusted using peer delay, correction field, residence time *
     * and packet transmission time based departure time of Sync message from GM *
     *****************************************************************************/
    clocktime_t newTime = sentTimeSync + peerDelay + correctionField + residenceTime;
    check_and_cast<SettableClock *>(clock)->setClockTime(newTime);

    receivedTimeSyncAfterSync = clock->getClockTime();
    receivedTimeSync = receivedTimeSyncAfterSync;

    // adjust local timestamps, too
    transmittedTimeRequester += receivedTimeSyncAfterSync - receivedTimeSyncBeforeSync;

    /************** Rate ratio calculation *************************************
     * It is calculated based on interval between two successive Sync messages *
     ***************************************************************************/
    clocktime_t neighborDrift = gptp->getLocalDrift();
    double newRateRatio = (neighborDrift + syncInterval) / (getCalculatedDrift(clock, syncInterval) + syncInterval);

    EV_INFO << "############## SYNC #####################################"<< endl;
    EV_INFO << "RECEIVED TIME AFTER SYNC - " << receivedTimeSyncAfterSync << endl;
    EV_INFO << "RECEIVED SIM TIME        - " << simTime() << endl;
    EV_INFO << "ORIGIN TIME SYNC         - " << sentTimeSync << endl;
    EV_INFO << "RESIDENCE TIME           - " << residenceTime << endl;
    EV_INFO << "CORRECTION FIELD         - " << correctionField << endl;
    EV_INFO << "PROPAGATION DELAY        - " << peerDelay << endl;

    EV_INFO << "TIME DIFFERENCE TO STIME - " << receivedTimeSyncAfterSync - clock->getClockTime() << endl;

    rateRatio = newRateRatio;
    vRateRatio.record(newRateRatio);
    vLocalTime.record(CLOCKTIME_AS_SIMTIME(receivedTimeSyncAfterSync));
    vMasterTime.record(CLOCKTIME_AS_SIMTIME(sentTimeSync));
    vTimeDifference.record(CLOCKTIME_AS_SIMTIME(receivedTimeSyncBeforeSync - sentTimeSync - peerDelay));
}

void GPtp::processFollowUp(Packet *packet, const GPtpFollowUp* gptp)
{
    receivedTimeFollowUp = clock->getClockTime();
    originTimestamp = gptp->getPreciseOriginTimestamp();
    correctionField = gptp->getCorrectionField();

    /************* Time difference to Grand master *******************************************
     * Time difference before synchronize local time and after synchronization of local time *
     *****************************************************************************************/
    clocktime_t timeDifferenceAfter  = receivedTimeSyncAfterSync - originTimestamp - peerDelay - correctionField;
    clocktime_t timeDifferenceBefore = receivedTimeSyncBeforeSync - originTimestamp - peerDelay - correctionField;
    vTimeDifferenceGMafterSync.record(CLOCKTIME_AS_SIMTIME(timeDifferenceAfter));
    vTimeDifferenceGMbeforeSync.record(CLOCKTIME_AS_SIMTIME(timeDifferenceBefore));

    EV_INFO << "############## FOLLOW_UP ################################"<< endl;
    EV_INFO << "RECEIVED TIME AFTER SYNC - " << receivedTimeSyncAfterSync << endl;
    EV_INFO << "ORIGIN TIME SYNC         - " << originTimestamp << endl;
    EV_INFO << "CORRECTION FIELD         - " << correctionField << endl;
    EV_INFO << "PROPAGATION DELAY        - " << peerDelay << endl;
    EV_INFO << "TIME DIFFERENCE TO GM    - " << timeDifferenceAfter << endl;
    EV_INFO << "TIME DIFFERENCE TO GM BEF- " << timeDifferenceBefore << endl;
}

void GPtp::processPdelayReq(Packet *packet, const GPtpPdelayReq* gptp)
{
    receivedTimeResponder = clock->getClockTime();

    auto resp = new GPtpReqAnswerEvent("selfMsgPdelayResp", GPTP_SELF_REQ_ANSWER_KIND);
    resp->setPortId(packet->getTag<InterfaceInd>()->getInterfaceId());
    resp->setIngressTimestamp(packet->getTag<GPtpIngressTimeInd>()->getArrivalClockTime());

    scheduleClockEventAfter(pDelayRespInterval, resp);
}

void GPtp::processPdelayResp(Packet *packet, const GPtpPdelayResp* gptp)
{
    receivedTimeRequester = packet->getTag<GPtpIngressTimeInd>()->getArrivalClockTime();
    receivedTimeResponder = gptp->getRequestReceiptTimestamp();
    transmittedTimeResponder = gptp->getSentTime();
}

void GPtp::processPdelayRespFollowUp(Packet *packet, const GPtpPdelayRespFollowUp* gptp)
{
    // TODO: names: peerDelayInitiator, peerDelayResponder
    //peerDelay = (rateRatio * (receivedTimeRequester - transmittedTimeRequester) - (transmittedTimeResponder - receivedTimeResponder)) / 2.0
    //        - pDelayRespInterval - packetTransmissionTime;
    // TODO: peerDelay --> propagationDelay
    clocktime_t newPeerDelay = (rateRatio * (receivedTimeRequester - transmittedTimeRequester) + transmittedTimeResponder - receivedTimeResponder) / 2.0;

    transmittedTimeResponder = gptp->getResponseOriginTimestamp();
    EV_INFO << "transmittedTimeRequester - " << transmittedTimeRequester << endl;
    EV_INFO << "transmittedTimeResponder - " << transmittedTimeResponder << endl;
    EV_INFO << "receivedTimeRequester    - " << receivedTimeRequester << endl;
    EV_INFO << "receivedTimeResponder    - " << receivedTimeResponder << endl;
    EV_INFO << "PEER DELAY               - " << newPeerDelay << endl;

    peerDelay = newPeerDelay;
    vPeerDelay.record(CLOCKTIME_AS_SIMTIME(peerDelay));
}

void GPtp::receiveSignal(cComponent *source, simsignal_t signal, cObject *obj, cObject *details)
{
    Enter_Method("receiveSignal");

    ClockUserModuleBase::receiveSignal(source, signal, obj, details);

    if (signal == receptionEndedSignal) {
        auto signal = check_and_cast<cPacket *>(obj);
        auto packet = check_and_cast_nullable<Packet *>(signal->getEncapsulatedPacket());
        if (packet) {
            packet->addTagIfAbsent<GPtpIngressTimeInd>()->setArrivalClockTime(clock->getClockTime());
        }
    }
    else if (signal == transmissionEndedSignal) {
        auto signal = check_and_cast<cPacket *>(obj);
        auto packet = check_and_cast_nullable<Packet *>(signal->getEncapsulatedPacket());
        auto protocol = packet->getTag<PacketProtocolTag>()->getProtocol();
        if (*protocol == Protocol::ethernetPhy) {
            const auto& ethPhyHeader = packet->peekAtFront<physicallayer::EthernetPhyHeader>();
            const auto& ethMacHeader = packet->peekAt<EthernetMacHeader>(ethPhyHeader->getChunkLength());
            if (ethMacHeader->getTypeOrLength() == ETHERTYPE_GPTP) {
                const auto& gptp = packet->peekAt<GPtpBase>(ethPhyHeader->getChunkLength() + ethMacHeader->getChunkLength());
                int portId = getContainingNicModule(check_and_cast<cModule*>(source))->getInterfaceId();
                switch (gptp->getTypeCode()) {
                    case GPTPTYPE_PDELAY_RESP:
                        sendPdelayRespFollowUp(portId);
                        break;
                    case GPTPTYPE_SYNC:
                        sendFollowUp(portId);
                        break;
                    case GPTPTYPE_PDELAY_REQ:
                        if (portId == slavePortId)
                            transmittedTimeRequester = clock->getClockTime();
                        break;
                    default:
                        break;
                }
            }
        }
    }
}

}

