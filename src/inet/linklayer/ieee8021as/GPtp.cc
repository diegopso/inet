//
// @authors: Enkhtuvshin Janchivnyambuu
//           Henning Puttnies
//           Peter Danielis
//           University of Rostock, Germany
// 

#include "GPtp.h"

#include "EtherGPtp.h"

#include "inet/common/IProtocolRegistrationListener.h"
#include "inet/linklayer/common/InterfaceTag_m.h"
#include "inet/linklayer/common/MacAddressTag_m.h"
#include "inet/linklayer/ethernet/common/Ethernet.h"
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

void GPtp::initialize(int stage)
{
    ClockUserModuleBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        gPtpNodeType = static_cast<GPtpNodeType>(cEnum::get("GPtpNodeType", "inet")->resolve(par("gPtpNodeType")));
        syncInterval = par("syncInterval");
        pDelayRespInterval = par("pDelayRespInterval");
        followUpInterval = par("followUpInterval");

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
            slavePortId = CHK(interfaceTable->findInterfaceByName(str))->getInterfaceId();
        }
        else
            if (gPtpNodeType != MASTER_NODE)
                throw cRuntimeError("Parameter error: Missing slave port for %s", par("gPtpNodeType").stringValue());

        auto v = check_and_cast<cValueArray *>(par("masterPorts").objectValue())->asStringVector();
        if (v.empty() and gPtpNodeType != SLAVE_NODE)
            throw cRuntimeError("Parameter error: Missing any master port for %s", par("gPtpNodeType").stringValue());
        for (const auto& p : v) {
            int portId = CHK(interfaceTable->findInterfaceByName(p.c_str()))->getInterfaceId();
            if (portId == slavePortId)
                throw cRuntimeError("Parameter error: the port '%s' specified both master and slave port", p.c_str());
            masterPortIds.insert(portId);
        }

        correctionField = par("correctionField");

        rateRatio = par("rateRatio");

        selfMsgFollowUp = new ClockEvent("selfMsgFollowUp", GPTP_SELF_MSG_FOLLOW_UP);

        registerProtocol(Protocol::gptp, gate("socketOut"), gate("socketIn"));

        /* Only grandmaster in the domain can initialize the synchronization message periodically
         * so below condition checks whether it is grandmaster and then schedule first sync message */
        if(gPtpNodeType == MASTER_NODE)
        {
            // Schedule Sync message to be sent
            selfMsgSync = new ClockEvent("selfMsgSync", GPTP_SELF_MSG_SYNC);

            clocktime_t scheduleSync = syncInterval + 0.01;
            this->setOriginTimestamp(scheduleSync);
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

        case GPTP_SELF_MSG_FOLLOW_UP:
            // masterport:
            sendFollowUp();
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
                    processSync(check_and_cast<const GPtpSync *>(gptp.get()));
                    delete msg;
                    break;
                case GPTPTYPE_FOLLOW_UP:
                    processFollowUp(check_and_cast<const GPtpFollowUp *>(gptp.get()));
                    // Send a request to send Sync message
                    // through other gPtp Ethernet interfaces
                    if(gPtpNodeType == BRIDGE_NODE)
                        sendSync(clock->getClockTime());
                    delete msg;
                    break;
                case GPTPTYPE_PDELAY_RESP:
                    processPdelayResp(check_and_cast<const GPtpPdelayResp *>(gptp.get()));
                    delete msg;
                    break;
                case GPTPTYPE_PDELAY_RESP_FOLLOW_UP:
                    processPdelayRespFollowUp(check_and_cast<const GPtpPdelayRespFollowUp *>(gptp.get()));
                    delete msg;
                    break;
                default:
                    throw cRuntimeError("Unknown gPTP packet type: %d", (int)(gptpTypeCode));
            }
        }
        else if (masterPortIds.find(incomingNicId) != masterPortIds.end()) {
            // master port
            if(gptp->getTypeCode() == GPTPTYPE_PDELAY_REQ) {
                processPdelayReq(packet, check_and_cast<const GPtpPdelayReq *>(gptp.get()));
                delete msg;
            }
            else {
                throw cRuntimeError("Unaccepted gPTP type: %d", (int)(gptpTypeCode));
            }
        }
        else {
            // passive port
        }
    }
    delete msg;
}

void GPtp::setCorrectionField(clocktime_t cf)
{
    correctionField = cf;
}

clocktime_t GPtp::getCorrectionField()
{
    return correctionField;
}

void GPtp::setRateRatio(clocktime_t cf)
{
    rateRatio = cf;
}

clocktime_t GPtp::getRateRatio()
{
    return rateRatio;
}

void GPtp::setPeerDelay(clocktime_t cf)
{
    peerDelay = cf;
}

clocktime_t GPtp::getPeerDelay()
{
    return peerDelay;
}

void GPtp::setReceivedTimeSync(clocktime_t cf)
{
    receivedTimeSync = cf;
}

clocktime_t GPtp::getReceivedTimeSync()
{
    return receivedTimeSync;
}

void GPtp::setReceivedTimeFollowUp(clocktime_t cf)
{
    receivedTimeFollowUp = cf;
}

clocktime_t GPtp::getReceivedTimeFollowUp()
{
    return receivedTimeFollowUp;
}

void GPtp::setReceivedTimeAtHandleMessage(clocktime_t cf)
{
    receivedTimeAtHandleMessage = cf;
}

clocktime_t GPtp::getReceivedTimeAtHandleMessage()
{
    return receivedTimeAtHandleMessage;
}

void GPtp::setOriginTimestamp(clocktime_t cf)
{
    originTimestamp = cf;
}

clocktime_t GPtp::getOriginTimestamp()
{
    return originTimestamp;
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
        packet->addTag<DispatchProtocolReq>()->setProtocol(protocol);
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
        setOriginTimestamp(value);
    }
    else if(gPtpNodeType == BRIDGE_NODE) {
        gptp->setOriginTimestamp(getOriginTimestamp());
    }

    gptp->setLocalDrift(getCalculatedDrift(clock, syncInterval));
    sentTimeSyncSync = clock->getClockTime();
    gptp->setSentTime(sentTimeSyncSync);
    packet->insertAtFront(gptp);

    for (auto port: masterPortIds)
        sendPacketToNIC(packet->dup(), port);
    delete packet;

    scheduleClockEventAfter(followUpInterval, selfMsgFollowUp);
}

void GPtp::sendFollowUp()
{
    auto packet = new Packet("GPtpFollowUp");
    packet->addTag<MacAddressReq>()->setDestAddress(GPTP_MULTICAST_ADDRESS);
    auto gptp = makeShared<GPtpFollowUp>();
    gptp->setSentTime(clock->getClockTime());
    gptp->setPreciseOriginTimestamp(this->getOriginTimestamp());

    if (gPtpNodeType == MASTER_NODE)
        gptp->setCorrectionField(0);
    else if (gPtpNodeType == BRIDGE_NODE)
    {
        /**************** Correction field calculation *********************************************
         * It is calculated by adding peer delay, residence time and packet transmission time      *
         * correctionField(i)=correctionField(i-1)+peerDelay+(timeReceivedSync-timeSentSync)*(1-f) *
         *******************************************************************************************/
        int bits = b(ETHERNET_PHY_HEADER_LEN + ETHER_MAC_HEADER_BYTES + GPTP_SYNC_PACKET_SIZE + ETHER_FCS_BYTES).get();

        clocktime_t packetTransmissionTime = (clocktime_t)(bits / nic->getDatarate());

        gptp->setCorrectionField(this->getCorrectionField() + this->getPeerDelay() + packetTransmissionTime + sentTimeSyncSync - this->getReceivedTimeSync());
//        gptp->setCorrectionField(this->getCorrectionField() + this->getPeerDelay() + packetTransmissionTime + clockGptp->getCurrentTime() - this->getReceivedTimeSync());
    }
    gptp->setRateRatio(getRateRatio());
    packet->insertAtFront(gptp);

    for (auto port: masterPortIds)
        sendPacketToNIC(packet->dup(), port);
    delete packet;
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
    sendPdelayRespFollowUp(portId);   //FIXME!!!
}

void GPtp::sendPdelayRespFollowUp(int portId)
{
    auto packet = new Packet("GPtpPdelayRespFollowUp");
    packet->addTag<MacAddressReq>()->setDestAddress(GPTP_MULTICAST_ADDRESS);
    auto gptp = makeShared<GPtpPdelayRespFollowUp>();
    gptp->setSentTime(clock->getClockTime());
    gptp->setResponseOriginTimestamp(receivedTimeResponder + (clocktime_t)pDelayRespInterval);
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

void GPtp::processSync(const GPtpSync* gptp)
{
    clocktime_t sentTimeSync = gptp->getOriginTimestamp();
    clocktime_t residenceTime = clock->getClockTime() - this->getReceivedTimeAtHandleMessage();
    receivedTimeSyncBeforeSync = clock->getClockTime();

    /************** Time synchronization *****************************************
     * Local time is adjusted using peer delay, correction field, residence time *
     * and packet transmission time based departure time of Sync message from GM *
     *****************************************************************************/
    int bits = b(ETHERNET_PHY_HEADER_LEN + ETHER_MAC_HEADER_BYTES + GPTP_SYNC_PACKET_SIZE + ETHER_FCS_BYTES + B(2)).get();

    clocktime_t packetTransmissionTime = (clocktime_t)(bits / nic->getDatarate());

    check_and_cast<SettableClock *>(clock)->setClockTime(sentTimeSync + this->getPeerDelay() + this->getCorrectionField() + residenceTime + packetTransmissionTime);

    receivedTimeSyncAfterSync = clock->getClockTime();
    this->setReceivedTimeSync(receivedTimeSyncAfterSync);

    // adjust local timestamps, too
    transmittedTimeRequester += receivedTimeSyncAfterSync - receivedTimeSyncBeforeSync;

    /************** Rate ratio calculation *************************************
     * It is calculated based on interval between two successive Sync messages *
     ***************************************************************************/
    clocktime_t neighborDrift = gptp->getLocalDrift();
    clocktime_t rateRatio = (neighborDrift + syncInterval)/(getCalculatedDrift(clock, syncInterval) + syncInterval);

    EV_INFO << "############## SYNC #####################################"<< endl;
    EV_INFO << "RECEIVED TIME AFTER SYNC - " << receivedTimeSyncAfterSync << endl;
    EV_INFO << "RECEIVED SIM TIME        - " << simTime() << endl;
    EV_INFO << "ORIGIN TIME SYNC         - " << sentTimeSync << endl;
    EV_INFO << "RESIDENCE TIME           - " << residenceTime << endl;
    EV_INFO << "CORRECTION FIELD         - " << this->getCorrectionField() << endl;
    EV_INFO << "PROPAGATION DELAY        - " << this->getPeerDelay() << endl;
    EV_INFO << "TRANSMISSION TIME        - " << packetTransmissionTime << endl;

    // Transmission time of 2 more bytes is going here
    // in mac layer? or in our implementation?
    EV_INFO << "TIME DIFFERENCE TO STIME - " << receivedTimeSyncAfterSync - clock->getClockTime() << endl;

    this->setRateRatio(rateRatio);
    vRateRatio.record(CLOCKTIME_AS_SIMTIME(rateRatio));
    vLocalTime.record(CLOCKTIME_AS_SIMTIME(receivedTimeSyncAfterSync));
    vMasterTime.record(CLOCKTIME_AS_SIMTIME(sentTimeSync));
    vTimeDifference.record(CLOCKTIME_AS_SIMTIME(receivedTimeSyncBeforeSync - sentTimeSync - this->getPeerDelay()));
}

void GPtp::processFollowUp(const GPtpFollowUp* gptp)
{
    this->setReceivedTimeFollowUp(clock->getClockTime());
    this->setOriginTimestamp(gptp->getPreciseOriginTimestamp());
    this->setCorrectionField(gptp->getCorrectionField());

    /************* Time difference to Grand master *******************************************
     * Time difference before synchronize local time and after synchronization of local time *
     *****************************************************************************************/
    int bits = b(ETHERNET_PHY_HEADER_LEN + ETHER_MAC_HEADER_BYTES + GPTP_FOLLOW_UP_PACKET_SIZE + ETHER_FCS_BYTES + B(2)).get();

    clocktime_t packetTransmissionTime = (clocktime_t)(bits / nic->getDatarate());

    clocktime_t timeDifferenceAfter  = receivedTimeSyncAfterSync - this->getOriginTimestamp() - this->getPeerDelay() - this->getCorrectionField() - packetTransmissionTime;
    clocktime_t timeDifferenceBefore = receivedTimeSyncBeforeSync - this->getOriginTimestamp() - this->getPeerDelay() - this->getCorrectionField() - packetTransmissionTime;
    vTimeDifferenceGMafterSync.record(CLOCKTIME_AS_SIMTIME(timeDifferenceAfter));
    vTimeDifferenceGMbeforeSync.record(CLOCKTIME_AS_SIMTIME(timeDifferenceBefore));

    EV_INFO << "############## FOLLOW_UP ################################"<< endl;
    EV_INFO << "RECEIVED TIME AFTER SYNC - " << receivedTimeSyncAfterSync << endl;
    EV_INFO << "ORIGIN TIME SYNC         - " << this->getOriginTimestamp() << endl;
    EV_INFO << "CORRECTION FIELD         - " << this->getCorrectionField() << endl;
    EV_INFO << "PROPAGATION DELAY        - " << this->getPeerDelay() << endl;
    EV_INFO << "TRANSMISSION TIME        - " << packetTransmissionTime << endl;
    EV_INFO << "TIME DIFFERENCE TO GM    - " << timeDifferenceAfter << endl;
    EV_INFO << "TIME DIFFERENCE TO GM BEF- " << timeDifferenceBefore << endl;

//    int bits = (MAC_HEADER + FOLLOW_UP_PACKET_SIZE + CRC_CHECKSUM) * 8;
//    clocktime_t packetTransmissionTime = (clocktime_t)(bits / nic->getDatarate());
//    vTimeDifferenceGMafterSync.record(receivedTimeSyncAfterSync - simTime() + FollowUpInterval + packetTransmissionTime + this->getPeerDelay());
//    vTimeDifferenceGMbeforeSync.record(receivedTimeSyncBeforeSync - simTime() + FollowUpInterval + packetTransmissionTime + this->getPeerDelay());
}

void GPtp::processPdelayReq(Packet *packet, const GPtpPdelayReq* gptp)
{
    receivedTimeResponder = clock->getClockTime();

    auto resp = new GPtpReqAnswerEvent("selfMsgPdelayResp", GPTP_SELF_REQ_ANSWER_KIND);
    resp->setPortId(packet->getTag<InterfaceInd>()->getInterfaceId());
    resp->setIngressTimestamp(gptp->getIngressTimestamp());

    scheduleClockEventAfter(pDelayRespInterval, resp);
}

void GPtp::processPdelayResp(const GPtpPdelayResp* gptp)
{
    receivedTimeRequester = clock->getClockTime();
    receivedTimeResponder = gptp->getRequestReceiptTimestamp();
    transmittedTimeResponder = gptp->getSentTime();
}

void GPtp::processPdelayRespFollowUp(const GPtpPdelayRespFollowUp* gptp)
{
    /************* Peer delay measurement ********************************************
     * It doesn't contain packet transmission time which is equal to (byte/datarate) *
     * on responder side, pdelay_resp is scheduled using PDelayRespInterval time.    *
     * PDelayRespInterval needs to be deducted as well as packet transmission time   *
     *********************************************************************************/
    int bits = b(ETHERNET_PHY_HEADER_LEN + ETHER_MAC_HEADER_BYTES + GPTP_PDELAY_RESP_PACKET_SIZE + ETHER_FCS_BYTES).get();

    clocktime_t packetTransmissionTime = (clocktime_t)(bits / nic->getDatarate());

    // TODO: names: peerDelayInitiator, peerDelayResponder
    //peerDelay = (this->getRateRatio().dbl() * (receivedTimeRequester.dbl() - transmittedTimeRequester.dbl()) - (transmittedTimeResponder.dbl() - receivedTimeResponder.dbl())) / 2
    //        - pDelayRespInterval - packetTransmissionTime;
    // TODO: peerDelay --> propagationDelay
    peerDelay = (this->getRateRatio().dbl() * (receivedTimeRequester.dbl() - transmittedTimeRequester.dbl()) + transmittedTimeResponder.dbl() - receivedTimeResponder.dbl()) / 2
            - pDelayRespInterval - packetTransmissionTime;

    EV_INFO << "transmittedTimeRequester - " << transmittedTimeRequester << endl;
    EV_INFO << "transmittedTimeResponder - " << transmittedTimeResponder << endl;
    EV_INFO << "receivedTimeRequester    - " << receivedTimeRequester << endl;
    EV_INFO << "receivedTimeResponder    - " << receivedTimeResponder << endl;
    EV_INFO << "packetTransmissionTime   - " << packetTransmissionTime << endl;
    EV_INFO << "PEER DELAY               - " << peerDelay << endl;

    this->setPeerDelay(peerDelay);
    vPeerDelay.record(CLOCKTIME_AS_SIMTIME(peerDelay));
}

}

