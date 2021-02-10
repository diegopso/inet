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

namespace inet {

Define_Module(GPtp);

void GPtp::initialize(int stage)
{
    ClockUserModuleBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        cModule* gPtpNode = getContainingNode(this);
        clockGptp = check_and_cast<SettableClock *>(clock);

        gPtpNodeType = static_cast<GPtpNodeType>(cEnum::get("GPtpNodeType", "inet")->resolve(par("gPtpNodeType")));
        syncInterval = par("syncInterval");
        withFcs = par("withFcs");

        pDelayRespInterval = par("pDelayRespInterval");
        followUpInterval = par("followUpInterval");

        /* Only grandmaster in the domain can initialize the synchronization message periodically
         * so below condition checks whether it is grandmaster and then schedule first sync message */
        if(portType == MASTER_PORT && nodeType == MASTER_NODE)
        {
            // Schedule Sync message to be sent
            if (NULL == selfMsgSync)
                selfMsgSync = new ClockEvent("selfMsgSync");

            clocktime_t scheduleSync = syncInterval + 0.01;
            this->setOriginTimestamp(scheduleSync);
            scheduleClockEventAfter(scheduleSync, selfMsgSync);
        }
        else if(portType == SLAVE_PORT)
        {
            vLocalTime.setName("Clock local");
            vMasterTime.setName("Clock master");
            vTimeDifference.setName("Clock difference to neighbor");
            vRateRatio.setName("Rate ratio");
            vPeerDelay.setName("Peer delay");
            vTimeDifferenceGMafterSync.setName("Clock difference to GM after Sync");
            vTimeDifferenceGMbeforeSync.setName("Clock difference to GM before Sync");

            requestMsg = new ClockEvent("requestToSendSync");

            // Schedule Pdelay_Req message is sent by slave port
            // without depending on node type which is grandmaster or bridge
            selfMsgDelayReq = new ClockEvent("selfMsgPdelay");
            pdelayInterval = par("pdelayInterval");

            schedulePdelay = pdelayInterval;
            scheduleClockEventAfter(schedulePdelay, selfMsgDelayReq);
        }
    }
    if (stage == INITSTAGE_LINK_LAYER) {
        peerDelay = 0;
        receivedTimeSync = 0;
        receivedTimeFollowUp = 0;

        interfaceTable = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);

        gPtpNodeType = static_cast<GPtpNodeType>(cEnum::get("GPtpNodeType", "inet")->resolve(par("gPtpNodeType")));

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

        selfMsgFollowUp = new ClockEvent("selfMsgFollowUp");

        registerProtocol(Protocol::gptp, gate("socketOut"), gate("socketIn"));
    }
}

void GPtp::handleMessage(cMessage *msg)
{
    if (msg->isSelfMessage()) {
        // masterport:
        if(selfMsgSync == msg) {
            sendSync(clockGptp->getClockTime());

            /* Schedule next Sync message at next sync interval
             * Grand master always works at simulation time */
            scheduleClockEventAfter(syncInterval, selfMsgSync);
        }
        else if(selfMsgFollowUp == msg) {
            sendFollowUp();
        }
        else if(selfMsgDelayResp == msg) {
            sendPdelayResp();
        }

        // slaveport:
        else if(msg == selfMsgDelayReq) {
            sendPdelayReq(); //TODO on slaveports only
            scheduleClockEventAfter(pdelayInterval, selfMsgDelayReq);
        }
        else
            throw cRuntimeError("Unknown self message");
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
                        sendSync(clockGptp->getClockTime());
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
                processPdelayReq(check_and_cast<const GPtpPdelayReq *>(gptp.get()));
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
    packet->addTag<MacAddressReq>()->setDestAddress(MacAddress::BROADCAST_ADDRESS);
    auto gptp = makeShared<GPtpSync>(); //---- gptp = gPtp::newSyncPacket();
    /* OriginTimestamp always get Sync departure time from grand master */
    if (gPtpNodeType == MASTER_NODE) {
        gptp->setOriginTimestamp(value);
        setOriginTimestamp(value);
    }
    else if(gPtpNodeType == BRIDGE_NODE) {
        gptp->setOriginTimestamp(getOriginTimestamp());
    }

    gptp->setLocalDrift(getCalculatedDrift(clockGptp, syncInterval));
    sentTimeSyncSync = clockGptp->getClockTime();
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
    packet->addTag<MacAddressReq>()->setDestAddress(MacAddress::BROADCAST_ADDRESS);
    auto gptp = makeShared<GPtpFollowUp>();
    gptp->setSentTime(clockGptp->getClockTime());
    gptp->setPreciseOriginTimestamp(this->getOriginTimestamp());

    if (nodeType == MASTER_NODE)
        gptp->setCorrectionField(0);
    else if (nodeType == BRIDGE_NODE)
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

void GPtp::sendPdelayResp(int portId)
{
    auto packet = new Packet("GPtpPdelayResp");
    packet->addTag<MacAddressReq>()->setDestAddress(MacAddress::BROADCAST_ADDRESS);
    auto gptp = makeShared<GPtpPdelayResp>();
    gptp->setSentTime(clockGptp->getClockTime());
    gptp->setRequestReceiptTimestamp(receivedTimeResponder);
    packet->insertAtFront(gptp);
    sendPacketToNIC(packet, portId);
    sendPdelayRespFollowUp(portId);   //FIXME!!!
}

void EtherGPtp::sendPdelayRespFollowUp(int portId)
{
    auto packet = new Packet("GPtpPdelayRespFollowUp");
    packet->addTag<MacAddressReq>()->setDestAddress(MacAddress::BROADCAST_ADDRESS);
    auto gptp = makeShared<GPtpPdelayRespFollowUp>();
    gptp->setSentTime(clockGptp->getClockTime());
    gptp->setResponseOriginTimestamp(receivedTimeResponder + (clocktime_t)pDelayRespInterval);
    packet->insertAtFront(gptp);
    sendPacketToNIC(packet, portId);
}

}

