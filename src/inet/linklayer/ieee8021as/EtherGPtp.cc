//
// @authors: Enkhtuvshin Janchivnyambuu
//           Henning Puttnies
//           Peter Danielis
//           University of Rostock, Germany
// 

#include "EtherGPtp.h"

#include <string>
#include <sstream>
#include <iostream>
#include <fstream>
#include <list>
#include <utility>

#include "inet/common/ModuleAccess.h"
#include "inet/common/ModuleRef.h"
#include "inet/linklayer/common/MacAddress.h"
#include "inet/linklayer/ethernet/base/EthernetMacBase.h"
#include "inet/linklayer/ethernet/common/EthernetMacHeader_m.h"
#include "inet/linklayer/ieee8021as/GPtp.h"
#include "inet/linklayer/ieee8021as/GPtpPacket_m.h"
#include "inet/linklayer/ieee8021as/TableGPtp.h"

namespace inet {

Define_Module(EtherGPtp);

EtherGPtp::EtherGPtp()
{
}

EtherGPtp::~EtherGPtp()
{
    if (tableGptp)
        tableGptp->removeGptp(this);
    cancelAndDelete(selfMsgSync);
    cancelAndDelete(selfMsgFollowUp);
    cancelAndDelete(selfMsgDelayReq);
    cancelAndDelete(selfMsgDelayResp);
    delete requestMsg;
}

void EtherGPtp::initialize(int stage)
{
    ClockUserModuleBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        cModule* gPtpNode = getContainingNode(this);
        tableGptp = check_and_cast<TableGPtp *>(gPtpNode->getSubmodule("tableGPtp"));
        clockGptp = check_and_cast<SettableClock *>(gPtpNode->getSubmodule("clock"));
        nic = getContainingNicModule(this);

        portType = static_cast<GPtpPortType>(cEnum::get("GPtpPortType", "inet")->resolve(par("portType")));
        nodeType = static_cast<GPtpNodeType>(cEnum::get("GPtpNodeType", "inet")->resolve(tableGptp->par("gPtpNodeType")));
        syncInterval = par("syncInterval");
        withFcs = par("withFcs");

        /* following parameters are used to schedule follow_up and pdelay_resp messages.
         * These numbers must be enough large to prevent creating queue in MAC layer.
         * It means it should be large than transmission time of message sent before */
        PDelayRespInterval = 0.000008;
        FollowUpInterval = 0.000007;

        /* Only grandmaster in the domain can initialize the synchronization message periodically
         * so below condition checks whether it is grandmaster and then schedule first sync message */
        if(portType == MASTER_PORT && nodeType == MASTER_NODE)
        {
            // Schedule Sync message to be sent
            if (NULL == selfMsgSync)
                selfMsgSync = new ClockEvent("selfMsgSync");

            clocktime_t scheduleSync = syncInterval + 0.01;
            tableGptp->setOriginTimestamp(scheduleSync);
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
            if (NULL == selfMsgDelayReq)
                selfMsgDelayReq = new ClockEvent("selfMsgPdelay");
            pdelayInterval = par("pdelayInterval");

            schedulePdelay = pdelayInterval;
            scheduleClockEventAfter(schedulePdelay, selfMsgDelayReq);
        }
    }
    if (stage == INITSTAGE_LOCAL + 1) {
        tableGptp->addGptp(this);
        peerDelay = tableGptp->getPeerDelay();
    }
}

void EtherGPtp::handleMessage(cMessage *msg)
{
    tableGptp->setReceivedTimeAtHandleMessage(clockGptp->getClockTime());

    if(portType == MASTER_PORT)
    {
        masterPort(msg);
    }
    else if(portType == SLAVE_PORT)
    {
        slavePort(msg);
    }
    else
    {
        // Forward message to upperLayerOut gate since packet is not gPtp
        if(msg->arrivedOn("lowerLayerIn"))
        {
            EV_INFO << "EtherGPTP: Received " << msg << " from LOWER LAYER." << endl;
            send(msg, "upperLayerOut");
        }
        else
        {
            EV_INFO << "EtherGPTP: Received " << msg << " from UPPER LAYER." << endl;
            send(msg, "lowerLayerOut");
        }
    }
}

void EtherGPtp::handleTableGptpCall(cMessage *msg)
{
    Enter_Method("handleTableGptpCall");

    take(msg);

    if(portType == MASTER_PORT) {
        // Only sync message is sent if its node is bridge
        if(nodeType == BRIDGE_NODE)
            sendSync(clockGptp->getClockTime());
        delete msg;
    }
    else if(portType == SLAVE_PORT) {
        delete msg;
    }
    else {
        delete msg;
    }
}

/*********************************/
/* Master port related functions */
/*********************************/

void EtherGPtp::masterPort(cMessage *msg)
{
    if (msg->isSelfMessage()) {
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
    }
    else if(msg->arrivedOn("lowerLayerIn")) {
        auto packet = check_and_cast<Packet *>(msg);
        const auto& ethHdr = packet->peekAtFront<EthernetMacHeader>();
        if (ethHdr->getTypeOrLength() == ETHERTYPE_GPTP) {
            auto gptp = packet->peekAt<GPtpBase>(packet->getFrontOffset() + ethHdr->getChunkLength());
            if(gptp->getTypeCode() == GPTPTYPE_PDELAY_REQ) {
                processPdelayReq(check_and_cast<const GPtpPdelayReq *>(gptp.get()));
                delete msg;
            }
            else {
                // Forward message to upperLayerOut gate since packet is not gPtp
                send(msg, "upperLayerOut");
            }
        }
        else {
            // Forward message to upperLayerOut gate since packet is not gPtp
            send(msg, "upperLayerOut");
        }
    }
    else if (msg->arrivedOn("upperLayerIn")) {
        // Forward message to lowerLayerOut gate because the message from upper layer doesn't need to be touched
        // and we are interested in only message from lowerLayerIn
        send(msg, "lowerLayerOut");
    }
}

void EtherGPtp::sendSync(clocktime_t value)
{
    auto packet = new Packet("GPtpSync");
    auto frame = makeShared<EthernetMacHeader>();
    frame->setDest(MacAddress::BROADCAST_ADDRESS);
    frame->setTypeOrLength(ETHERTYPE_GPTP);
    auto gptp = makeShared<GPtpSync>(); //---- gptp = gPtp::newSyncPacket();

    /* OriginTimestamp always get Sync departure time from grand master */
    if (nodeType == MASTER_NODE) {
        gptp->setOriginTimestamp(value);
        tableGptp->setOriginTimestamp(value);
    }
    else if(nodeType == BRIDGE_NODE) {
        gptp->setOriginTimestamp(tableGptp->getOriginTimestamp());
    }

    gptp->setLocalDrift(getCalculatedDrift(clockGptp, syncInterval));
    sentTimeSyncSync = clockGptp->getClockTime();
    gptp->setSentTime(sentTimeSyncSync);
    packet->insertAtFront(gptp);
    packet->insertAtFront(frame);

    B paddingLength = MIN_ETHERNET_FRAME_BYTES - ETHER_FCS_BYTES - packet->getDataLength();
    if (paddingLength > B(0)) {
        const auto& ethPadding = makeShared<EthernetPadding>();
        ethPadding->setChunkLength(paddingLength);
        packet->insertAtBack(ethPadding);
    }

    if (withFcs) {
        const auto& ethernetFcs = makeShared<EthernetFcs>();
        ethernetFcs->setFcsMode(FcsMode::FCS_DECLARED_CORRECT);     //TODO add parameter
        packet->insertAtBack(ethernetFcs);
    }

    send(packet, "lowerLayerOut");

    if (NULL == selfMsgFollowUp)
        selfMsgFollowUp = new ClockEvent("selfMsgFollowUp");
    scheduleClockEventAfter(FollowUpInterval, selfMsgFollowUp);
}

void EtherGPtp::sendFollowUp()
{
    auto packet = new Packet("GPtpFollowUp");
    auto frame = makeShared<EthernetMacHeader>();
    frame->setDest(MacAddress::BROADCAST_ADDRESS);
    frame->setTypeOrLength(ETHERTYPE_GPTP);  // So far INET doesn't support gPTP (etherType = 0x88f7)

    auto gptp = makeShared<GPtpFollowUp>(); //---- gPtp_FollowUp* gptp = gPtp::newFollowUpPacket();
    gptp->setSentTime(clockGptp->getClockTime());        // simTime()
    gptp->setPreciseOriginTimestamp(tableGptp->getOriginTimestamp());

    if (nodeType == MASTER_NODE)
        gptp->setCorrectionField(0);
    else if (nodeType == BRIDGE_NODE)
    {
        /**************** Correction field calculation *********************************************
         * It is calculated by adding peer delay, residence time and packet transmission time      *
         * correctionField(i)=correctionField(i-1)+peerDelay+(timeReceivedSync-timeSentSync)*(1-f) *
         *******************************************************************************************/
        int bits = (MAC_HEADER + GPTP_SYNC_PACKET_SIZE + CRC_CHECKSUM) * 8;

        clocktime_t packetTransmissionTime = (clocktime_t)(bits / nic->getDatarate());

        gptp->setCorrectionField(tableGptp->getCorrectionField() + tableGptp->getPeerDelay() + packetTransmissionTime + sentTimeSyncSync - tableGptp->getReceivedTimeSync());
//        gptp->setCorrectionField(tableGptp->getCorrectionField() + tableGptp->getPeerDelay() + packetTransmissionTime + clockGptp->getCurrentTime() - tableGptp->getReceivedTimeSync());
    }
    gptp->setRateRatio(tableGptp->getRateRatio());
    packet->insertAtFront(gptp);
    packet->insertAtFront(frame);

    B paddingLength = MIN_ETHERNET_FRAME_BYTES - ETHER_FCS_BYTES - packet->getDataLength();
    if (paddingLength > B(0)) {
        const auto& ethPadding = makeShared<EthernetPadding>();
        ethPadding->setChunkLength(paddingLength);
        packet->insertAtBack(ethPadding);
    }

    if (withFcs) {
        const auto& ethernetFcs = makeShared<EthernetFcs>();
        ethernetFcs->setFcsMode(FcsMode::FCS_DECLARED_CORRECT);     //TODO add parameter
        packet->insertAtBack(ethernetFcs);
    }

    send(packet, "lowerLayerOut");
}

void EtherGPtp::processPdelayReq(const GPtpPdelayReq* gptp)
{
    receivedTimeResponder = clockGptp->getClockTime(); // simTime();

    if (NULL == selfMsgDelayResp)
        selfMsgDelayResp = new ClockEvent("selfMsgPdelayResp");

    scheduleClockEventAfter(PDelayRespInterval, selfMsgDelayResp);
}

void EtherGPtp::sendPdelayResp()
{
    auto packet = new Packet("GPtpPdelayResp");
    auto frame = makeShared<EthernetMacHeader>();
    frame->setDest(MacAddress::BROADCAST_ADDRESS);
    frame->setTypeOrLength(ETHERTYPE_GPTP);

    auto gptp = makeShared<GPtpPdelayResp>();
    gptp->setSentTime(clockGptp->getClockTime());
    gptp->setRequestReceiptTimestamp(receivedTimeResponder);
    packet->insertAtFront(gptp);
    packet->insertAtFront(frame);

    B paddingLength = MIN_ETHERNET_FRAME_BYTES - ETHER_FCS_BYTES - packet->getDataLength();
    if (paddingLength > B(0)) {
        const auto& ethPadding = makeShared<EthernetPadding>();
        ethPadding->setChunkLength(paddingLength);
        packet->insertAtBack(ethPadding);
    }

    if (withFcs) {
        const auto& ethernetFcs = makeShared<EthernetFcs>();
        ethernetFcs->setFcsMode(FcsMode::FCS_DECLARED_CORRECT);     //TODO add parameter
        packet->insertAtBack(ethernetFcs);
    }

    send(packet, "lowerLayerOut");
    sendPdelayRespFollowUp();
}

void EtherGPtp::sendPdelayRespFollowUp()
{
    auto packet = new Packet("GPtpPdelayRespFollowUp");
    auto frame = makeShared<EthernetMacHeader>();
    frame->setDest(MacAddress::BROADCAST_ADDRESS);
    frame->setTypeOrLength(ETHERTYPE_GPTP);

    auto gptp = makeShared<GPtpPdelayRespFollowUp>();
    gptp->setSentTime(clockGptp->getClockTime());    //  simTime()
    gptp->setResponseOriginTimestamp(receivedTimeResponder + (clocktime_t)PDelayRespInterval);
    packet->insertAtFront(gptp);
    packet->insertAtFront(frame);

    B paddingLength = MIN_ETHERNET_FRAME_BYTES - ETHER_FCS_BYTES - packet->getDataLength();
    if (paddingLength > B(0)) {
        const auto& ethPadding = makeShared<EthernetPadding>();
        ethPadding->setChunkLength(paddingLength);
        packet->insertAtBack(ethPadding);
    }

    if (withFcs) {
        const auto& ethernetFcs = makeShared<EthernetFcs>();
        ethernetFcs->setFcsMode(FcsMode::FCS_DECLARED_CORRECT);     //TODO add parameter
        packet->insertAtBack(ethernetFcs);
    }

    send(packet, "lowerLayerOut");
}

/********************************/
/* Slave port related functions */
/********************************/

void EtherGPtp::slavePort(cMessage *msg)
{
    if (msg->isSelfMessage())
    {
        if(selfMsgDelayReq == msg)
        {
            sendPdelayReq();
            scheduleClockEventAfter(pdelayInterval, selfMsgDelayReq);
        }
    }
    else if(msg->arrivedOn("lowerLayerIn"))
    {
        auto packet = check_and_cast<Packet *>(msg);
        const auto& ethHdr = packet->peekAtFront<EthernetMacHeader>();
        if (ethHdr->getTypeOrLength() == ETHERTYPE_GPTP) {
            auto gptpBase = packet->peekAt<GPtpBase>(packet->getFrontOffset() + ethHdr->getChunkLength());
            switch (gptpBase->getTypeCode()) {
                case GPTPTYPE_SYNC:
                    processSync(check_and_cast<const GPtpSync *>(gptpBase.get()));
                    delete msg;
                    break;
                case GPTPTYPE_FOLLOW_UP:
                    processFollowUp(check_and_cast<const GPtpFollowUp *>(gptpBase.get()));
                    // Send a request to send Sync message
                    // through other gPtp Ethernet interfaces
                    tableGptp->handleGptpCall(requestMsg->dup());
                    delete msg;
                    break;
                case GPTPTYPE_PDELAY_RESP:
                    processPdelayResp(check_and_cast<const GPtpPdelayResp *>(gptpBase.get()));
                    delete msg;
                    break;
                case GPTPTYPE_PDELAY_RESP_FOLLOW_UP:
                    processPdelayRespFollowUp(check_and_cast<const GPtpPdelayRespFollowUp *>(gptpBase.get()));
                    delete msg;
                    break;
                default:
                    send(msg, "upperLayerOut");
                    break;
            }
        }
        else {
            // Forward message to upperLayerOut gate since packet is not gPtp
            send(msg, "upperLayerOut");
        }
    }
    else if (msg->arrivedOn("upperLayerIn")) {
        // Forward message to lowerLayerOut gate because the message from upper layer doesn't need to be touched
        // and we are interested in only message from lowerLayerIn
        send(msg, "lowerLayerOut");
    }
}

void EtherGPtp::sendPdelayReq()
{
    auto packet = new Packet("GPtpPdelayReq");
    auto frame = makeShared<EthernetMacHeader>();
    frame->setDest(MacAddress::BROADCAST_ADDRESS);
    frame->setTypeOrLength(ETHERTYPE_GPTP);

    auto gptp = makeShared<GPtpPdelayReq>();
    gptp->setSentTime(clockGptp->getClockTime());
    gptp->setOriginTimestamp(clockGptp->getClockTime());
    packet->insertAtFront(gptp);
    packet->insertAtFront(frame);

    B paddingLength = MIN_ETHERNET_FRAME_BYTES - ETHER_FCS_BYTES - packet->getDataLength();
    if (paddingLength > B(0)) {
        const auto& ethPadding = makeShared<EthernetPadding>();
        ethPadding->setChunkLength(paddingLength);
        packet->insertAtBack(ethPadding);
    }

    if (withFcs) {
        const auto& ethernetFcs = makeShared<EthernetFcs>();
        ethernetFcs->setFcsMode(FcsMode::FCS_DECLARED_CORRECT);     //TODO add parameter
        packet->insertAtBack(ethernetFcs);
    }

    send(packet, "lowerLayerOut");
    transmittedTimeRequester = clockGptp->getClockTime();
}

void EtherGPtp::processSync(const GPtpSync* gptp)
{
    clocktime_t sentTimeSync = gptp->getOriginTimestamp();
    clocktime_t residenceTime = clockGptp->getClockTime() - tableGptp->getReceivedTimeAtHandleMessage();
    receivedTimeSyncBeforeSync = clockGptp->getClockTime();

    /************** Time synchronization *****************************************
     * Local time is adjusted using peer delay, correction field, residence time *
     * and packet transmission time based departure time of Sync message from GM *
     *****************************************************************************/
    int bits = (MAC_HEADER + GPTP_SYNC_PACKET_SIZE + CRC_CHECKSUM + 2) * 8;

    clocktime_t packetTransmissionTime = (clocktime_t)(bits / nic->getDatarate());

    clockGptp->setClockTime(sentTimeSync + tableGptp->getPeerDelay() + tableGptp->getCorrectionField() + residenceTime + packetTransmissionTime);

    receivedTimeSyncAfterSync = clockGptp->getClockTime();
    tableGptp->setReceivedTimeSync(receivedTimeSyncAfterSync);

    // adjust local timestamps, too
    transmittedTimeRequester += receivedTimeSyncAfterSync - receivedTimeSyncBeforeSync;

    /************** Rate ratio calculation *************************************
     * It is calculated based on interval between two successive Sync messages *
     ***************************************************************************/
    clocktime_t neighborDrift = gptp->getLocalDrift();
    clocktime_t rateRatio = (neighborDrift + syncInterval)/(getCalculatedDrift(clockGptp, syncInterval) + syncInterval);

    EV_INFO << "############## SYNC #####################################"<< endl;
    EV_INFO << "RECEIVED TIME AFTER SYNC - " << receivedTimeSyncAfterSync << endl;
    EV_INFO << "RECEIVED SIM TIME        - " << simTime() << endl;
    EV_INFO << "ORIGIN TIME SYNC         - " << sentTimeSync << endl;
    EV_INFO << "RESIDENCE TIME           - " << residenceTime << endl;
    EV_INFO << "CORRECTION FIELD         - " << tableGptp->getCorrectionField() << endl;
    EV_INFO << "PROPAGATION DELAY        - " << tableGptp->getPeerDelay() << endl;
    EV_INFO << "TRANSMISSION TIME        - " << packetTransmissionTime << endl;

    // Transmission time of 2 more bytes is going here
    // in mac layer? or in our implementation?
    EV_INFO << "TIME DIFFERENCE TO STIME - " << receivedTimeSyncAfterSync - clockGptp->getClockTime() << endl;

    tableGptp->setRateRatio(rateRatio);
    vRateRatio.record(CLOCKTIME_AS_SIMTIME(rateRatio));
    vLocalTime.record(CLOCKTIME_AS_SIMTIME(receivedTimeSyncAfterSync));
    vMasterTime.record(CLOCKTIME_AS_SIMTIME(sentTimeSync));
    vTimeDifference.record(CLOCKTIME_AS_SIMTIME(receivedTimeSyncBeforeSync - sentTimeSync - tableGptp->getPeerDelay()));
}

void EtherGPtp::processFollowUp(const GPtpFollowUp* gptp)
{
    tableGptp->setReceivedTimeFollowUp(clockGptp->getClockTime());
    tableGptp->setOriginTimestamp(gptp->getPreciseOriginTimestamp());
    tableGptp->setCorrectionField(gptp->getCorrectionField());

    /************* Time difference to Grand master *******************************************
     * Time difference before synchronize local time and after synchronization of local time *
     *****************************************************************************************/
    int bits = (MAC_HEADER + GPTP_SYNC_PACKET_SIZE + CRC_CHECKSUM + 2) * 8;

    clocktime_t packetTransmissionTime = (clocktime_t)(bits / nic->getDatarate());

    clocktime_t timeDifferenceAfter  = receivedTimeSyncAfterSync - tableGptp->getOriginTimestamp() - tableGptp->getPeerDelay() - tableGptp->getCorrectionField() - packetTransmissionTime;
    clocktime_t timeDifferenceBefore = receivedTimeSyncBeforeSync - tableGptp->getOriginTimestamp() - tableGptp->getPeerDelay() - tableGptp->getCorrectionField() - packetTransmissionTime;
    vTimeDifferenceGMafterSync.record(CLOCKTIME_AS_SIMTIME(timeDifferenceAfter));
    vTimeDifferenceGMbeforeSync.record(CLOCKTIME_AS_SIMTIME(timeDifferenceBefore));

    EV_INFO << "############## FOLLOW_UP ################################"<< endl;
    EV_INFO << "RECEIVED TIME AFTER SYNC - " << receivedTimeSyncAfterSync << endl;
    EV_INFO << "ORIGIN TIME SYNC         - " << tableGptp->getOriginTimestamp() << endl;
    EV_INFO << "CORRECTION FIELD         - " << tableGptp->getCorrectionField() << endl;
    EV_INFO << "PROPAGATION DELAY        - " << tableGptp->getPeerDelay() << endl;
    EV_INFO << "TRANSMISSION TIME        - " << packetTransmissionTime << endl;
    EV_INFO << "TIME DIFFERENCE TO GM    - " << timeDifferenceAfter << endl;
    EV_INFO << "TIME DIFFERENCE TO GM BEF- " << timeDifferenceBefore << endl;

//    int bits = (MAC_HEADER + FOLLOW_UP_PACKET_SIZE + CRC_CHECKSUM) * 8;
//    clocktime_t packetTransmissionTime = (clocktime_t)(bits / nic->getDatarate());
//    vTimeDifferenceGMafterSync.record(receivedTimeSyncAfterSync - simTime() + FollowUpInterval + packetTransmissionTime + tableGptp->getPeerDelay());
//    vTimeDifferenceGMbeforeSync.record(receivedTimeSyncBeforeSync - simTime() + FollowUpInterval + packetTransmissionTime + tableGptp->getPeerDelay());
}

void EtherGPtp::processPdelayResp(const GPtpPdelayResp* gptp)
{
    receivedTimeRequester = clockGptp->getClockTime();        // simTime();
    receivedTimeResponder = gptp->getRequestReceiptTimestamp();
    transmittedTimeResponder = gptp->getSentTime();
}

void EtherGPtp::processPdelayRespFollowUp(const GPtpPdelayRespFollowUp* gptp)
{
    /************* Peer delay measurement ********************************************
     * It doesn't contain packet transmission time which is equal to (byte/datarate) *
     * on responder side, pdelay_resp is scheduled using PDelayRespInterval time.    *
     * PDelayRespInterval needs to be deducted as well as packet transmission time   *
     *********************************************************************************/
    int bits = (MAC_HEADER + GPTP_PDELAY_RESP_PACKET_SIZE + CRC_CHECKSUM) * 8;

    clocktime_t packetTransmissionTime = (clocktime_t)(bits / nic->getDatarate());

    peerDelay = (tableGptp->getRateRatio().dbl() * (receivedTimeRequester.dbl() - transmittedTimeRequester.dbl()) + transmittedTimeResponder.dbl() - receivedTimeResponder.dbl()) / 2
            - PDelayRespInterval - packetTransmissionTime;

    EV_INFO << "transmittedTimeRequester - " << transmittedTimeRequester << endl;
    EV_INFO << "transmittedTimeResponder - " << transmittedTimeResponder << endl;
    EV_INFO << "receivedTimeRequester    - " << receivedTimeRequester << endl;
    EV_INFO << "receivedTimeResponder    - " << receivedTimeResponder << endl;
    EV_INFO << "packetTransmissionTime   - " << packetTransmissionTime << endl;
    EV_INFO << "PEER DELAY               - " << peerDelay << endl;

    tableGptp->setPeerDelay(peerDelay);
    vPeerDelay.record(CLOCKTIME_AS_SIMTIME(peerDelay));
}

}

