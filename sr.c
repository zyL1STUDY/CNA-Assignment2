#include <stdio.h>
#include "emulator.h"
#include "sr.h"

#define RTT 16.0
#define WINDOWSIZE 6
#define SEQSPACE 12
#define NOTINUSE -1

/* ---------- Packet Utilities ---------- */
int ComputeChecksum(struct pkt packet) {
    int checksum = packet.seqnum + packet.acknum;
    int i;
    for (i = 0; i < 20; i++) {
        checksum += (int)(packet.payload[i]);
    }
    return checksum;
}

int IsCorrupted(struct pkt packet) {
    return packet.checksum != ComputeChecksum(packet);
}

/* ---------- Sender State ---------- */
static struct pkt window[SEQSPACE];
static int acked[SEQSPACE];
static int base = 0;
static int nextseqnum = 0;
static int timer_active = 0;

void A_output(struct msg message) {
    struct pkt pkt;
    int i;

    if (((nextseqnum - base + SEQSPACE) % SEQSPACE) >= WINDOWSIZE) {
        if (TRACE > 0) printf("----A: Window full, drop message\n");
        window_full++;
        return;
    }

    pkt.seqnum = nextseqnum;
    pkt.acknum = NOTINUSE;
    for (i = 0; i < 20; i++) {
        pkt.payload[i] = message.data[i];
    }
    pkt.checksum = ComputeChecksum(pkt);

    window[nextseqnum] = pkt;
    acked[nextseqnum] = 0;

    if (TRACE > 0) printf("----A: Sending packet %d\n", pkt.seqnum);
    tolayer3(A, pkt);

    if (!timer_active) {
        starttimer(A, RTT);
        timer_active = 1;
    }

    nextseqnum = (nextseqnum + 1) % SEQSPACE;
}

void A_input(struct pkt packet) {
    int ack;
    int i;

    if (IsCorrupted(packet)) {
        if (TRACE > 0) printf("----A: Corrupted ACK received\n");
        return;
    }
    ack = packet.acknum;
    if (!acked[ack]) {
        acked[ack] = 1;
        new_ACKs++;
        total_ACKs_received++;
    }

    while (acked[base]) {
        base = (base + 1) % SEQSPACE;
    }

    stoptimer(A);
    timer_active = 0;

    for (i = 0; i < WINDOWSIZE; i++) {
        int seq = (base + i) % SEQSPACE;
        if (!acked[seq]) {
            starttimer(A, RTT);
            timer_active = 1;
            break;
        }
    }
}

void A_timerinterrupt(void) {
    int i;

    if (TRACE > 0) printf("----A: Timer interrupt, resend earliest unacked packet\n");
    timer_active = 0;

    for (i = 0; i < WINDOWSIZE; i++) {
        int seq = (base + i) % SEQSPACE;
        if (!acked[seq]) {
            tolayer3(A, window[seq]);
            packets_resent++;
            starttimer(A, RTT);
            timer_active = 1;
            break;
        }
    }
}

void A_init(void) {
    int i;
    for (i = 0; i < SEQSPACE; i++) {
        acked[i] = 0;
    }
    base = 0;
    nextseqnum = 0;
    timer_active = 0;
}

/* ---------- Receiver State ---------- */
static struct pkt recv_pkt[SEQSPACE];
static int received[SEQSPACE];
static int expected = 0;

void B_input(struct pkt packet) {
    int seq;
    int i;
    struct pkt ackpkt;

    seq = packet.seqnum;

    if (IsCorrupted(packet)) {
        if (TRACE > 0) printf("----B: Corrupted packet\n");
        return;
    }

    if (!received[seq]) {
        recv_pkt[seq] = packet;
        received[seq] = 1;
        if (TRACE > 0) printf("----B: Buffered packet %d\n", seq);
    }

    while (received[expected]) {
        tolayer5(B, recv_pkt[expected].payload);
        packets_received++;
        received[expected] = 0;
        expected = (expected + 1) % SEQSPACE;
    }

    ackpkt.seqnum = NOTINUSE;
    ackpkt.acknum = seq;
    for (i = 0; i < 20; i++) ackpkt.payload[i] = '0';
    ackpkt.checksum = ComputeChecksum(ackpkt);
    tolayer3(B, ackpkt);

    if (TRACE > 0) printf("----B: Sent ACK %d\n", seq);
}

void B_init(void) {
    int i;
    for (i = 0; i < SEQSPACE; i++) {
        received[i] = 0;
    }
    expected = 0;
}

void B_output(struct msg message) { 
    /* not used */ 
}

void B_timerinterrupt(void) { 
    /* not used */ 
}
