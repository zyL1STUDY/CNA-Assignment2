#include <stdio.h>
#include "emulator.h"
#include "sr.h"
extern float time;

/*Protocol Configuration*/
#define RTT 16.0
#define WINDOWSIZE 6
#define SEQSPACE 12
#define NOTINUSE (-1)

/*Checksum Functions*/
int ComputeChecksum(struct pkt packet) {
    int i;
    
        int checksum = packet.seqnum + packet.acknum;
    
    for (i = 0; i < 20; i++) {
        checksum += (int)(packet.payload[i]);
    }
    return checksum;
}

int IsCorrupted(struct pkt packet) {
    return packet.checksum != ComputeChecksum(packet);
}

/*Sender State*/
static struct pkt window[SEQSPACE];
static int acked[SEQSPACE];
static float timer_expiry[SEQSPACE];
static int base = 0;
static int nextseqnum = 0;
static int timer_active = 0;

/*A_output*/
void A_output(struct msg message) {
    struct pkt pkt;
    int i;

    if (((nextseqnum + SEQSPACE - base) % SEQSPACE) >= WINDOWSIZE) {
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

    if (TRACE > 0) printf("----A: sent packet %d\n", pkt.seqnum);
    tolayer3(A, pkt);
    timer_expiry[nextseqnum] = time + RTT;

    if (!timer_active) {
        starttimer(A, RTT);
        timer_active = 1;
    }

    nextseqnum = (nextseqnum + 1) % SEQSPACE;
}

/*A_input*/
void A_input(struct pkt packet) {
    int ack;
    int i;
    int seq;

    if (IsCorrupted(packet)) {
        if (TRACE > 0) printf("----A: received corrupted ACK\n");
        return;
    }

        ack = packet.acknum;
    if (TRACE > 0) printf("----A: ACK %d received and marked\n", ack);

    if (!acked[ack]) {
        acked[ack] = 1;
        new_ACKs++;
        total_ACKs_received++;
    }

    /*Restart timer for the next outstanding packet*/
    stoptimer(A);
    timer_active = 0;
    for (i = 0; i < SEQSPACE; i++) {
        seq = (base + i) % SEQSPACE;
        if (!acked[seq] && timer_expiry[seq] > time) {
            starttimer(A, timer_expiry[seq] - time);
            timer_active = 1;
            break;
        }
    }

    /*slide window*/
    while (acked[base]) {
        base = (base + 1) % SEQSPACE;
    }
}

/*A_timerinterrupt*/
void A_timerinterrupt(void) {
    int i;
    
    if (TRACE > 0) printf("----A: timeout event triggered\n");
    timer_active = 0;

    
    for (i = 0; i < SEQSPACE; i++) {
        int seq = (base + i) % SEQSPACE;
        if (!acked[seq] && time >= timer_expiry[seq]) {
            tolayer3(A, window[seq]);
            packets_resent++;
            timer_expiry[seq] = time + RTT;
            if (!timer_active) {
                starttimer(A, RTT);
                timer_active = 1;
            }
        }
    }
}

/*A_init*/
void A_init(void) {
    int i;
    for (i = 0; i < SEQSPACE; i++) {
        acked[i] = 0;
        timer_expiry[i] = 0.0;
    }
    base = 0;
    nextseqnum = 0;
    timer_active = 0;
}

/*Receiver State*/
static struct pkt recv_pkt[SEQSPACE];
static int received[SEQSPACE];
static int expected = 0;

/*B_input*/
void B_input(struct pkt packet) {
    int i;
    
    
    int seq = packet.seqnum;
    struct pkt ackpkt;

    if (IsCorrupted(packet)) {
        if (TRACE > 0) printf("----B: received corrupted packet\n");
        return;
    }

    if (!received[seq]) {
        recv_pkt[seq].seqnum = packet.seqnum;
        recv_pkt[seq].acknum = packet.acknum;
        recv_pkt[seq].checksum = packet.checksum;
        for (i = 0; i < 20; i++) {
            recv_pkt[seq].payload[i] = packet.payload[i];
        }
        received[seq] = 1;
        if (TRACE > 0) printf("----B: buffered packet %d\n", seq);
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
    if (TRACE > 0) printf("----B: sent ACK %d\n", ackpkt.acknum);
}

/*B_init*/
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
