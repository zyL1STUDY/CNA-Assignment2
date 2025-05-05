#include <stdio.h>
#include <string.h> 
#include "emulator.h"
#include "sr.h"

#define RTT 16.0
#define WINDOWSIZE 6
#define SEQSPACE 12
#define NOTINUSE -1
#define BUFFER_INDEX(seqnum) ((seqnum) % SEQSPACE)

static struct pkt recv_buffer[SEQSPACE];
static int       recv_has[SEQSPACE];
static int       recv_expected;

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
        if (TRACE > 0)
            printf("----A: New message arrives, send window is full\n");
        window_full++;
        return;
    }
    if (TRACE > 0)
        printf("----A: New message arrives, send window is not full, send new messge to layer3!\n");


    pkt.seqnum = nextseqnum;
    pkt.acknum = NOTINUSE;
    for (i = 0; i < 20; i++) {
        pkt.payload[i] = message.data[i];
    }
    pkt.checksum = ComputeChecksum(pkt);

    window[BUFFER_INDEX(pkt.seqnum)] = pkt;
    acked[BUFFER_INDEX(pkt.seqnum)] = 0;

    if (TRACE > 0) printf("Sending packet %d to layer 3\n", pkt.seqnum);
    tolayer3(A, pkt);

    if (!timer_active) {
        starttimer(A, RTT);
        timer_active = 1;
    }

    nextseqnum = (nextseqnum + 1) % SEQSPACE;
}

void A_input(struct pkt packet) {
    int ack         = packet.acknum;
    int win_start   = base;
    int win_end     = (base + WINDOWSIZE) % SEQSPACE;
    int in_window;
    
    /* determine if ack is in [base, base+WINDOWSIZE) */
    
    if (IsCorrupted(packet)) {
        if (TRACE>0) printf("----A: corrupted ACK is received, do nothing!\n");
        return;
    }
    
    if (TRACE>0) 
        printf("----A: uncorrupted ACK %d is received\n", ack);
    total_ACKs_received++;

    if (win_start < win_end)
        in_window = (ack >= win_start && ack < win_end);
    else
        in_window = (ack >= win_start || ack < win_end);

    if (in_window && !acked[ack]) {
            acked[ack] = 1;
            new_ACKs++;
            if (TRACE>0) 
                printf("----A: ACK %d is not a duplicate\n", ack);
            stoptimer(A);
            timer_active = 0;

            /* slide base */
            while (acked[base]) {
                acked[base] = 0;
                base = (base + 1) % SEQSPACE;
            }
            if (base != nextseqnum) {
                starttimer(A, RTT);
            }
        } 
        else if (in_window && acked[ack]) {
        /* 重复 ACK */
            if (TRACE>0) 
                printf("----A: ACK %d is a duplicate, do nothing!\n", ack);
    }
    /* out-of-window 的 ACK 什么也不做 */
}

void A_timerinterrupt(void) {
    int i;
    if (base == nextseqnum) {
        timer_active = 0;
        return;
    }
    if (TRACE > 0) printf("----A: time out,resend packets!\n");
    for (i = 0; i < WINDOWSIZE; i++) {
        int seq = (base + i) % SEQSPACE;
        if (!acked[BUFFER_INDEX(seq)]) {
            if (TRACE > 0)
                printf("---A: resending packet %d\n", seq);
            tolayer3(A, window[BUFFER_INDEX(seq)]);
            packets_resent++;
            starttimer(A, RTT);
            timer_active = 1;
            return;
        }
    }
    timer_active = 0;
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
static int received[SEQSPACE];
static int expected = 0;

void B_input(struct pkt packet) {
    int seq = packet.seqnum;
    struct pkt ackpkt;

    if (IsCorrupted(packet)) {
        if (TRACE > 0)
            printf("----B: received corrupted packet, drop it\n");
        return;
    }

    ackpkt.seqnum  = NOTINUSE;
    ackpkt.acknum  = seq;
    memset(ackpkt.payload, '0', sizeof ackpkt.payload);
    ackpkt.checksum = ComputeChecksum(ackpkt);
    tolayer3(B, ackpkt);
    if (TRACE > 0)
        printf("----B: sent ACK %d\n", seq);

    int win_end = (recv_expected + WINDOWSIZE) % SEQSPACE;
    int in_window;
    if (recv_expected < win_end) {
        in_window = (seq >= recv_expected && seq < win_end);
    } else {
        in_window = (seq >= recv_expected || seq < win_end);
    }

    if (in_window && !recv_has[seq]) {
        recv_buffer[seq] = packet;   
        recv_has[seq]   = 1;         
        if (TRACE > 0)
            printf("----B: buffered packet %d\n", seq);
    }

    while (recv_has[recv_expected]) {
        tolayer5(B, recv_buffer[recv_expected].payload);
        packets_received++;
        if (TRACE > 0)
            printf("----B: delivered packet %d to application\n", recv_expected);
        recv_has[recv_expected] = 0;
        recv_expected = (recv_expected + 1) % SEQSPACE;
    }
}


void B_timerinterrupt(void) { 
    /* not used */ 
}
