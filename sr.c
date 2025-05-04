extern float time;
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "emulator.h"
#include "sr.h"

// ========== 协议参数定义 / Protocol Configuration ==========
#define RTT 16.0             // 模拟器要求的超时时间 / Timeout interval
#define WINDOWSIZE 10        // 发送/接收窗口大小 / Sender & Receiver window size
#define SEQSPACE 32          // 序列号空间，应 ≥ 2 * WINDOWSIZE / Sequence space (should ≥ 2 * window size)
#define NOTINUSE -1          // 占位符 / Placeholder value

// ========== 公用校验函数 / Common Utility ==========
int ComputeChecksum(struct pkt packet) {
    // 计算校验和，用于检测数据包是否被损坏
    // Compute packet checksum for corruption detection
    int checksum = packet.seqnum + packet.acknum;
    for (int i = 0; i < 20; i++) {
        checksum += packet.payload[i];
    }
    return checksum;
}

bool IsCorrupted(struct pkt packet) {
    // 判断数据包是否损坏
    // Return true if packet is corrupted
    return ComputeChecksum(packet) != packet.checksum;
}

// ========== A 端发送方变量 / Sender State Variables ==========
static struct pkt send_buffer[SEQSPACE];     // 缓存所有未确认的数据包 / Send buffer
static bool acked[SEQSPACE];                 // 标记每个包是否已被确认 / ACK received flags
static float timer_expiry[SEQSPACE];         // 模拟每个包的超时时间 / Simulated per-packet timeout

static int base = 0;                         // 窗口起始序号 / Base of sender window
static int nextseqnum = 0;                   // 下一个可发送序号 / Next sequence number to send
static bool timer_active = false;            // 当前是否有运行中的计时器 / Whether a timer is active

// ========== A_output: 应用层消息到达 / New message from layer 5 ==========
void A_output(struct msg message) {
    // 如果窗口已满，则丢弃 / Drop if window full
    if ((nextseqnum - base + SEQSPACE) % SEQSPACE >= WINDOWSIZE) {
        if (TRACE > 0) printf("----A: window full, drop message\n");
        window_full++;
        return;
    }

    // 构造数据包 / Construct packet
    struct pkt pkt;
    pkt.seqnum = nextseqnum;
    pkt.acknum = NOTINUSE;
    for (int i = 0; i < 20; i++)
        pkt.payload[i] = message.data[i];
    pkt.checksum = ComputeChecksum(pkt);

    // 缓存并发送数据包 / Store & send packet
    send_buffer[nextseqnum] = pkt;
    acked[nextseqnum] = false;
    timer_expiry[nextseqnum] = time + RTT;

    tolayer3(A, pkt);
    if (TRACE > 0) printf("----A: sent packet %d\n", pkt.seqnum);

    if (!timer_active) {
        starttimer(A, RTT);
        timer_active = true;
    }

    nextseqnum = (nextseqnum + 1) % SEQSPACE;
}

// ========== A_input: 接收 ACK / Receive ACK ==========
void A_input(struct pkt packet) {
    if (IsCorrupted(packet)) {
        if (TRACE > 0) printf("----A: corrupted ACK received\n");
        return;
    }

    int ack = packet.acknum;

    if (!acked[ack]) {
        acked[ack] = true;
        if (TRACE > 0) printf("----A: ACK %d received and marked\n", ack);
        total_ACKs_received++;
        new_ACKs++;

        // 滑动窗口起始值 / Slide base if possible
        while (acked[base]) {
            base = (base + 1) % SEQSPACE;
        }

        stoptimer(A);

        // 重启最早未确认包的定时器 / Restart next earliest unacked timer
        for (int i = 0; i < SEQSPACE; i++) {
            int seq = (base + i) % SEQSPACE;
            if (!acked[seq] && timer_expiry[seq] > time) {
                starttimer(A, timer_expiry[seq] - time);
                timer_active = true;
                break;
            }
        }
    }
}

// ========== A_timerinterrupt: 超时重传 / Timeout handler ==========
void A_timerinterrupt(void) {
    if (TRACE > 0) printf("----A: timeout event triggered\n");
    timer_active = false;

    // 找到并重传最早超时的数据包 / Retransmit earliest timed-out packet
    for (int i = 0; i < SEQSPACE; i++) {
        int seq = (base + i) % SEQSPACE;
        if (!acked[seq] && time >= timer_expiry[seq]) {
            tolayer3(A, send_buffer[seq]);
            packets_resent++;
            if (TRACE > 0) printf("----A: retransmit packet %d\n", seq);

            timer_expiry[seq] = time + RTT;
            starttimer(A, RTT);
            timer_active = true;
            break;
        }
    }
}

// ========== A_init: 发送方初始化 / Sender Initialization ==========
void A_init(void) {
    for (int i = 0; i < SEQSPACE; i++) {
        acked[i] = false;
    }
    base = 0;
    nextseqnum = 0;
    timer_active = false;
}

// ========== B 端接收方变量 / Receiver State Variables ==========
static struct pkt recv_buffer[SEQSPACE];     // 接收缓存区 / Receive buffer
static bool received[SEQSPACE];              // 是否收到该序号 / Receive flags
static int expected_base = 0;                // 接收窗口 base / Expected in-order base

// ========== B_input: 接收数据包 / Receive data packet ==========
void B_input(struct pkt packet) {
    if (IsCorrupted(packet)) {
        if (TRACE > 0) printf("----B: corrupted packet received\n");
        return;
    }

    int seq = packet.seqnum;

    // 判断包是否在接收窗口内 / Check if in receiving window
    if ((seq - expected_base + SEQSPACE) % SEQSPACE < WINDOWSIZE) {
        if (!received[seq]) {
            recv_buffer[seq] = packet;
            received[seq] = true;
            packets_received++;
            if (TRACE > 0) printf("----B: buffered packet %d\n", seq);
        }

        // 从 base 开始顺序交付 / Deliver in-order packets
        while (received[expected_base]) {
            tolayer5(B, recv_buffer[expected_base].payload);
            received[expected_base] = false;
            expected_base = (expected_base + 1) % SEQSPACE;
        }
    } else {
        if (TRACE > 0) printf("----B: packet %d not in window, ignored\n", seq);
    }

    // 回复 ACK / Send ACK regardless
    struct pkt ackpkt;
    ackpkt.seqnum = 0;
    ackpkt.acknum = seq;
    for (int i = 0; i < 20; i++) ackpkt.payload[i] = '0';
    ackpkt.checksum = ComputeChecksum(ackpkt);
    tolayer3(B, ackpkt);
    if (TRACE > 0) printf("----B: sent ACK %d\n", seq);
}

// ========== B_init: 接收方初始化 / Receiver Initialization ==========
void B_init(void) {
    for (int i = 0; i < SEQSPACE; i++) {
        received[i] = false;
    }
    expected_base = 0;
}

// ========== 以下函数未启用，仅为接口保留 / Unused Functions (interface only) ==========
void B_output(struct msg message) {}
void B_timerinterrupt(void) {}

