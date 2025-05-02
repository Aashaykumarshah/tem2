#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "emulator.h"
#include "sr.h"

#define RTT 16.0
#define WINDOWSIZE 6
#define SEQSPACE 12 /* 2 * WINDOWSIZE (standard SR rule) */
#define NOTINUSE (-1)

struct pkt buffer[SEQSPACE];
bool acked[SEQSPACE];
bool sent[SEQSPACE];
float send_times[SEQSPACE];

int A_base = 0;
int A_nextseqnum = 0;

int B_expected = 0;
struct pkt B_buffer[SEQSPACE];
bool B_valid[SEQSPACE];

int current_time = 0;

int ComputeChecksum(struct pkt packet) {
    int checksum = packet.seqnum + packet.acknum;
    int i;
    for (i = 0; i < 20; i++)
        checksum += packet.payload[i];
    return checksum;
}

bool IsCorrupted(struct pkt packet) {
    return ComputeChecksum(packet) != packet.checksum;
}

void A_output(struct msg message) {
    int i;
    struct pkt p;

    if (((A_nextseqnum - A_base + SEQSPACE) % SEQSPACE) >= WINDOWSIZE) {
        if (TRACE > 0)
            printf("----A: New message arrives, send window is full\n");
        window_full++;
        return;
    }

    p.seqnum = A_nextseqnum;
    p.acknum = NOTINUSE;
    for (i = 0; i < 20; i++)
        p.payload[i] = message.data[i];
    p.checksum = ComputeChecksum(p);

    buffer[A_nextseqnum] = p;
    acked[A_nextseqnum] = false;
    sent[A_nextseqnum] = true;
    send_times[A_nextseqnum] = current_time;

    if (TRACE > 0)
        printf("Sending packet %d to layer 3\n", p.seqnum);
    tolayer3(A, p);
    starttimer(A, RTT);

    A_nextseqnum = (A_nextseqnum + 1) % SEQSPACE;
}

void A_input(struct pkt packet) {
    int acknum;
    int i;
    bool pending = false;

    if (IsCorrupted(packet)) {
        if (TRACE > 0)
            printf("----A: corrupted ACK is received, do nothing!\n");
        return;
    }

    if (TRACE > 0)
        printf("----A: uncorrupted ACK %d is received\n", packet.acknum);
    total_ACKs_received++;

    acknum = packet.acknum;
    if (!acked[acknum]) {
        new_ACKs++;
        acked[acknum] = true;

        while (acked[A_base]) {
            A_base = (A_base + 1) % SEQSPACE;
        }

        stoptimer(A);
        for (i = 0; i < SEQSPACE; i++) {
            if (sent[i] && !acked[i]) {
                pending = true;
                break;
            }
        }
        if (pending)
            starttimer(A, RTT);
    } else {
        if (TRACE > 0)
            printf("----A: duplicate ACK received, do nothing!\n");
    }
}

void A_timerinterrupt(void) {
    int i;

    if (TRACE > 0)
        printf("----A: time out,resend packets!\n");

    stoptimer(A);
    for (i = 0; i < SEQSPACE; i++) {
        if (sent[i] && !acked[i]) {
            if (TRACE > 0)
                printf("---A: resending packet %d\n", buffer[i].seqnum);
            tolayer3(A, buffer[i]);
            packets_resent++;
            send_times[i] = current_time;
        }
    }
    starttimer(A, RTT);
}

void A_init(void) {
    int i;
    A_base = 0;
    A_nextseqnum = 0;
    for (i = 0; i < SEQSPACE; i++) {
        acked[i] = false;
        sent[i] = false;
        send_times[i] = 0;
    }
}

void B_input(struct pkt packet) {
    struct pkt ackpkt;
    int seq = packet.seqnum;
    int i;

    if (!IsCorrupted(packet) && ((seq - B_expected + SEQSPACE) % SEQSPACE) < WINDOWSIZE) {
        if (TRACE > 0)
            printf("----B: packet %d is correctly received, send ACK!\n", seq);

        if (!B_valid[seq]) {
            for (i = 0; i < 20; i++)
                B_buffer[seq].payload[i] = packet.payload[i];
            B_valid[seq] = true;
            B_buffer[seq].seqnum = seq;
        }

        while (B_valid[B_expected]) {
            tolayer5(B, B_buffer[B_expected].payload);
            B_valid[B_expected] = false;
            B_expected = (B_expected + 1) % SEQSPACE;
            packets_received++;
        }
        ackpkt.acknum = seq;
    } else {
        if (TRACE > 0)
            printf("----B: packet corrupted or not expected sequence number, resend ACK!\n");
        ackpkt.acknum = (B_expected - 1 + SEQSPACE) % SEQSPACE;
    }

    ackpkt.seqnum = 0;
    for (i = 0; i < 20; i++) ackpkt.payload[i] = '0';
    ackpkt.checksum = ComputeChecksum(ackpkt);
    tolayer3(B, ackpkt);
}

void B_init(void) {
    int i;
    B_expected = 0;
    for (i = 0; i < SEQSPACE; i++) {
        B_valid[i] = false;
    }
}

void B_output(struct msg message) {}
void B_timerinterrupt(void) {}
