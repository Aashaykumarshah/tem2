#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "emulator.h"
#include "sr.h"

#define RTT  16.0
#define WINDOWSIZE 6
#define SEQSPACE 7
#define NOTINUSE (-1)
#define MAXBUFFER 1000

int ComputeChecksum(struct pkt packet) {
  int checksum = packet.seqnum + packet.acknum;
  int i;
  for (i = 0; i < 20; i++) checksum += (int)(packet.payload[i]);
  return checksum;
}

bool IsCorrupted(struct pkt packet) {
  return packet.checksum != ComputeChecksum(packet);
}

/***************** SENDER (A) SIDE ******************/

static struct pkt A_buffer[SEQSPACE];
static bool A_acknowledged[SEQSPACE];
static int A_base, A_nextseqnum;

void A_init(void) {
  int i;
  A_nextseqnum = 0;
  A_base = 0;
  for (i = 0; i < SEQSPACE; i++) {
    A_acknowledged[i] = false;
  }
}

void A_output(struct msg message) {
  int i;
  if ((A_nextseqnum - A_base + SEQSPACE) % SEQSPACE < WINDOWSIZE) {
    struct pkt sendpkt;
    sendpkt.seqnum = A_nextseqnum;
    sendpkt.acknum = NOTINUSE;
    for (i = 0; i < 20; i++) sendpkt.payload[i] = message.data[i];
    sendpkt.checksum = ComputeChecksum(sendpkt);

    A_buffer[A_nextseqnum] = sendpkt;
    A_acknowledged[A_nextseqnum] = false;

    tolayer3(A, sendpkt);
    if (A_base == A_nextseqnum) {
      starttimer(A, RTT);
    }

    A_nextseqnum = (A_nextseqnum + 1) % SEQSPACE;
  } else {
    if (TRACE > 0) printf("----A: Window full, message dropped\n");
  }
}

void A_input(struct pkt packet) {
  int acknum;
  if (!IsCorrupted(packet)) {
    acknum = packet.acknum;
    A_acknowledged[acknum] = true;

    while (A_acknowledged[A_base]) {
      A_acknowledged[A_base] = false;
      A_base = (A_base + 1) % SEQSPACE;
    }

    stoptimer(A);
    if (A_base != A_nextseqnum) {
      starttimer(A, RTT);
    }
  }
}

void A_timerinterrupt(void) {
  int i;
  for (i = 0; i < SEQSPACE; i++) {
    if (!A_acknowledged[i] &&
        (i - A_base + SEQSPACE) % SEQSPACE < WINDOWSIZE) {
      tolayer3(A, A_buffer[i]);
    }
  }
  starttimer(A, RTT);
}

/***************** RECEIVER (B) SIDE ******************/

static struct pkt B_buffer[SEQSPACE];
static bool B_received[SEQSPACE];
static int B_expectedseqnum;

void B_init(void) {
  int i;
  B_expectedseqnum = 0;
  for (i = 0; i < SEQSPACE; i++) {
    B_received[i] = false;
  }
}

void B_input(struct pkt packet) {
  int seq;
  int i;
  struct pkt ackpkt;

  if (!IsCorrupted(packet)) {
    seq = packet.seqnum;

    if (!B_received[seq]) {
      B_buffer[seq] = packet;
      B_received[seq] = true;
    }

    while (B_received[B_expectedseqnum]) {
      tolayer5(B, B_buffer[B_expectedseqnum].payload);
      B_received[B_expectedseqnum] = false;
      B_expectedseqnum = (B_expectedseqnum + 1) % SEQSPACE;
    }

    ackpkt.seqnum = 0;
    ackpkt.acknum = seq;
    for (i = 0; i < 20; i++) ackpkt.payload[i] = '0';
    ackpkt.checksum = ComputeChecksum(ackpkt);
    tolayer3(B, ackpkt);
  }
}

void B_output(struct msg message) {
    /* Not used */
}

void B_timerinterrupt(void) {
    /* Not used */
}
