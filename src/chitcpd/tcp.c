/*
 *  chiTCP - A simple, testable TCP stack
 *
 *  Implementation of the TCP protocol.
 *
 *  chiTCP follows a state machine approach to implementing TCP.
 *  This means that there is a handler function for each of
 *  the TCP states (CLOSED, LISTEN, SYN_RCVD, etc.). If an
 *  event (e.g., a packet arrives) while the connection is
 *  in a specific state (e.g., ESTABLISHED), then the handler
 *  function for that state is called, along with information
 *  about the event that just happened.
 *
 *  Each handler function has the following prototype:
 *
 *  int f(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event);
 *
 *  si is a pointer to the chiTCP server info. The functions in
 *       this file will not have to access the data in the server info,
 *       but this pointer is needed to call other functions.
 *
 *  entry is a pointer to the socket entry for the connection that
 *          is being handled. The socket entry contains the actual TCP
 *          data (variables, buffers, etc.), which can be extracted
 *          like this:
 *
 *            tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
 *
 *          Other than that, no other fields in "entry" should be read
 *          or modified.
 *
 *  event is the event that has caused the TCP thread to wake up. The
 *          list of possible events corresponds roughly to the ones
 *          specified in http://tools.ietf.org/html/rfc793#section-3.9.
 *          They are:
 *
 *            APPLICATION_CONNECT: Application has called socket_connect()
 *            and a three-way handshake must be initiated.
 *
 *            APPLICATION_SEND: Application has called socket_send() and
 *            there is unsent data in the send buffer.
 *
 *            APPLICATION_RECEIVE: Application has called socket_recv() and
 *            any received-and-acked data in the recv buffer will be
 *            collected by the application (up to the maximum specified
 *            when calling socket_recv).
 *
 *            APPLICATION_CLOSE: Application has called socket_close() and
 *            a connection tear-down should be initiated.
 *
 *            PACKET_ARRIVAL: A packet has arrived through the network and
 *            needs to be processed (RFC 793 calls this "SEGMENT ARRIVES")
 *
 *            TIMEOUT: A timeout (e.g., a retransmission timeout) has
 *            happened.
 *
 */

/*
 *  Copyright (c) 2013-2014, The University of Chicago
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or withsend
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of The University of Chicago nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software withsend specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY send OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "chitcp/log.h"
#include "chitcp/utils.h"
#include "chitcp/buffer.h"
#include "chitcp/chitcpd.h"
#include "serverinfo.h"
#include "connection.h"
#include "tcp.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * struct of server info to pass in the callback functions
*/
typedef struct arg_struct {
    serverinfo_t *si;
    chisocketentry_t *entry;
} arg_struct_t;

/*
 * raw_rtx_func - Callback function for rtx timer
 *
 * mt: pointer to multitimer
 *
 * st: pointer to singler timer
 *
 * args: pointer to the server info
 *
 * Returns: nothing
 */
void raw_rtx_func(multi_timer_t *mt, single_timer_t* st, void* args);

/*
 * rtx_queue_size - Returns the size of rtx_queue
 *
 * tcp_data: pointer to tcp_data
 *
 * Returns: size of the queue
 */
int rtx_queue_size(tcp_data_t *tcp_data);

/*
 * cmp_func - Compator for utlist INSERT_IN_ORDER
 *            Compare two packet's sequence number
 *
 * a: packet a
 *
 * b: packet b
 *
 * Returns: -1 if a is smaller, 1 if a is greater
 */
int cmp_func(out_order_packet_t *a, out_order_packet_t *b);

/*
 * max_func - Calculate the max of a and b
 *
 * a: number a
 *
 * b: number b
 *
 * Returns: a if a is greater, b if b is greater
 */
uint64_t max_func(uint64_t a, uint64_t b);

/*
 * insert_packet_to_rtx_queue - Insert a packet to rtx queue
 *
 * si: pointer to server information
 *
 * entry: pointer chisocketentry_t entry
 *
 * Returns: number of bytes sent
 */
void insert_packet_to_rtx_queue(serverinfo_t *si, chisocketentry_t *entry,
                                tcp_packet_t *send_packet)
{
    tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);
    /*  Managing the Retransmission Queue - Avoid adding pure ACK packets
        Managing the Timer Thread: prevent empty segment setting timer*/
    if(SEG_LEN(send_packet) == 0 && send_header->syn == 0
            && send_header->fin == 0) {
        return;
    }

    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    single_timer_t *single_timer;


    mt_get_timer_by_id(&tcp_data->mt, RETRANSMISSION, &single_timer);
    if(single_timer->active == false) {
        arg_struct_t *args = malloc(sizeof(arg_struct_t));
        args->si = si;
        args->entry = entry;
        mt_set_timer(&tcp_data->mt, RETRANSMISSION, tcp_data->RTO,
                     raw_rtx_func, (void *)args);
    }

    // insert the packet into rtx queue, with retransmission_cnt = 0
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    out_order_packet_t *cur_packet = malloc(sizeof(out_order_packet_t));
    cur_packet->next = NULL;
    cur_packet->packet = send_packet;
    cur_packet->time = now;
    cur_packet->retransmission_cnt = 0;
    DL_INSERT_INORDER(tcp_data->rtx_queue, cur_packet, cmp_func);
}


/*
 * raw_persist_func - Callback function for persist timer
 *
 * mt: pointer to multitimer
 *
 * st: pointer to singler timer
 *
 * args: pointer to the server info
 *
 * Returns: nothing
 */
void raw_persist_func(multi_timer_t *mt, single_timer_t* st, void* args);

/*
 * handle_persist_timeout - Decides wehter to send a probe segment
 *                          if persist timeout
 *
 * si: pointer to server information
 *
 * entry: pointer chisocketentry_t entry
 *
 * Returns: nothing
 */
void handle_persist_timeout(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    if(circular_buffer_count(&tcp_data->send) == 0 && tcp_data->probe_byte == NULL) {
        arg_struct_t *args = malloc(sizeof(arg_struct_t));
        args->si = si;
        args->entry = entry;
        mt_cancel_timer(&tcp_data->mt, PERSIST);
        mt_set_timer(&tcp_data->mt, PERSIST, tcp_data->RTO, raw_persist_func, (void *)args);
        return;
    }

    int incr_snd_nxt = 0;
    if(tcp_data->probe_byte == NULL) {
        /* No probe sent before, build a new one */
        int payload_len = 1;
        uint8_t *payload = malloc(payload_len * sizeof(uint8_t));
        circular_buffer_read(&tcp_data->send, payload, payload_len, FALSE);
        tcp_data->probe_byte = payload;
        incr_snd_nxt = 1;
    } else {
        /* A probe byte was sent, re-use that seq number */
        tcp_data->SND_NXT = tcp_data->SND_NXT - 1;
    }

    tcp_packet_t *send_packet = calloc(1, sizeof(tcp_packet_t));
    chitcpd_tcp_packet_create(entry, send_packet, tcp_data->probe_byte, 1);
    tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);
    send_header->ack = 1;
    send_header->seq = chitcp_htonl(tcp_data->SND_NXT);
    send_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
    send_header->win = chitcp_htons(tcp_data->RCV_WND);

    /*  Persist timer
        - Updating SND.NXT */
    tcp_data->SND_NXT = tcp_data->SND_NXT + 1;
    chitcpd_send_tcp_packet(si, entry, send_packet);
    free(send_packet);
}



/*
 * update_rto - RTT Estimation and update RTO
 *
 * si: pointer to server information
 *
 * entry: pointer chisocketentry_t entry
 *
 * sent_time: when the packet was ACK'ed
 *
 * Returns: nothing
 */
void update_rto(serverinfo_t *si, chisocketentry_t *entry, struct timespec sent_time)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    struct timespec now, res;
    clock_gettime(CLOCK_REALTIME, &now);
    timespec_subtract(&res, &now, &sent_time);
    uint64_t R = res.tv_sec * SECOND + res.tv_nsec;
    uint64_t K = 4;

    /* If no RTT samples are received before */
    if(tcp_data->NO_RTT == 1) {
        tcp_data->NO_RTT == 0;
        tcp_data->SRTT = R;
        tcp_data->RTTVAR = R / 2;
        tcp_data->RTO = tcp_data->SRTT + max_func(tcp_data->G, K * tcp_data->RTTVAR);
    } else {
        /* [Resolve item] 
            - changed alpha and beta to integers to represent the formula
            - RTTVAR <- (1 - beta) * RTTVAR + beta * |SRTT - R'|
            - SRTT <- (1 - alpha) * SRTT + alpha * R'
        */
        uint64_t alpha = 4;
        uint64_t beta = 8;
        uint64_t diff = (tcp_data->SRTT > R) ? tcp_data->SRTT - R : R - tcp_data->SRTT;
        tcp_data->RTTVAR = (beta - 1) * tcp_data->RTTVAR / beta +  diff / beta;
        tcp_data->SRTT = (alpha - 1) * tcp_data->SRTT / alpha + R / alpha;
        tcp_data->RTO = tcp_data->SRTT + max_func(tcp_data->G, K * tcp_data->RTTVAR);
    }

    if(tcp_data->RTO < 200 * MILLISECOND) {
        tcp_data->RTO = 200 * MILLISECOND;
    }

    /* If RTO bigger than 60 seconds, set to 60 seconds */
    if(tcp_data->RTO > (60 * SECOND)) {
        tcp_data->RTO = 60 * SECOND;
    }

    return;
}


/*
 * go_back_n - Go back and send n packets
 *
 * si: pointer to server information
 *
 * entry: pointer chisocketentry_t entry
 *
 * Returns: nothing
 */
void go_back_n(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    out_order_packet_t *elt, *tmp;

    int effective_window = tcp_data->SND_WND - (tcp_data->SND_NXT - tcp_data->SND_UNA);

    DL_FOREACH_SAFE(tcp_data->rtx_queue, elt, tmp) {
        if(SEG_SEQ(elt->packet) < tcp_data->SND_UNA) {
            DL_DELETE(tcp_data->rtx_queue, elt);
            free(elt->packet);
            continue;
        }

        chitcpd_send_tcp_packet(si, entry, elt->packet);
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        elt->time = now;
        elt->retransmission_cnt++;
    }
    arg_struct_t *args = malloc(sizeof(arg_struct_t));
    args->si = si;
    args->entry = entry;


    mt_cancel_timer(&tcp_data->mt, RETRANSMISSION);

    /* count any packets remain in rtx queue */
    int cnt = 0;
    DL_FOREACH_SAFE(tcp_data->rtx_queue, elt, tmp) {
        cnt ++;
    }
    if(cnt > 0) {
        /* only set timer when retransmission queue is not empty */
        mt_set_timer(&tcp_data->mt, RETRANSMISSION, tcp_data->RTO, raw_rtx_func, (void *)args);
    }

    return;
}


/*
 * single_send - Send a single packet and add to rtx_queue
 *
 * si: pointer to server information
 *
 * entry: pointer chisocketentry_t entry
 *
 * payload_len: length of the payload for the packet
 *
 * Returns: nothing
 */
void single_send(serverinfo_t *si, chisocketentry_t *entry, int payload_len)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    tcp_packet_t *send_packet = calloc(1, sizeof(tcp_packet_t));
    uint8_t *payload = malloc(payload_len * sizeof(uint8_t));
    circular_buffer_read(&tcp_data->send, payload, payload_len, FALSE);
    chitcpd_tcp_packet_create(entry, send_packet, payload, payload_len);
    tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);
    send_header->ack = 1;
    send_header->seq = chitcp_htonl(tcp_data->SND_NXT);
    send_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
    send_header->win = chitcp_htons(tcp_data->RCV_WND);
    tcp_data->SND_NXT = tcp_data->SND_NXT + payload_len;
    chitcpd_send_tcp_packet(si, entry, send_packet);

    insert_packet_to_rtx_queue(si, entry, send_packet);
}

/*
 * batch_send - Sends all packets in the send buffer
 *
 * si: pointer to server information
 *
 * entry: pointer chisocketentry_t entry
 *
 * Returns: number of bytes sent
 */
int batch_send(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    int remaining = circular_buffer_count(&tcp_data->send);

    if(remaining == 0)
        return 0;

    int effective_window = tcp_data->SND_WND - (tcp_data->SND_NXT - tcp_data->SND_UNA);

    if(effective_window < remaining)
        remaining = effective_window;

    if(remaining == 0)
        return 0;

    int total_sent = remaining;

    while(remaining > 0) {
        if(circular_buffer_count(&tcp_data->send) == 0)
            break;

        int payload_len = TCP_MSS;
        if(remaining < TCP_MSS)
            payload_len = remaining;

        single_send(si, entry, payload_len);
        remaining = remaining - payload_len;
    }

    return total_sent;
}


/*
 * clean_rtx_queue - Remove old rtx packets and update rto.
 *
 * si: pointer to server information
 *
 * entry: pointer chisocketentry_t entry
 * 
 * p: the packet received
 *
 * Returns: number of rtx packets cleared
 */
int clean_rtx_queue (serverinfo_t *si, chisocketentry_t *entry,
    tcp_packet_t *p)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    out_order_packet_t *elt, *tmp;
    int cnt = 0;
    DL_FOREACH_SAFE(tcp_data->rtx_queue, elt, tmp) {
        if(SEG_SEQ(elt->packet) < SEG_ACK(p)) {
            cnt ++;
            if(elt->retransmission_cnt == 0) { //Excluded rtx packets
                update_rto(si, entry, elt->time);
            }
            DL_DELETE(tcp_data->rtx_queue, elt);
            free(elt->packet);
        }
    }
    return cnt;
}


/*
 * chitcpd_tcp_handle_packet - Handles a single arriving packet
 *
 * si: pointer to server information
 *
 * entry: pointer chisocketentry_t entry
 *
 * Returns: -1 if silently dropped packet; 1 if finished handling
 */
int chitcpd_tcp_handle_packet(serverinfo_t *si, chisocketentry_t *entry)
{
    if(entry->tcp_state == CLOSED)
        return -1;

    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    tcp_packet_t *p = NULL;
    pthread_mutex_lock(&tcp_data->lock_pending_packets);

    if(tcp_data->pending_packets) {
        p = tcp_data->pending_packets->packet;
        chitcp_packet_list_pop_head(&tcp_data->pending_packets);
    } else
        return -1;

    pthread_mutex_unlock(&tcp_data->lock_pending_packets);


    tcphdr_t *header = TCP_PACKET_HEADER(p);


    if(entry->tcp_state == LISTEN) {
        tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
        if(header->ack == 1 || !header->syn) {
            chilog(ERROR, "Need Reset");
            return -1;
        }

        /* Pick random ISS */
        srand(time(NULL));
        tcp_data->ISS = rand() % 100;
        tcp_data->IRS = SEG_SEQ(p);
        tcp_data->RCV_NXT = SEG_SEQ(p) + 1;
        tcp_data->SND_UNA = tcp_data->ISS;
        tcp_data->SND_NXT = tcp_data->ISS + 1;
        tcp_data->SND_WND = SEG_WND(p);

        circular_buffer_set_seq_initial(&tcp_data->recv, tcp_data->IRS);
        tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
        tcp_packet_t *send_packet = malloc(sizeof(tcp_packet_t));
        chitcpd_tcp_packet_create(entry, send_packet, NULL, 0);
        tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);
        send_header->ack = 1;
        send_header->syn = 1;
        send_header->seq = chitcp_htonl(tcp_data->ISS);
        send_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
        send_header->win = chitcp_htons(tcp_data->RCV_WND);
        chitcpd_send_tcp_packet(si, entry, send_packet);

        /*  Managing the Retransmission Queue
            adding SYN and FIN to rtx queue */
        insert_packet_to_rtx_queue(si, entry, send_packet);

        chitcpd_update_tcp_state(si, entry, SYN_RCVD);
        return 1;
    }

    if(entry->tcp_state == SYN_SENT) {
        if(SEG_ACK(p) <= tcp_data->ISS || SEG_ACK(p) > tcp_data->SND_NXT) {
            chilog(ERROR, "Need Reset");
            return -1;
        }

        if(SEG_ACK(p) > tcp_data->SND_UNA && SEG_ACK(p) <= tcp_data->SND_NXT) {
            /* [Resolve item] 
                - Added a helper function to remove the old rtx packets */
            int cnt = clean_rtx_queue(si, entry, p);

            /*  Restarting the timer only when some outstanding packets are ACKed */
            if(cnt > 0) {
                arg_struct_t *args = malloc(sizeof(arg_struct_t));
                args->si = si;
                args->entry = entry;
                mt_cancel_timer(&tcp_data->mt, RETRANSMISSION);
                mt_set_timer(&tcp_data->mt, RETRANSMISSION, tcp_data->RTO,
                             raw_rtx_func, (void *)args);
            }

            if(header->syn == 1) {
                tcp_data->RCV_NXT = SEG_SEQ(p) + 1;
                tcp_data->IRS = SEG_SEQ(p);
                tcp_data->SND_UNA = SEG_ACK(p);
                tcp_data->SND_WND = SEG_WND(p);
                circular_buffer_set_seq_initial(&tcp_data->recv, tcp_data->IRS);
                tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);

                if(tcp_data->SND_UNA > tcp_data->ISS) {
                    tcp_packet_t *send_packet = malloc(sizeof(tcp_packet_t));
                    chitcpd_tcp_packet_create(entry, send_packet, NULL, 0);
                    tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);

                    send_header->ack = 1;
                    send_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
                    send_header->seq = chitcp_htonl(tcp_data->SND_NXT);
                    send_header->win = chitcp_htons(tcp_data->RCV_WND);

                    chitcpd_send_tcp_packet(si, entry, send_packet);
                    chitcpd_update_tcp_state(si, entry, ESTABLISHED);

                    return 0;
                }
                /* [Resolve item]
                    - Added else statement according to RFC P68
                    - Send a SYN, ACK packet and transition to SYN_RCVD */
                else
                {
                    tcp_packet_t *send_packet = malloc(sizeof(tcp_packet_t));
                    chitcpd_tcp_packet_create(entry, send_packet, NULL, 0);
                    tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);

                    send_header->ack = 1;
                    send_header->syn = 1;
                    send_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
                    send_header->seq = chitcp_htonl(tcp_data->SND_NXT);
                    send_header->win = chitcp_htons(tcp_data->RCV_WND);

                    chitcpd_send_tcp_packet(si, entry, send_packet);
                    chitcpd_update_tcp_state(si, entry, SYN_RCVD);

                    free(send_packet);
                    
                    return 0;
                }
            }
            
        }

    }

    tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
    int acceptable = 0;

    /* [Address feedback] Data transfer
        - Fix unconditionally sending an ACK segment
        - Follow RFC procedure exactly
    */
    if(SEG_LEN(p) == 0 && tcp_data->RCV_WND == 0) {
        if(SEG_SEQ(p) == tcp_data->RCV_NXT)
            acceptable = 1;
    } else if(SEG_LEN(p) == 0 && tcp_data->RCV_WND > 0) {
        if(tcp_data->RCV_NXT <= SEG_SEQ(p) && SEG_SEQ(p) < tcp_data->RCV_NXT + tcp_data->RCV_WND)
            acceptable = 1;
    } else if(SEG_LEN(p) > 0 && tcp_data->RCV_WND == 0) {
        acceptable = 0;
    } else {
        if(tcp_data->RCV_NXT <= SEG_SEQ(p) && SEG_SEQ(p)
                || tcp_data->RCV_NXT <= SEG_SEQ(p) + SEG_LEN(p) - 1
                && tcp_data->RCV_NXT + tcp_data->RCV_WND)
            acceptable = 1;
    }

    if(acceptable == 0) {
        tcp_packet_t *send_packet = malloc(sizeof(tcp_packet_t));
        chitcpd_tcp_packet_create(entry, send_packet, NULL, 0);
        tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);
        send_header->ack = 1;
        send_header->seq = chitcp_htonl(tcp_data->SND_NXT);
        send_header->ack_seq = chitcp_htonl(SEG_SEQ(p) + 1);
        send_header->win = chitcp_htons(tcp_data->RCV_WND);
        /*To check final ACK in handshake*/
        if(entry->tcp_state == SYN_RCVD && header->syn == 1) {
            send_header->seq = chitcp_htonl(tcp_data->ISS);
            send_header->syn = 1;
        }
        chitcpd_send_tcp_packet(si, entry, send_packet);
        free(send_packet);
        return 1;
    }

    /*  [Resolve item]
        - Exludes pure ACK packets
        - Does not insert duplicate packets into queue
        - Removed setting time when inserting into out-of-order queue
    */
    if(SEG_SEQ(p) > tcp_data->RCV_NXT &&
            (SEG_LEN(p) > 0 || header->fin || header->syn)) {
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        out_order_packet_t *cur_packet = malloc(sizeof(out_order_packet_t));
        cur_packet->next = NULL;
        cur_packet->packet = p;
        pthread_mutex_lock(&tcp_data->lock_out_order_queue);
        out_order_packet_t *elt = NULL;
        DL_SEARCH(tcp_data->out_order_queue, elt, cur_packet, cmp_func);
        /* [Resolve item] Only insert if no duplicate is found */
        if(elt == NULL)
            DL_INSERT_INORDER(tcp_data->out_order_queue, cur_packet, cmp_func);
        pthread_mutex_unlock(&tcp_data->lock_out_order_queue);
        return 1;
    }

    if(SEG_SEQ(p) < tcp_data->RCV_NXT) {
        chilog(ERROR, "[Problem] SEG SEQ < RCV_NXT");
        return -1;
    }

    /* check if can match any out of order queue packets */
    pthread_mutex_lock(&tcp_data->lock_out_order_queue);
    uint32_t rcv_nxt = SEG_SEQ(p) + SEG_LEN(p);
    if(tcp_data->out_order_queue) {
        out_order_packet_t *elt, *tmp;
        DL_FOREACH_SAFE(tcp_data->out_order_queue, elt, tmp) {
            if(SEG_SEQ(elt->packet) < rcv_nxt) {
                continue;
            } else if(SEG_SEQ(elt->packet) == rcv_nxt) {
                /*lock pending packets before accessing*/
                pthread_mutex_lock(&tcp_data->lock_pending_packets);
                chitcp_packet_list_append(&tcp_data->pending_packets, elt->packet);
                pthread_mutex_unlock(&tcp_data->lock_pending_packets);
                DL_DELETE(tcp_data->out_order_queue, elt);
                rcv_nxt = SEG_SEQ(elt->packet) + SEG_LEN(elt->packet);
            } else {
                break;
            }
        }
    }
    pthread_mutex_unlock(&tcp_data->lock_out_order_queue);

    if(header->syn == 1 || header->ack != 1) {
        return -1;
    }

    if(entry->tcp_state == SYN_RCVD) {
        if(SEG_ACK(p) >= tcp_data->SND_UNA && SEG_ACK(p) <= tcp_data->SND_NXT)
            chitcpd_update_tcp_state(si, entry, ESTABLISHED); // continue processing
        else
            return -1;
    }

    if(SEG_ACK(p) < tcp_data->SND_UNA) {
        return -1;
    } else if(SEG_ACK(p) > tcp_data->SND_NXT) {
        /* acked on something not sent yet, sent an ack and return */
        if(SEG_LEN(p) > 0) {
            tcp_packet_t *send_packet = malloc(sizeof(tcp_packet_t));
            chitcpd_tcp_packet_create(entry, send_packet, NULL, 0);
            tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);
            send_header->ack = 1;
            send_header->seq = chitcp_htonl(tcp_data->SND_NXT);
            send_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
            send_header->win = chitcp_htons(tcp_data->RCV_WND);
            chitcpd_send_tcp_packet(si, entry, send_packet);
            free(send_packet);
            return -1;
        }
    }

    if(entry->tcp_state == FIN_WAIT_1 && header->fin == 0) {
        if(SEG_ACK(p) == tcp_data->SND_UNA + 1) {
            chitcpd_update_tcp_state(si, entry, FIN_WAIT_2);
        }
    } else if(entry->tcp_state == CLOSING && header->fin == 0) {
        if(SEG_ACK(p) == tcp_data->SND_UNA + 1) {
            chitcpd_update_tcp_state(si, entry, TIME_WAIT);
            chitcpd_update_tcp_state(si, entry, CLOSED);
        } else
            return -1;
    } else if(entry->tcp_state == LAST_ACK) {
        if(SEG_ACK(p) == tcp_data->SND_UNA + 1) {
            chitcpd_update_tcp_state(si, entry, CLOSED);
            return -1;
        } else
            return -1;
    }


    if(entry->tcp_state == CLOSE_WAIT || entry->tcp_state == CLOSING || entry->tcp_state == LAST_ACK || entry->tcp_state == TIME_WAIT) {
        return -1;
    }

    int original_SND_UNA = tcp_data->SND_UNA;

    if(SEG_SEQ(p) == tcp_data->RCV_NXT) {
        tcp_data->RCV_NXT = SEG_SEQ(p) + SEG_LEN(p);
    }
    tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
    if(SEG_WND(p) > tcp_data->SND_WND || SEG_ACK(p) > tcp_data->SND_UNA) {
        tcp_data->SND_WND = SEG_WND(p);
        batch_send(si, entry);
    }

    tcp_data->SND_WND = SEG_WND(p);

    /*  Managing the Retransmission Queue
        - removing acknowledged packets from queue */
    if(SEG_ACK(p) > tcp_data->SND_UNA && SEG_ACK(p) <= tcp_data->SND_NXT) {
        /* [Resolve item] 
            - Added a helper function to remove the old rtx packets */
        int cnt = clean_rtx_queue(si, entry, p);

        /*reset the rtx timer only when some packets are cleared */
        if(cnt > 0) {
            arg_struct_t *args = malloc(sizeof(arg_struct_t));
            args->si = si;
            args->entry = entry;
            mt_cancel_timer(&tcp_data->mt, RETRANSMISSION);
            mt_set_timer(&tcp_data->mt, RETRANSMISSION, tcp_data->RTO, raw_rtx_func, (void *)args);
        }
        tcp_data->SND_UNA = SEG_ACK(p);
    }


    /* Check if tcp is in closing state */
    if(circular_buffer_count(&tcp_data->send) == 0
            && rtx_queue_size(tcp_data) == 0 && tcp_data->closing == 1) {
        if(entry->tcp_state == ESTABLISHED) {
            tcp_packet_t *send_packet = malloc(sizeof(tcp_packet_t));
            chitcpd_tcp_packet_create(entry, send_packet, NULL, 0);
            tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);

            send_header->ack = 1;
            send_header->fin = 1;
            send_header->seq = chitcp_htonl(tcp_data->SND_NXT);
            send_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
            send_header->win = chitcp_htons(tcp_data->RCV_WND);
            tcp_data->SND_NXT = tcp_data->SND_NXT + 1;
            chitcpd_send_tcp_packet(si, entry, send_packet);

            insert_packet_to_rtx_queue(si, entry, send_packet);
            chitcpd_update_tcp_state(si, entry, FIN_WAIT_1);
        } else if(entry->tcp_state == CLOSE_WAIT) {
            /* Send fin */
            tcp_packet_t *send_packet = malloc(sizeof(tcp_packet_t));
            chitcpd_tcp_packet_create(entry, send_packet, NULL, 0);
            tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);

            send_header->ack = 1;
            send_header->fin = 1;
            send_header->seq = chitcp_htonl(tcp_data->SND_NXT);
            send_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
            send_header->win = chitcp_htons(tcp_data->RCV_WND);
            tcp_data->SND_NXT = tcp_data->SND_NXT + 1;
            chitcpd_send_tcp_packet(si, entry, send_packet);

            insert_packet_to_rtx_queue(si, entry, send_packet);

            chitcpd_update_tcp_state(si, entry, LAST_ACK);
        }
    }

    /* Persist timer logic */
    if(SEG_WND(p) == 0) {
        single_timer_t *single_timer;
        mt_get_timer_by_id(&tcp_data->mt, PERSIST, &single_timer);
        if(single_timer->active == false) {
            arg_struct_t *args = malloc(sizeof(arg_struct_t));
            args->si = si;
            args->entry = entry;
            mt_set_timer(&tcp_data->mt, PERSIST, tcp_data->RTO, raw_persist_func, (void *)args);
        }
    } else {
        single_timer_t *single_timer;
        mt_get_timer_by_id(&tcp_data->mt, PERSIST, &single_timer);
        if(single_timer->active == true) {
            arg_struct_t *args = malloc(sizeof(arg_struct_t));
            args->si = si;
            args->entry = entry;
            mt_cancel_timer(&tcp_data->mt, PERSIST);
        }
        tcp_data->probe_byte = NULL;
    }

    if(SEG_LEN(p) > 0) {
        int bytes_wrote = circular_buffer_write(&tcp_data->recv, TCP_PAYLOAD_START(p), SEG_LEN(p), FALSE);
    }

    tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);

    tcp_packet_t *send_packet = malloc(sizeof(tcp_packet_t));
    chitcpd_tcp_packet_create(entry, send_packet, NULL, 0);
    tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);

    send_header->ack = 1;
    send_header->seq = chitcp_htonl(tcp_data->SND_NXT);
    send_header->win = chitcp_htons(tcp_data->RCV_WND);
    send_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);

    if(header->fin != 1 && SEG_LEN(p) > 0) {
        chitcpd_send_tcp_packet(si, entry, send_packet);
        free(send_packet);
        return 1;
    }

    /* Check the fin bit */
    if(header->fin == 1) {
        if(entry->tcp_state == CLOSED || entry->tcp_state == LISTEN || entry->tcp_state == SYN_SENT) {
            return -1;
        }

        tcp_data->RCV_NXT = SEG_SEQ(p) + 1;
        send_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
        chitcpd_send_tcp_packet(si, entry, send_packet);
        free(send_packet);


        if(entry->tcp_state == ESTABLISHED || entry->tcp_state == SYN_RCVD) {
            chitcpd_update_tcp_state(si, entry, CLOSE_WAIT);

        } else if(entry->tcp_state == FIN_WAIT_1) {
            if(original_SND_UNA + 1 == SEG_ACK(p)) {
                chitcpd_update_tcp_state(si, entry, TIME_WAIT);
                chitcpd_update_tcp_state(si, entry, CLOSED);
            } else {
                chitcpd_update_tcp_state(si, entry, CLOSING);
            }
        } else if(entry->tcp_state == FIN_WAIT_2) {
            chitcpd_update_tcp_state(si, entry, TIME_WAIT);
            chitcpd_update_tcp_state(si, entry, CLOSED);
        }
    }

    return 1;
}

int chitcpd_tcp_state_handle_CLOSED(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == APPLICATION_CONNECT) {
        tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
        /* [Address Feedback]
             Pick random ISS */
        srand(time(NULL));
        tcp_data->ISS = rand() % 100;
        tcp_data->SND_UNA = tcp_data->ISS;
        tcp_data->SND_NXT = tcp_data->ISS + 1;
        circular_buffer_init(&tcp_data->send, 4096);
        circular_buffer_init(&tcp_data->recv, 4096);
        circular_buffer_set_seq_initial(&tcp_data->send, tcp_data->ISS);
        tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);

        tcp_packet_t *send_packet = malloc(sizeof(tcp_packet_t));
        chitcpd_tcp_packet_create(entry, send_packet, NULL, 0);
        tcphdr_t *header;
        header = TCP_PACKET_HEADER(send_packet);
        header->syn = 1;
        header->seq = chitcp_htonl(tcp_data->ISS);
        header->win = chitcp_htons(tcp_data->RCV_WND);
        chitcpd_send_tcp_packet(si, entry, send_packet);

        insert_packet_to_rtx_queue(si, entry, send_packet);

        chitcpd_update_tcp_state(si, entry, SYN_SENT);
    } else if (event == CLEANUP) {
        /* Any additional cleanup goes here */
    } else
        chilog(WARNING, "In CLOSED state, received unexpected event.");

    return CHITCP_OK;
}

/*
 * tcp_data_init - Initialize fields in tcp_data
 *
 * si: pointer to server information
 *
 * entry: pointer chisocketentry_t entry
 *
 * Returns: nothing
 */
void tcp_data_init(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    tcp_data->closing = 0;
    tcp_data->pending_packets = NULL;
    pthread_mutex_init(&tcp_data->lock_pending_packets, NULL);
    pthread_cond_init(&tcp_data->cv_pending_packets, NULL);

    /*  Managing the Retransmission Queue
            - Locking the retransmission queue
            - Locking the out_of_order queue */
    pthread_mutex_init(&tcp_data->lock_out_order_queue, NULL);

    tcp_data->RTO = 200 * MILLISECOND;
    tcp_data->G = 50 * MILLISECOND; // [fix] check clock gruality
    tcp_data->NO_RTT = 1;
    mt_init(&tcp_data->mt, 2);
    mt_set_timer_name(&tcp_data->mt, RETRANSMISSION, "Retransmission");
    mt_set_timer_name(&tcp_data->mt, PERSIST, "Persist");
    tcp_data->probe_byte = NULL;
}

/*
 * tcp_data_free - Free fields in tcp_data
 *
 * si: pointer to server information
 *
 * entry: pointer chisocketentry_t entry
 *
 * Returns: nothing
 */
void tcp_data_free(serverinfo_t *si, chisocketentry_t *entry)
{
    chilog(DEBUG, "calling tcp data free");
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    circular_buffer_free(&tcp_data->send);
    circular_buffer_free(&tcp_data->recv);
    chitcp_packet_list_destroy(&tcp_data->pending_packets);
    pthread_mutex_destroy(&tcp_data->lock_pending_packets);
    pthread_cond_destroy(&tcp_data->cv_pending_packets);

    if(tcp_data->rtx_queue) {
        out_order_packet_t *elt, *tmp;
        DL_FOREACH_SAFE(tcp_data->rtx_queue, elt, tmp) {
            free(elt->packet);
            DL_DELETE(tcp_data->rtx_queue, elt);
        }
    }

    pthread_mutex_lock(&tcp_data->lock_out_order_queue);
    if(tcp_data->out_order_queue) {
        out_order_packet_t *elt, *tmp;
        DL_FOREACH_SAFE(tcp_data->out_order_queue, elt, tmp) {
            free(elt->packet);
            DL_DELETE(tcp_data->out_order_queue, elt);
        }
    }
    pthread_mutex_unlock(&tcp_data->lock_out_order_queue);

    pthread_mutex_destroy(&tcp_data->lock_out_order_queue);

    free(tcp_data->probe_byte);

    mt_free(&tcp_data->mt);
}


int chitcpd_tcp_state_handle_LISTEN(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL) {
        chitcpd_tcp_handle_packet(si, entry);
    } else
        chilog(WARNING, "In LISTEN state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_SYN_RCVD(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL) {
        chitcpd_tcp_handle_packet(si, entry);
    } else if (event == TIMEOUT_RTX) {
        go_back_n(si, entry);
    } else
        chilog(WARNING, "In SYN_RCVD state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_SYN_SENT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL) {
        chitcpd_tcp_handle_packet(si, entry);

    } else if (event == TIMEOUT_RTX) {
        go_back_n(si, entry);
    } else
        chilog(WARNING, "In SYN_SENT state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_ESTABLISHED(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == APPLICATION_SEND) {
        batch_send(si, entry);
    } else if (event == PACKET_ARRIVAL) {
        chitcpd_tcp_handle_packet(si, entry);

    } else if (event == APPLICATION_RECEIVE) {
        tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
        tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
    } else if (event == APPLICATION_CLOSE) {
        /* Connection teardown -
            Delaying the FIN packet until all outstanding data has been sent*/
        tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
        batch_send(si, entry);
        if(circular_buffer_count(&tcp_data->send) == 0
                && rtx_queue_size(tcp_data) == 0) {
            tcp_packet_t *send_packet = malloc(sizeof(tcp_packet_t));
            chitcpd_tcp_packet_create(entry, send_packet, NULL, 0);
            tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);

            send_header->ack = 1;
            send_header->fin = 1;
            send_header->seq = chitcp_htonl(tcp_data->SND_NXT);
            send_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
            send_header->win = chitcp_htons(tcp_data->RCV_WND);
            tcp_data->SND_NXT = tcp_data->SND_NXT + 1;
            chitcpd_send_tcp_packet(si, entry, send_packet);

            insert_packet_to_rtx_queue(si, entry, send_packet);
            chitcpd_update_tcp_state(si, entry, FIN_WAIT_1);
        } else {
            tcp_data->closing = 1;
        }

    } else if (event == TIMEOUT_RTX) {
        go_back_n(si, entry);
    } else if (event == TIMEOUT_PST) {
        handle_persist_timeout(si, entry);
    } else
        chilog(WARNING, "In ESTABLISHED state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_FIN_WAIT_1(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL) {
        chitcpd_tcp_handle_packet(si, entry);
    } else if (event == APPLICATION_RECEIVE) {
        tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
        tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
    } else if (event == TIMEOUT_RTX) {
        go_back_n(si, entry);
    } else if (event == TIMEOUT_PST) {
        handle_persist_timeout(si, entry);
    } else
        chilog(WARNING, "In FIN_WAIT_1 state, received unexpected event (%i).", event);

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_FIN_WAIT_2(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL) {
        chitcpd_tcp_handle_packet(si, entry);
    } else if (event == APPLICATION_RECEIVE) {
        tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
        tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
    } else if (event == TIMEOUT_RTX) {
        go_back_n(si, entry);
    } else
        chilog(WARNING, "In FIN_WAIT_2 state, received unexpected event (%i).", event);

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_CLOSE_WAIT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == APPLICATION_CLOSE) {
        /* Connection teardown
            - Delaying the FIN packet until all outstanding data has been sent
        */
        tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
        batch_send(si, entry);
        if(circular_buffer_count(&tcp_data->send) == 0
                && rtx_queue_size(tcp_data) == 0) {
            tcp_packet_t *send_packet = malloc(sizeof(tcp_packet_t));
            chitcpd_tcp_packet_create(entry, send_packet, NULL, 0);
            tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);

            send_header->ack = 1;
            send_header->fin = 1;
            send_header->seq = chitcp_htonl(tcp_data->SND_NXT);
            send_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
            send_header->win = chitcp_htons(tcp_data->RCV_WND);
            tcp_data->SND_NXT = tcp_data->SND_NXT + 1;
            chitcpd_send_tcp_packet(si, entry, send_packet);

            insert_packet_to_rtx_queue(si, entry, send_packet);

            chitcpd_update_tcp_state(si, entry, LAST_ACK);
        } else {
            tcp_data->closing = 1;
        }
    } else if (event == PACKET_ARRIVAL) {
        chitcpd_tcp_handle_packet(si, entry);
    } else if (event == TIMEOUT_RTX) {
        go_back_n(si, entry);
    } else if (event == TIMEOUT_PST) {
        handle_persist_timeout(si, entry);
    } else
        chilog(WARNING, "In CLOSE_WAIT state, received unexpected event (%i).", event);


    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_CLOSING(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL) {
        chitcpd_tcp_handle_packet(si, entry);
    } else if (event == TIMEOUT_RTX) {
        go_back_n(si, entry);
    } else if (event == TIMEOUT_PST) {
        handle_persist_timeout(si, entry);
    } else
        chilog(WARNING, "In CLOSING state, received unexpected event (%i).", event);

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_TIME_WAIT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    chilog(WARNING, "Running handler for TIME_WAIT. This should not happen.");

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_LAST_ACK(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL) {
        chitcpd_tcp_handle_packet(si, entry);
    } else if (event == TIMEOUT_RTX) {
        go_back_n(si, entry);
    } else if (event == TIMEOUT_PST) {
        handle_persist_timeout(si, entry);
    } else
        chilog(WARNING, "In LAST_ACK state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

/*                                                           */
/*     Any additional functions you need should go here      */
/*                                                           */

void raw_rtx_func(multi_timer_t *mt, single_timer_t* st, void* args)
{
    arg_struct_t *inner_args = (arg_struct_t *)args;
    tcp_data_t *tcp_data = &(inner_args->entry->socket_state.active.tcp_data);
    tcp_data->RTO = (tcp_data->RTO * 2); //Exponential Backoff
    if(tcp_data->RTO > (60 * SECOND)) {
        tcp_data->RTO = 60 * SECOND;
    }
    chitcpd_timeout(inner_args->si, inner_args->entry, RETRANSMISSION);
    free(args);
}

void raw_persist_func(multi_timer_t *mt, single_timer_t* st, void* args)
{
    arg_struct_t *inner_args = (arg_struct_t *)args;
    chitcpd_timeout(inner_args->si, inner_args->entry, PERSIST);
    free(args);
}

int rtx_queue_size(tcp_data_t *tcp_data)
{
    if(!tcp_data->rtx_queue) {
        return 0;
    }
    int cnt = 0;
    out_order_packet_t *elt, *tmp;
    DL_FOREACH_SAFE(tcp_data->rtx_queue, elt, tmp) {
        cnt ++;
    }
    return cnt;
}


int cmp_func(out_order_packet_t *a, out_order_packet_t *b)
{
    if(SEG_SEQ(a->packet) < SEG_SEQ(b->packet))
        return -1;
    else if(SEG_SEQ(a->packet) > SEG_SEQ(b->packet))
        return 1;
    else
        return 0;
}

uint64_t max_func(uint64_t a, uint64_t b)
{
    return (a > b) ? a : b;
}
