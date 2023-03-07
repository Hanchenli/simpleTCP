REGRADE EXPLANATIONS:
We submitted changes according to the following feedback:

1. [Code Quality] Make sure not to lock the retransmission queue, as there is no possibility of concurrent access by multiple threads since it is only accessed by the socket thread.

[Solution] Deleted rtx_lock in tcp_data struct (tcp.c:939).

2. [Code Quality] Please be careful when doing integer division, since it is floor division, so you lose the fractions, leaving you with 0 for alpha and beta.

[Solution] Transformed the formula and calculated in another way to avoid incorrect fractional division. (tcp.c: ~295)

3. [Code Quality] You should have another else here, since this would mean that your SYN has not been ACKed. In that case, you should be transitioning into the SYN_RCVD state (see RFC p. 68)

[Solution] Added else statement according to RFC P68: send a SYN, ACK packet and transition to SYN_RCVD (tcp.c:581).

4. [Code Quality] Make sure to check your out-of-order queue for whether you have already added the packet to the queue, or you may inadvertently insert duplicate segments.

[Solution] First search the out-of-order queue for duplicates. If none is found, insert the packet (tcp.c:660). Ed post #508. 

5. [Code Quality] You have code for managing the retransmission queue in multiple areas within this function. It may be cleaner to have a helper function to handle retransmission logic.

[Solution] Wrote a helper function clean_rtx_queue that removes the old rtx packets (tcp.c:448).

6. Your out-of-order list implementation doesn't need to keep account of time. 

[Solution] Removed setting time when inserting into out-of-order list. (tcp.c:652).

There is no rubric that was not addressed. Thank you for the valuable feedback.