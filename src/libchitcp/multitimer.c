/*
 *  chiTCP - A simple, testable TCP stack
 *
 *  An API for managing multiple timers
 */

/*
 *  Copyright (c) 2013-2019, The University of Chicago
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
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
 *    software without specific prior written permission.
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
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "chitcp/multitimer.h"
#include "chitcp/log.h"



/* See multitimer.h */
int timespec_subtract(struct timespec *result, struct timespec *x, struct timespec *y)
{
    struct timespec tmp;
    tmp.tv_sec = y->tv_sec;
    tmp.tv_nsec = y->tv_nsec;

    /* Perform the carry for the later subtraction by updating tmp. */
    if (x->tv_nsec < tmp.tv_nsec) {
        uint64_t sec = (tmp.tv_nsec - x->tv_nsec) / SECOND + 1;
        tmp.tv_nsec -= SECOND * sec;
        tmp.tv_sec += sec;
    }
    if (x->tv_nsec - tmp.tv_nsec > SECOND) {
        uint64_t sec = (x->tv_nsec - tmp.tv_nsec) / SECOND;
        tmp.tv_nsec += SECOND * sec;
        tmp.tv_sec -= sec;
    }

    /* Compute the time remaining to wait.
       tv_nsec is certainly positive. */
    result->tv_sec = x->tv_sec - tmp.tv_sec;
    result->tv_nsec = x->tv_nsec - tmp.tv_nsec;

    /* Return 1 if result is negative. */
    return x->tv_sec < tmp.tv_sec;
}

void *multi_timer_func(void *args)
{
    multi_timer_t *mt = (multi_timer_t *) args;

    pthread_mutex_lock(&mt->lock);
    while(mt->active) {
        if(mt->active_timers == NULL) {
            pthread_cond_wait(&mt->condition, &mt->lock);
        } else {
            if(!mt->active_timers->active)
                chilog(ERROR, "NOT ACTIVE TIMER BEING IN USE, ID is:%d",
                       mt->active_timers->id);

            single_timer_t *active_timer_save = mt->active_timers;
            int rc = pthread_cond_timedwait(&mt->condition, &mt->lock,
                                            &active_timer_save->expire_time);

            if (rc == ETIMEDOUT) {
                active_timer_save->callback(mt, active_timer_save,
                                            active_timer_save->callback_args);
                active_timer_save->num_timeouts += 1;
                active_timer_save->active = false;
                if(mt->active_timers)
                    DL_DELETE(mt->active_timers, active_timer_save);
            }
        }

    }
    pthread_mutex_unlock(&mt->lock);
    pthread_exit(NULL);
}

/* See multitimer.h */
int mt_init(multi_timer_t *mt, uint16_t num_timers)
{
    mt->active = true;
    if ((mt->timers = malloc(sizeof(single_timer_t) * num_timers)) == NULL) {
        return CHITCP_ENOMEM;
    }
    for(int i=0; i < num_timers; i++) {
        mt->timers[i].id = i;
        mt->timers[i].active = false;
        mt->timers[i].num_timeouts = 0;
    }

    mt->num_timers = num_timers;
    mt->active_timers = NULL;

    if (pthread_mutex_init(&mt->lock, NULL) != 0
            || pthread_cond_init(&mt->condition, NULL) != 0) {
        return CHITCP_EINIT;
    }

    if (pthread_create(&mt->timer_thread, NULL, multi_timer_func, mt) != 0) {
        return CHITCP_ETHREAD;
    }
    return CHITCP_OK;
}


/* See multitimer.h */
int mt_free(multi_timer_t *mt)
{
    pthread_mutex_lock(&mt->lock);
    mt->active = false; //Graceful Exit
    pthread_cond_signal(&mt->condition);

    single_timer_t *elt, *tmp;
    free(mt->timers);
    DL_FOREACH_SAFE(mt->active_timers, elt, tmp) {
        DL_DELETE(mt->active_timers, elt);
    }

    pthread_mutex_unlock(&mt->lock);
    pthread_join(mt->timer_thread, NULL);
    return CHITCP_OK;
}


/* See multitimer.h */
int mt_get_timer_by_id(multi_timer_t *mt, uint16_t id, single_timer_t **timer)
{
    pthread_mutex_lock(&mt->lock);
    if (id < 0 || id >= mt->num_timers) {
        pthread_mutex_unlock(&mt->lock);
        return CHITCP_EINVAL;
    }

    *timer = &mt->timers[id];
    pthread_mutex_unlock(&mt->lock);

    return CHITCP_OK;
}


/* See multitimer.h */
int mt_set_timer(multi_timer_t *mt, uint16_t id, uint64_t timeout, mt_callback_func callback, void* callback_args)
{
    pthread_mutex_lock(&mt->lock);

    if (id < 0 || id >= mt->num_timers) {
        pthread_mutex_unlock(&mt->lock);
        return CHITCP_EINVAL;
    }
    if(mt->timers[id].active) {
        pthread_mutex_unlock(&mt->lock);
        return CHITCP_EINVAL;
    }

    /*First we modify the original timer*/
    mt->timers[id].active = true;
    mt->timers[id].callback = callback;
    mt->timers[id].callback_args = callback_args;
    clock_gettime(CLOCK_REALTIME, &mt->timers[id].expire_time);

    uint64_t second_addition = timeout / SECOND;
    timeout = timeout % SECOND;
    second_addition += (timeout + mt->timers[id].expire_time.tv_nsec) / SECOND;
    mt->timers[id].expire_time.tv_sec += second_addition;
    mt->timers[id].expire_time.tv_nsec = (timeout + mt->timers[id].expire_time.tv_nsec) % SECOND;

    /*Second we insert it into active list*/
    if(mt->active_timers == NULL) {
        DL_APPEND(mt->active_timers, &mt->timers[id]);
    } else {
        single_timer_t *elt, *tmp;
        bool added = false;

        DL_FOREACH_SAFE(mt->active_timers, elt, tmp) {
            struct timespec diff;
            if(timespec_subtract(&diff, &elt->expire_time,
                                 &mt->timers[id].expire_time) != 1) {
                DL_PREPEND_ELEM(mt->active_timers, elt, &mt->timers[id]);
                added = true;
                break;
            }

        }

        if(added == false) {
            DL_APPEND(mt->active_timers, &mt->timers[id]);
        }
    }

    pthread_cond_signal(&mt->condition);
    chilog(ERROR, "5th timer activeness: %d", mt->timers[5].active);
    pthread_mutex_unlock(&mt->lock);

    return CHITCP_OK;
}


/* See multitimer.h */
int mt_cancel_timer(multi_timer_t *mt, uint16_t id)
{
    pthread_mutex_lock(&mt->lock);
    chilog(ERROR, "id is %d, num_timers: %d", id, mt->num_timers);
    if (id < 0 || id >= mt->num_timers) {
        chilog(ERROR, "id not in range");
        pthread_mutex_unlock(&mt->lock);
        return CHITCP_EINVAL;
    }
    if(!mt->timers[id].active) {
        chilog(ERROR, "active not");
        pthread_mutex_unlock(&mt->lock);
        return CHITCP_EINVAL;
    }

    if(mt->active_timers->id == id) {
        pthread_cond_signal(&mt->condition);
        mt->active_timers->active = false;
        DL_DELETE(mt->active_timers, mt->active_timers);
    } else { //else the canceled timer is still waiting.
        single_timer_t *elt, *tmp;
        DL_FOREACH_SAFE(mt->active_timers, elt, tmp) {
            if(elt->id == id) {
                elt->active = false;
                DL_DELETE(mt->active_timers, elt);
            }
        }
    }

    pthread_mutex_unlock(&mt->lock);
    return CHITCP_OK;
}


/* See multitimer.h */
int mt_set_timer_name(multi_timer_t *mt, uint16_t id, const char *name)
{
    /* Your code here */

    return CHITCP_OK;
}


/* mt_chilog_single_timer - Prints a single timer using chilog
 *
 * level: chilog log level
 *
 * timer: Timer
 *
 * Returns: Always returns CHITCP_OK
 */
int mt_chilog_single_timer(loglevel_t level, single_timer_t *timer)
{
    struct timespec now, diff;
    clock_gettime(CLOCK_REALTIME, &now);

    if(timer->active) {
        /* Compute the appropriate value for "diff" here; it should contain
         * the time remaining until the timer times out.
         * Note: The timespec_subtract function can come in handy here*/
        diff.tv_sec = 0;
        diff.tv_nsec = 0;
        chilog(level, "%i %s %lis %lins", timer->id, timer->name, diff.tv_sec, diff.tv_nsec);
    } else
        chilog(level, "%i %s", timer->id, timer->name);

    return CHITCP_OK;
}


/* See multitimer.h */
int mt_chilog(loglevel_t level, multi_timer_t *mt, bool active_only)
{
    /* Your code here */

    return CHITCP_OK;
}