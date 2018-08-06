/*
 * Copyright (C) 2012 - Julien Desfossez <julien.desfossez@efficios.com>
 *                      David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <assert.h>
#include <inttypes.h>
#include <signal.h>

#include <bin/lttng-consumerd/health-consumerd.h>
#include <common/common.h>
#include <common/compat/endian.h>
#include <common/kernel-ctl/kernel-ctl.h>
#include <common/kernel-consumer/kernel-consumer.h>
#include <common/consumer/consumer-stream.h>
#include <common/consumer/consumer-timer.h>
#include <common/consumer/consumer-testpoint.h>
#include <common/ust-consumer/ust-consumer.h>
#include <common/relayd/relayd.h>

typedef int (*stream_action)(struct lttng_consumer_stream *, void *);

static struct timer_signal_data timer_signal = {
	.tid = 0,
	.setup_done = 0,
	.qs_done = 0,
	.lock = PTHREAD_MUTEX_INITIALIZER,
};

struct stream_array {
	unsigned int count;
	struct lttng_dynamic_buffer buffer;
};

/*
 * Set custom signal mask to current thread.
 */
static void setmask(sigset_t *mask)
{
	int ret;

	ret = sigemptyset(mask);
	if (ret) {
		PERROR("sigemptyset");
	}
	ret = sigaddset(mask, LTTNG_CONSUMER_SIG_SWITCH);
	if (ret) {
		PERROR("sigaddset switch");
	}
	ret = sigaddset(mask, LTTNG_CONSUMER_SIG_TEARDOWN);
	if (ret) {
		PERROR("sigaddset teardown");
	}
	ret = sigaddset(mask, LTTNG_CONSUMER_SIG_LIVE);
	if (ret) {
		PERROR("sigaddset live");
	}
	ret = sigaddset(mask, LTTNG_CONSUMER_SIG_EXIT);
	if (ret) {
		PERROR("sigaddset exit");
	}
}

/*
 * Execute action on a timer switch.
 *
 * Beware: metadata_switch_timer() should *never* take a mutex also held
 * while consumer_timer_switch_stop() is called. It would result in
 * deadlocks.
 */
static void metadata_switch_timer(struct lttng_consumer_local_data *ctx,
		int sig, siginfo_t *si, void *uc)
{
	int ret;
	struct lttng_consumer_channel *channel;

	channel = si->si_value.sival_ptr;
	assert(channel);

	if (channel->switch_timer_error) {
		return;
	}

	DBG("Switch timer for channel %" PRIu64, channel->key);
	switch (ctx->type) {
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		/*
		 * Locks taken by lttng_ustconsumer_request_metadata():
		 * - metadata_socket_lock
		 *   - Calling lttng_ustconsumer_recv_metadata():
		 *     - channel->metadata_cache->lock
		 *     - Calling consumer_metadata_cache_flushed():
		 *       - channel->timer_lock
		 *         - channel->metadata_cache->lock
		 *
		 * Ensure that neither consumer_data.lock nor
		 * channel->lock are taken within this function, since
		 * they are held while consumer_timer_switch_stop() is
		 * called.
		 */
		ret = lttng_ustconsumer_request_metadata(ctx, channel, 1, 1);
		if (ret < 0) {
			channel->switch_timer_error = 1;
		}
		break;
	case LTTNG_CONSUMER_KERNEL:
	case LTTNG_CONSUMER_UNKNOWN:
		assert(0);
		break;
	}
}

static int send_empty_index(struct lttng_consumer_stream *stream, uint64_t ts,
		uint64_t stream_id, struct consumer_relayd_sock_pair *relayd,
		bool deferred)
{
	int ret;
	struct ctf_packet_index index;

	memset(&index, 0, sizeof(index));
	index.stream_id = htobe64(stream_id);
	index.timestamp_end = htobe64(ts);
	ret = consumer_stream_write_index(stream, &index, relayd, deferred);
	if (ret < 0) {
		goto error;
	}

error:
	return ret;
}

int consumer_flush_kernel_index(struct lttng_consumer_stream *stream,
		struct consumer_relayd_sock_pair *relayd,
		bool deferred)
{
	uint64_t ts, stream_id;
	int ret;

	ret = kernctl_get_current_timestamp(stream->wait_fd, &ts);
	if (ret < 0) {
		ERR("Failed to get the current timestamp");
		goto end;
	}
	ret = kernctl_buffer_flush(stream->wait_fd);
	if (ret < 0) {
		ERR("Failed to flush kernel stream");
		goto end;
	}
	ret = kernctl_snapshot(stream->wait_fd);
	if (ret < 0) {
		if (ret != -EAGAIN && ret != -ENODATA) {
			PERROR("live timer kernel snapshot");
			ret = -1;
			goto end;
		}
		ret = kernctl_get_stream_id(stream->wait_fd, &stream_id);
		if (ret < 0) {
			PERROR("kernctl_get_stream_id");
			goto end;
		}
		DBG("Stream %" PRIu64 " empty, sending beacon", stream->key);
		ret = send_empty_index(stream, ts, stream_id, relayd, deferred);
		if (ret < 0) {
			goto end;
		}
	}
	ret = 0;
end:
	return ret;
}

/* Stream lock must be held by the caller. */
static int check_kernel_stream(struct lttng_consumer_stream *stream,
		void *_relayd)
{
	int ret;
	struct consumer_relayd_sock_pair *relayd = _relayd;

	/*
	 * The actual sending of the indexes is deferred since this is
	 * performed withing the context of an iteration on all streams
	 * of a channel. In all likelyhood, multiple indexes (beacons) will
	 * need to be sent to a significant network communication efficiency
	 * gain is realized by packing multiple 'send_index' commands together
	 * as a single send().
	 */
	ret = consumer_flush_kernel_index(stream, relayd, true);
	return ret;
}

int consumer_flush_ust_index(struct lttng_consumer_stream *stream,
		struct consumer_relayd_sock_pair *relayd,
		bool deferred)
{
	uint64_t ts, stream_id;
	int ret;

	ret = cds_lfht_is_node_deleted(&stream->node.node);
	if (ret) {
		goto end;
	}

	ret = lttng_ustconsumer_get_current_timestamp(stream, &ts);
	if (ret < 0) {
		ERR("Failed to get the current timestamp");
		goto end;
	}
	lttng_ustconsumer_flush_buffer(stream, 1);
	ret = lttng_ustconsumer_take_snapshot(stream);
	if (ret < 0) {
		if (ret != -EAGAIN) {
			ERR("Taking UST snapshot");
			ret = -1;
			goto end;
		}
		ret = lttng_ustconsumer_get_stream_id(stream, &stream_id);
		if (ret < 0) {
			PERROR("ustctl_get_stream_id");
			goto end;
		}
		DBG("Stream %" PRIu64 " empty, sending beacon", stream->key);
		ret = send_empty_index(stream, ts, stream_id,
				relayd, deferred);
		if (ret < 0) {
			goto end;
		}
	}
	ret = 0;
end:
	return ret;
}

/* Stream lock must be held by the caller. */
static int check_ust_stream(struct lttng_consumer_stream *stream,
		void *_relayd)
{
	int ret;
	struct consumer_relayd_sock_pair *relayd = _relayd;

	assert(stream);
	assert(stream->ustream);
	/*
	 * The actual sending of the indexes is deferred since this is
	 * performed within the context of an iteration on all streams
	 * of a channel. In all likelyhood, multiple indexes (beacons) will
	 * need to be sent, so a significant network communication efficiency
	 * gain is realized by packing multiple 'send_index' commands together
	 * in a single send-buffer.
	 */
	ret = consumer_flush_ust_index(stream, relayd, true);
	return ret;
}

static int unlock_stream(struct lttng_consumer_stream *stream, void *data)
{
	pthread_mutex_unlock(&stream->lock);
	return 0;
}

static int lock_and_add_stream(struct lttng_consumer_stream *stream, void *data)
{
	int ret;
	struct stream_array *streams = data;

	/*
	 * While holding the stream mutex, try to take a snapshot, if it
	 * succeeds, it means that data is ready to be sent, just let the data
	 * thread handle that. Otherwise, if the snapshot returns EAGAIN, it
	 * means that there is no data to read after the flush, so we can
	 * safely send the empty index.
	 *
	 * Doing a trylock and checking if waiting on metadata if
	 * trylock fails. Bail out of the stream is indeed waiting for
	 * metadata to be pushed. Busy wait on trylock otherwise.
	 */
	for (;;) {
		ret = pthread_mutex_trylock(&stream->lock);
		switch (ret) {
		case 0:
			break;	/* We have the lock. */
		case EBUSY:
			pthread_mutex_lock(&stream->metadata_timer_lock);
			if (stream->waiting_on_metadata) {
				ret = 0;
				stream->missed_metadata_flush = true;
				pthread_mutex_unlock(&stream->metadata_timer_lock);
				goto end;	/* Bail out. */
			}
			pthread_mutex_unlock(&stream->metadata_timer_lock);
			/* Try again. */
			caa_cpu_relax();
			continue;
		default:
			ERR("Unexpected pthread_mutex_trylock error %d", ret);
			ret = -1;
			goto end;
		}
		break;
	}

	streams->count++;
	ret = lttng_dynamic_buffer_append(&streams->buffer, &stream,
			sizeof(stream));
end:
	return ret;
}

static int for_each_stream_array(struct stream_array *streams,
		stream_action action, void *data)
{
	unsigned int i;
	bool error = false;
	struct lttng_consumer_stream **it =
			(struct lttng_consumer_stream **) streams->buffer.data;

	for (i = 0; i < streams->count; i++) {
		int ret;

		ret = action(*it, data);
		if (ret) {
			error = true;
		}
		it++;
	}
	return error ? -1 : 0;
}

static int for_each_stream_ht(struct lttng_ht *stream_per_chan_id_ht,
		uint64_t channel_key,
		stream_action action, void *data)
{
	bool error = false;
	struct lttng_consumer_stream *stream;
	struct lttng_ht_iter iter;

	cds_lfht_for_each_entry_duplicate(stream_per_chan_id_ht->ht,
			stream_per_chan_id_ht->hash_fct(&channel_key, lttng_ht_seed),
			stream_per_chan_id_ht->match_fct, &channel_key, &iter.iter,
			stream, node_channel_id.node) {
		int ret;

		ret = action(stream, data);
		if (ret) {
			error = true;
		}
	}
	return error ? -1 : 0;
}

/*
 * Execute action on a live timer
 */
static void live_timer(struct lttng_consumer_local_data *ctx,
		int sig, siginfo_t *si, void *uc)
{
	int ret;
	struct lttng_consumer_channel *channel;
	struct lttng_ht *ht;
	struct consumer_relayd_sock_pair *relayd = NULL;
	stream_action check_stream;
	struct stream_array streams = { .count = 0 };

	channel = si->si_value.sival_ptr;
	assert(channel);


	lttng_dynamic_buffer_init(&streams.buffer);

	rcu_read_lock();

	switch (ctx->type) {
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		check_stream = check_ust_stream;
		break;
	case LTTNG_CONSUMER_KERNEL:
		check_stream = check_kernel_stream;
		break;
	default:
		abort();
	}

	/*
	 * The live timer periodically flushes a channel's streams' indexes
	 * to provide the relayd with a checkpoint up to which it is safe
	 * to provide the traces to a client. In doing so, indexes or beacons
	 * (effectively empty indexes) will be sent for each stream.
	 *
	 * As this results in a lot of individual 'SEND_INDEX' command, a slow
	 * network connection can make this operation fairly long.
	 *
	 * To preserve compatibility with existing relay daemons, we choose
	 * to fill a single network send buffer containing a batch of
	 * 'SEND_INDEX' commands to send it all at once.
	 *
	 * Batching the commands changes the assumptions that are made about
	 * the order of commands reaching the relay daemon under certain
	 * circumstances. One of the problematic scenarios that can arise
	 * is that a stream's index/beacon could be enqueued in the send
	 * buffer and it could then be closed (in another thread). Then,
	 * when the send-buffer is finally flushed to the network, the
	 * relay daemon will receive an index for a stream that was previously
	 * closed. Unfortunately, the relay daemon may close the connection
	 * when an invalid command is received.
	 *
	 * To prevent this scenario, the lock of every stream is acquired
	 * and they are all released once the send-buffer has been sent
	 * over the network. This preserves the expected order of commands
	 * from the relay daemon's point of view.
	 */
	if (channel->switch_timer_error) {
		goto error;
	}
	ht = consumer_data.stream_per_chan_id_ht;

	DBG("Live timer for channel %" PRIu64, channel->key);

	if (channel->relayd_id != (uint64_t) -1ULL) {
		relayd = consumer_find_relayd(channel->relayd_id);
		if (!relayd) {
			ERR("Channel %s relayd ID %" PRIu64 " unknown. Can't process live timer.",
					channel->name, channel->relayd_id);
		}
	}

	ret = for_each_stream_ht(ht, channel->key, lock_and_add_stream,
			&streams);
	if (ret) {
		goto unlock_streams;
	}

	pthread_mutex_lock(&relayd->ctrl_sock_mutex);
	ret = for_each_stream_array(&streams, check_stream, relayd);
	if (ret) {
		goto unlock_streams;
	}

	if (relayd) {
		ret = relayd_flush_commands(relayd, relayd_generic_reply_handling);
		if (ret) {
			ERR("relayd_flush_commands failed in live_timer()");
		}
	}

unlock_streams:
	pthread_mutex_unlock(&relayd->ctrl_sock_mutex);
	ret = for_each_stream_array(&streams, unlock_stream, NULL);
	if (ret) {
		goto error;
	}

error:
	rcu_read_unlock();
	lttng_dynamic_buffer_reset(&streams.buffer);
	return;
}

static
void consumer_timer_signal_thread_qs(unsigned int signr)
{
	sigset_t pending_set;
	int ret;

	/*
	 * We need to be the only thread interacting with the thread
	 * that manages signals for teardown synchronization.
	 */
	pthread_mutex_lock(&timer_signal.lock);

	/* Ensure we don't have any signal queued for this channel. */
	for (;;) {
		ret = sigemptyset(&pending_set);
		if (ret == -1) {
			PERROR("sigemptyset");
		}
		ret = sigpending(&pending_set);
		if (ret == -1) {
			PERROR("sigpending");
		}
		if (!sigismember(&pending_set, signr)) {
			break;
		}
		caa_cpu_relax();
	}

	/*
	 * From this point, no new signal handler will be fired that would try to
	 * access "chan". However, we still need to wait for any currently
	 * executing handler to complete.
	 */
	cmm_smp_mb();
	CMM_STORE_SHARED(timer_signal.qs_done, 0);
	cmm_smp_mb();

	/*
	 * Kill with LTTNG_CONSUMER_SIG_TEARDOWN, so signal management thread wakes
	 * up.
	 */
	kill(getpid(), LTTNG_CONSUMER_SIG_TEARDOWN);

	while (!CMM_LOAD_SHARED(timer_signal.qs_done)) {
		caa_cpu_relax();
	}
	cmm_smp_mb();

	pthread_mutex_unlock(&timer_signal.lock);
}

/*
 * Set the timer for periodical metadata flush.
 */
void consumer_timer_switch_start(struct lttng_consumer_channel *channel,
		unsigned int switch_timer_interval)
{
	int ret;
	struct sigevent sev;
	struct itimerspec its;

	assert(channel);
	assert(channel->key);

	if (switch_timer_interval == 0) {
		return;
	}

	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = LTTNG_CONSUMER_SIG_SWITCH;
	sev.sigev_value.sival_ptr = channel;
	ret = timer_create(CLOCKID, &sev, &channel->switch_timer);
	if (ret == -1) {
		PERROR("timer_create");
	}
	channel->switch_timer_enabled = 1;

	its.it_value.tv_sec = switch_timer_interval / 1000000;
	its.it_value.tv_nsec = (switch_timer_interval % 1000000) * 1000;
	its.it_interval.tv_sec = its.it_value.tv_sec;
	its.it_interval.tv_nsec = its.it_value.tv_nsec;

	ret = timer_settime(channel->switch_timer, 0, &its, NULL);
	if (ret == -1) {
		PERROR("timer_settime");
	}
}

/*
 * Stop and delete timer.
 */
void consumer_timer_switch_stop(struct lttng_consumer_channel *channel)
{
	int ret;

	assert(channel);

	ret = timer_delete(channel->switch_timer);
	if (ret == -1) {
		PERROR("timer_delete");
	}

	consumer_timer_signal_thread_qs(LTTNG_CONSUMER_SIG_SWITCH);

	channel->switch_timer = 0;
	channel->switch_timer_enabled = 0;
}

/*
 * Set the timer for the live mode.
 */
void consumer_timer_live_start(struct lttng_consumer_channel *channel,
		int live_timer_interval)
{
	int ret;
	struct sigevent sev;
	struct itimerspec its;

	assert(channel);
	assert(channel->key);

	if (live_timer_interval <= 0) {
		return;
	}

	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = LTTNG_CONSUMER_SIG_LIVE;
	sev.sigev_value.sival_ptr = channel;
	ret = timer_create(CLOCKID, &sev, &channel->live_timer);
	if (ret == -1) {
		PERROR("timer_create");
	}
	channel->live_timer_enabled = 1;

	its.it_value.tv_sec = live_timer_interval / 1000000;
	its.it_value.tv_nsec = (live_timer_interval % 1000000) * 1000;
	its.it_interval.tv_sec = its.it_value.tv_sec;
	its.it_interval.tv_nsec = its.it_value.tv_nsec;

	ret = timer_settime(channel->live_timer, 0, &its, NULL);
	if (ret == -1) {
		PERROR("timer_settime");
	}
}

/*
 * Stop and delete timer.
 */
void consumer_timer_live_stop(struct lttng_consumer_channel *channel)
{
	int ret;

	assert(channel);

	ret = timer_delete(channel->live_timer);
	if (ret == -1) {
		PERROR("timer_delete");
	}

	consumer_timer_signal_thread_qs(LTTNG_CONSUMER_SIG_LIVE);

	channel->live_timer = 0;
	channel->live_timer_enabled = 0;
}

/*
 * Block the RT signals for the entire process. It must be called from the
 * consumer main before creating the threads
 */
int consumer_signal_init(void)
{
	int ret;
	sigset_t mask;

	/* Block signal for entire process, so only our thread processes it. */
	setmask(&mask);
	ret = pthread_sigmask(SIG_BLOCK, &mask, NULL);
	if (ret) {
		errno = ret;
		PERROR("pthread_sigmask");
		return -1;
	}
	return 0;
}

/*
 * This thread is the sighandler for signals LTTNG_CONSUMER_SIG_SWITCH,
 * LTTNG_CONSUMER_SIG_TEARDOWN, LTTNG_CONSUMER_SIG_LIVE, and
 * LTTNG_CONSUMER_SIG_EXIT.
 */
void *consumer_timer_thread(void *data)
{
	int signr;
	sigset_t mask;
	siginfo_t info;
	struct lttng_consumer_local_data *ctx = data;

	rcu_register_thread();

	health_register(health_consumerd, HEALTH_CONSUMERD_TYPE_METADATA_TIMER);

	if (testpoint(consumerd_thread_metadata_timer)) {
		goto error_testpoint;
	}

	health_code_update();

	/* Only self thread will receive signal mask. */
	setmask(&mask);
	CMM_STORE_SHARED(timer_signal.tid, pthread_self());

	while (1) {
		health_code_update();

		health_poll_entry();
		signr = sigwaitinfo(&mask, &info);
		health_poll_exit();
		if (signr == -1) {
			if (errno != EINTR) {
				PERROR("sigwaitinfo");
			}
			continue;
		} else if (signr == LTTNG_CONSUMER_SIG_SWITCH) {
			metadata_switch_timer(ctx, info.si_signo, &info, NULL);
		} else if (signr == LTTNG_CONSUMER_SIG_TEARDOWN) {
			cmm_smp_mb();
			CMM_STORE_SHARED(timer_signal.qs_done, 1);
			cmm_smp_mb();
			DBG("Signal timer metadata thread teardown");
		} else if (signr == LTTNG_CONSUMER_SIG_LIVE) {
			live_timer(ctx, info.si_signo, &info, NULL);
		} else if (signr == LTTNG_CONSUMER_SIG_EXIT) {
			assert(consumer_quit);
			goto end;
		} else {
			ERR("Unexpected signal %d\n", info.si_signo);
		}
	}

error_testpoint:
	/* Only reached in testpoint error */
	health_error();
end:
	health_unregister(health_consumerd);
	rcu_unregister_thread();
	return NULL;
}
