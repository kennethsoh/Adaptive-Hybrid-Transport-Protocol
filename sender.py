"""
Sender.py
------------
- Randomly generates 40-50 messages composed of random words.
- Each message is sent either reliably or unreliably based on a random choice (50% chance for each).
"""
import logging
import random
import time
import json
from datetime import datetime
from GameNetAPI import GameNetAPI

# Sender configurations
HOST = '127.0.0.1'
PORT = 5000
WAIT_AFTER_SEND = 1.0

# Server configurations
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5000

# Logger setup
LOGGER = logging.getLogger(__name__)


def generate_sentences():
    '''
    Randomly construct a short sentence (5 - 10 words) from a list of predefined words.
    '''
    words = [
        "packet", "latency", "server", "client", "protocol", "data", "network",
        "reliable", "unreliable", "message", "transmission", "game", "performance",
        "adaptive", "hybrid", "transport", "simulation", "testing", "connection",
        "throughput", "bandwidth", "jitter", "loss", "delay", "buffer", "queue", "socket"
    ]
    sentence = " ".join(random.choices(words, k=random.randint(5, 10)))
    return sentence


def main():
    '''
    Initialises the GameNetAPI client and sends randomly genereated messages either reliably or unreliably.
    '''

    # Initialise GameNetAPI sender (client)
    api = GameNetAPI(is_server=False, host=HOST, port=PORT)
    api.connect_to_server(SERVER_HOST, SERVER_PORT)

    # Send 30 Reliable and Unreliable Messages
    NUM_RELIABLE = 30
    NUM_UNRELIABLE = 30

    # Shuffle the order of reliable and unreliable sends
    send_tasks = (['reliable'] * NUM_RELIABLE) + (['unreliable'] * NUM_UNRELIABLE)
    random.shuffle(send_tasks)
    total_packets = len(send_tasks)

    # Counter for Total Unreliable Messages Sent
    total_unreliable_sent = 0

    time.sleep(5)
    for i, task_type in enumerate(send_tasks):
        LOGGER.info("Preparing to send message %d/%d", i + 1, total_packets)
        message = generate_sentences()
        data = message.encode('utf-8')

        # Randomly decide to send reliably or unreliably
        if task_type == 'reliable':
            LOGGER.info("[Send] Preparing (reliable) message: %r", message)
            api.send_reliable(data)
            LOGGER.info("[Send] Message sent at time %s\n", datetime.now().strftime("%H:%M:%S"))
            time.sleep(0.1)
        else:
            LOGGER.info("[Send] Preparing (unreliable) message %r", message)
            api.send_unreliable(data)
            total_unreliable_sent += 1
            LOGGER.info("[Send] Message sent at time %s\n", datetime.now().strftime("%H:%M:%S"))
            time.sleep(0.1)

    LOGGER.info("All messages sent. Sending Final Reliable Stats Package...")
    stats_payload = json.dumps({"total_unreliable_sent": total_unreliable_sent})
    api.send_reliable(stats_payload.encode('utf-8'))

    t_end = time.time() + WAIT_AFTER_SEND
    while time.time() < t_end:
        api.process_events(timeout=0.1)

    # Wait to ensure all (reliable) packets are delivered before closing
    # Quic may need some time to retransmit lost packets
    api.drain_events()

    api.report_results()
    api.close()


if __name__ == "__main__":
    main()