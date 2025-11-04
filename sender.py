"""
Sender.py
------------
- Randomly generates 40-50 messages composed of random words.
- Each message is sent either reliably or unreliably based on a random choice (50% chance for each).
"""
import logging
import random
import time

from GameNetAPI import GameNetAPI

# Server configurations
HOST = '127.0.0.1'
PORT = 5000
WAIT_AFTER_SEND = 1.0

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

    # Initialise GameNetAPI client
    api = GameNetAPI(is_server=False, host=HOST, port=PORT)
    api.connect_to_server()

    # Send between 40 and 50 messages
    random_number = random.randint(40, 50)

    for i in range(random_number):
        LOGGER.info("Preparing to send message %d/%d", i + 1, random_number)
        message = generate_sentences()
        data = message.encode('utf-8')

        # Randomly decide to send reliably or unreliably
        if random.random() < 0.5:
            LOGGER.info("[Send] Preparing (reliable) message: %r", message)
            api.send_reliable(data)
            LOGGER.info("[Send] Message sent\n")
            time.sleep(0.1)
        else:
            LOGGER.info("[Send] Preparing (unreliable) message %r", message)
            api.send_unreliable(data)
            LOGGER.info("[Send] Message sent\n")
            time.sleep(0.1)

    t_end = time.time() + WAIT_AFTER_SEND
    while time.time() < t_end:
        api.process_events(timeout=0.1)

    api.report_results()
    api.close()


if __name__ == "__main__":
    main()
