import argparse
import time

from GameNetAPI import GameNetAPI

HOST = '127.0.0.1'
PORT = 5000
WAIT_AFTER_SEND = 1.0


def main():
    parser = argparse.ArgumentParser(description="GameNet Sender")
    parser.add_argument('--mode', choices=['reliable', 'unreliable'], default='reliable',
                        help="Choose the sending mode: reliable or unreliable")
    parser.add_argument('--message', type=str, required=True,
                        help="The message to send to the receiver")
    args = parser.parse_args()

    api = GameNetAPI(is_server=False, host=HOST, port=PORT)

    api.connect_to_server()

    data = args.message.encode('utf-8')
    if args.mode == 'reliable':
        api.send_reliable(data)
        print(f"[SENT RELIABLE] {args.message!r}")
    else:
        api.send_unreliable(data)
        print(f"[SENT UNRELIABLE] {args.message!r}")

    t_end = time.time() + WAIT_AFTER_SEND
    while time.time() < t_end:
        api.process_events(timeout=0.1)

    api.report_results()
    api.close()


if name == "__main__":
    main()