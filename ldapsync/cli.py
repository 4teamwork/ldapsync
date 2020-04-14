from ldapsync.sync import sync

import argparse
import confuse
import logging


def main():
    config = confuse.LazyConfig('ldapsync', __name__)
    parser = argparse.ArgumentParser(description='LDAP synchronization')

    parser.add_argument('--config', '-c', dest='config_file',
                        help='configuration file')
    parser.add_argument('--debug', '-d', dest='debug', action='store_true',
                        help='configuration file')

    args = parser.parse_args()
    if args.config_file:
        config.set_file(args.config_file)
    config.set_args(args, dots=True)

    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        format='%(asctime)s %(levelname)s %(name)s %(message)s',
        level=log_level,
    )

    sync(config)


if __name__ == '__main__':
    main()
