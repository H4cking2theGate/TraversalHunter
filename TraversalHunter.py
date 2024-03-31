import logging
import os

import click
from core.scanner import scan
from util.logging_utils import setup_logging


@click.command()
@click.option('--url', '-u', help='Target URL (supports swagger docs)')
@click.option('--file', '-f',help='HTTP request file')
@click.option('--proxy', '-x', is_flag=True, default=False, help='Enable proxy')
def main(url, file, proxy):
    """
    Scan for directory traversal vulnerabilities.
    """
    filename_with_extension = os.path.basename(file)
    filename_without_extension, _ = os.path.splitext(filename_with_extension)
    output = f"logs/{filename_without_extension}.log"

    setup_logging(log_file=output)
    if not url and not file:
        raise click.UsageError('Either --url or --file is required.')

    if url and file:
        raise click.UsageError('Only one of --url or --file should be provided.')

    if url:
        request = url
    else:
        with open(file, 'rb') as filee:
            request = filee.read()

    results = scan(request, enable_proxy=proxy)

    if results:
        logging.info(f"[*] Found {len(results)} vulnerabilities")
        for result in results:
            logging.info(f"Payload: {result}")
    logging.info("[*] Finished scanning\n")


if __name__ == '__main__':
    main()
