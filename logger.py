import os, sys
import logging

dir_path = os.path.dirname(os.path.realpath(__file__))
filename = os.path.join(dir_path, 'app.log')

# Initialize the logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Format for the logging
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# File handler
file_handler = logging.FileHandler(filename)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(formatter)

# Stream handler
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setLevel(logging.INFO)
stream_handler.setFormatter(formatter)

# Add the handlers
logger.addHandler(file_handler)
logger.addHandler(stream_handler)

if __name__ == '__main__':
    logger.info("App logger test")

