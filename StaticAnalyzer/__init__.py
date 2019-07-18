import logging
LOG_FORMAT = "%(asctime)s - %(filename)s - %(levelname)s - %(message)s"
logging.basicConfig(filename="../wood.log", level=logging.INFO, format=LOG_FORMAT)