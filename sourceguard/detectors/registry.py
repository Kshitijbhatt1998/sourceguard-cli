from .aws import AWSDetector
from .stripe import StripeDetector
from .private_keys import PrivateKeyDetector
from .database import DatabaseDetector
from .tokens import TokenDetector
from .entropy import EntropyDetector

DETECTORS = [
    AWSDetector(),
    StripeDetector(),
    PrivateKeyDetector(),
    DatabaseDetector(),
    TokenDetector(),
    EntropyDetector(),
]
