import os

# A tshark parser that raises fails the run here, rather than skipping
# the packet as it does for a user (shark_analyzer._parser_failed): a
# parser's bug has to fail its tests.
os.environ.setdefault('SOCRATES_STRICT_PARSERS', '1')
