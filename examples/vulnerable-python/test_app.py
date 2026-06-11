import unittest

from app import parse_expr


class ParseExprTests(unittest.TestCase):
    def test_safe_literal(self):
        self.assertEqual(parse_expr("{'safe': 1}"), {"safe": 1})
