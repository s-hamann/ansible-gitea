#!/usr/bin/env python
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class FilterModule(object):
    def filters(self):
        return {
            'sort_versions': self.sort_versions,
        }

    def sort_versions(self, value):
        """This is a somewhat naive approach to version sorting. It only
        supports versions that consist of numbers separated by dots."""
        return sorted(value, key=lambda s: list(map(int, s.split('.'))))
