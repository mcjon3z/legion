"""
LEGION (https://shanewilliamscott.com)
Copyright (c) 2025 Shane William Scott

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
    version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
    warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
    details.

    You should have received a copy of the GNU General Public License along with this program.
    If not, see <http://www.gnu.org/licenses/>.

Author(s): Shane Scott (sscott@shanewilliamscott.com), Dmitriy Dubson (d.dubson@gmail.com)
"""
import unittest

from PyQt6 import QtCore

from app.ModelHelpers import resolveHeaders, itemInteractive, itemSelectable


class ModelHelpersTest(unittest.TestCase):
    def test_resolveHeaders_WhenRoleIsDisplayAndOrientationIsHzAndSectionIsWithinBound_ReturnsHeaders(self):
        expectedHeaders = ["header1", "header2", "header3"]
        headers = [[], expectedHeaders, []]
        actualHeaders = resolveHeaders(QtCore.Qt.ItemDataRole.DisplayRole, QtCore.Qt.Orientation.Horizontal, 1, headers)
        self.assertEqual(expectedHeaders, actualHeaders)

    def test_resolveHeaders_WhenRoleIsNotDisplay_ReturnsNone(self):
        self.assertIsNone(
            resolveHeaders(
                QtCore.Qt.ItemDataRole.BackgroundRole,
                QtCore.Qt.Orientation.Horizontal,
                1,
                []
            )
        )

    def test_resolveHeaders_WhenRoleIsDisplayAndOrientationIsNotHz_ReturnsNone(self):
        self.assertIsNone(resolveHeaders(QtCore.Qt.ItemDataRole.DisplayRole, QtCore.Qt.Orientation.Vertical, 1, []))

    def test_resolveHeaders_WhenRoleIsDisplayAndOrientationIsHzAndSectionIsOutOfBound_ReturnsStringMessage(self):
        expectedMessage = "not implemented in view model"
        actualMessage = resolveHeaders(QtCore.Qt.ItemDataRole.DisplayRole, QtCore.Qt.Orientation.Horizontal, 100, [])
        self.assertEqual(expectedMessage, actualMessage)

    def test_itemInteractive_ReturnsItemFlagForEnabledSelectableEditableItem(self):
        expectedFlags = (
            QtCore.Qt.ItemFlag.ItemIsEnabled
            | QtCore.Qt.ItemFlag.ItemIsSelectable
            | QtCore.Qt.ItemFlag.ItemIsEditable
        )
        self.assertEqual(expectedFlags, itemInteractive())

    def test_itemSelectable_ReturnItemFlagForEnabledSelectableItem(self):
        expectedFlags = QtCore.Qt.ItemFlag.ItemIsEnabled | QtCore.Qt.ItemFlag.ItemIsSelectable
        self.assertEqual(expectedFlags, itemSelectable())
