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

from db.SqliteDbAdapter import Database
from six import u as unicode

from db.entities.note import note


class NoteRepository:
    def __init__(self, dbAdapter: Database, log):
        self.dbAdapter = dbAdapter
        self.log = log

    def getNoteByHostId(self, hostId):
        session = self.dbAdapter.session()
        result = session.query(note).filter_by(hostId=str(hostId)).first()
        session.close()
        return result

    def storeNotes(self, hostId, notes):
        session = self.dbAdapter.session()
        if len(notes) == 0:
            notes = unicode("".format(hostId=hostId))
        self.log.debug("Storing notes for {hostId}, Notes {notes}".format(hostId=hostId, notes=notes))
        t_note = self.getNoteByHostId(hostId)
        if t_note:
            t_note.text = unicode(notes)
        else:
            t_note = note(hostId, unicode(notes))
        session.add(t_note)
        session.commit()
        session.close()
