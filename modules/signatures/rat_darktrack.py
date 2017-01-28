# Copyright (C) 2014 @threatlead
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature

class DarktrackMutex(Signature):
    name = "rat_darktrack"
    description = "Creates Darktrack RAT mutex"
    severity = 3
    categories = ["rat"]
    families = ["darktrack"]
    authors = ["Daniel Gallagher"]
    minimum = "1.2"

    def run(self):
        indicators = [
            "I_AM_DT[a-zA-Z]{8}",
        ]

        for indicator in indicators:
            match = self.check_mutex(pattern=indicator, regex=True)
            if match:
                self.data.append({"Mutex": match})
                return True

        return False
