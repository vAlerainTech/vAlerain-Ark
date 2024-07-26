#!/usr/bin/python

"""
Diaphora, a diffing plugin for IDA
Copyright (c) 2015, Joxean Koret
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import idc

from diaphora_ida import load_and_import_all_results

#-----------------------------------------------------------------------
def main():
	filename = idc.ARGV[1]
	main_db = idc.ARGV[2]
	diff_db = idc.ARGV[3]

	load_and_import_all_results(filename, main_db, diff_db)

if __name__ == "__main__":
  main()
