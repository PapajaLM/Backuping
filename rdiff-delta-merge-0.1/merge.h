/* Copyright 2011 Jaroslaw Filiochowski <jarfil@users.sf.net>
 * This file is part of rdiff-delta-merge.

 * rdiff-delta-merge is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * rdiff-delta-merge is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with rdiff-delta-merge.  If not, see <http://www.gnu.org/licenses/>.
*/

#define LITERAL_BUF_SIZE    4096

struct delta_chunk {
	int c_type;
	// output file
	size_t start;
	size_t len;
	// source file
	int sf_id;
	size_t sf_pos;
};

