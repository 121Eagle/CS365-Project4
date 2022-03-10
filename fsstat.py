"""Get information about a FAT32 filesystem and each file."""

import json
import os
import sys
from typing import Any, Optional

import hw4utils


def unpack(data: bytes, signed=False, byteorder="little") -> int:
    """Unpack a single value from bytes"""
    return int.from_bytes(data, byteorder=byteorder, signed=signed)


class Fat:
    def __init__(self, filename):
        """Parses a FAT32 filesystem"""
        self.filename = filename
        self.file = open(self.filename, "rb")
        # set of key/value pairs parsed from the "Reserved" sector of the filesystem
        self.boot = dict()
        self._parse_reserved_sector()

    def __del__(self):
        """Called when the object is destroyed."""
        # close the open file reader
        self.file.close()

    def _parse_reserved_sector(self):
        """Parse information from the "Reserved" sector of the filesystem.

        The start of the FAT32 must be at the start of self.file.

        Stores the following keys in the self.boot dictionary:
            bytes_per_sector
            sectors_per_cluster
            reserved_sectors
            number_of_fats
            total_sectors
            sectors_per_fat
            root_dir_first_cluster
            total_sectors
            bytes_per_cluster
            fat0_sector_start
            fat0_sector_end
            data_start
            data_end

        This function also stores fat0 in self.fat.

        Refer to Carrier Chapters 9 and 10.
        """
        boot_sector = self.file.read(512)  # because screw it
        # I will just read in the entire reserved sector at once and deal with
        # the parts later
        self.boot = dict(
            zip(
                (
                    "bytes_per_sector",
                    "sectors_per_cluster",
                    "reserved_sectors",
                    "number_of_fats",
                ),
                map(
                    unpack,
                    (
                        boot_sector[11:13],
                        boot_sector[13:14],
                        boot_sector[14:16],
                        boot_sector[16:17],
                    ),
                ),
            )
        )
        potential_total = unpack(boot_sector[19:21])
        if potential_total == 0:
            potential_total = unpack(boot_sector[32:36])
        self.boot |= {"total_sectors": potential_total}
        self.boot |= dict(
            zip(
                ("sectors_per_fat", "root_dir_first_cluster"),
                map(
                    unpack,
                    (
                        boot_sector[36:40],
                        boot_sector[44:48],
                    ),
                ),
            )
        )
        self.boot |= {
            "bytes_per_cluster": self.boot["bytes_per_sector"]
            * self.boot["sectors_per_cluster"]
        }
        self.boot |= {"fat0_sector_start": self.boot["reserved_sectors"]}
        self.boot |= {
            "fat0_sector_end": self.boot["fat0_sector_start"]
            + self.boot["sectors_per_fat"]
            - 1
        }
        assert self.boot["fat0_sector_start"] <= self.boot["fat0_sector_end"]
        self.boot |= {
            "data_start": self.boot["fat0_sector_end"]
            + self.boot["sectors_per_fat"]
            + 1
        }
        self.boot |= {"data_end": potential_total - 1}
        assert self.boot["data_start"] < self.boot["data_end"]
        self.file.seek(self.boot["fat0_sector_start"] * self.boot["bytes_per_sector"])
        self.fat = self.file.read(
            self.boot["sectors_per_fat"] * self.boot["bytes_per_sector"]
        )

    def info(self):
        """Print already-parsed information about the FAT filesystem as a json string"""

        # Print out all keys stored in the self.boot dictionary
        print(json.dumps(self.boot, indent=4))

        # Parsing the root directory
        all_files = self.parse_dir(self.boot["root_dir_first_cluster"])
        for file in all_files:
            print(json.dumps(file))

    def _to_sector(self, cluster: int) -> int:
        """Convert a cluster number to a sector number

        Carrier explains how in Chapter 10.

        returns:
            int: sector number
        """
        sector_offset = (cluster - 2) * self._sectors_per_cluster
        return sector_offset + self.boot["data_start"]

    def _end_sector(self, cluster: int) -> int:
        """Return the last sector of a cluster

        There are n sectors per cluster. This functions returns
        the last sector of the cluster.

        returns:
            int: sector number
        """
        return self._to_sector(cluster) + self._sectors_per_cluster

    @property
    def _sectors_per_cluster(self) -> int:
        """
        I am just annoyed with trying to get the line length correct,
        So I am making this a property, fight me on this
        """
        return self.boot["sectors_per_cluster"]

    @property
    def _sector_of_cluster_2(self) -> int:
        """
        returns the start of sector 2 in the data area
        """
        return self.boot["data_start"]

    def _get_sectors(self, number: int) -> list[int]:
        """Return list of sectors for a given table entry number

        This function follws the cluster chains in the file allocation table.
        Accordingly, the sectors may be non-contiguous. If the first table
        entry is 0, then an empty list is returned.
        When the end-of-file marker is found, the chain ends.
        It's important to not follow the chains recursively, because you'll
        quickly hit Python's recursion limit.

        returns:
            list[int]: list of sectors
        """
        assert (
            0 < (number * 4 + 4) < self.boot["sectors_per_fat"]
        ), f"{number} exceeds FAT size"

        sector_list: list[int] = []
        current_cluster = number
        if current_cluster == 0:
            return [self._to_sector(current_cluster)]
        while current_cluster <= 0xFFFFFF8:
            for sector in range(
                self._to_sector(current_cluster), self._end_sector(current_cluster)
            ):
                sector_list.append(sector)
            cluster_start = current_cluster * 4
            cluster_end = cluster_start + 4  # the ending value of a slice is
            # exclusive rather then inclusive
            current_cluster = unpack(self.fat[cluster_start:cluster_end])
        return sector_list

    def _retrieve_data(self, cluster: int, ignore_unallocated=False) -> bytes:
        """Read in the data for a given file allocation table entry number (i.e., the cluster number).

        Important: this function returns all bytes in the cluster, even the slack data past the
        actual filesize.

        Because the cluster chain may be non-contiguous,
        the sectors may be non-contiguous and we read in sectors one at a time.
        The results are returned as a contiguous byte string.

        If ignore_unallocated is False, then when the cluster is unallocated,
        we return an empty bytes() object.

        When you are read, start to deal with the case when ignore_unallocated is True. In that case,
        then instead of returning an empty bytes object, we read in the sectors associated
        with the cluster. For example, assume cluster 2 starts at sector 1000, and there are
        2 sectors per cluster. Then for cluster 4, if discover it is unallocated, we would
        return 1000+ (4-2)*2 = 1004 as well as 1005 (since
        the cluster consists of 2 sectors). We are likely reading data for the wrong file.

        returns:
            bytes: data (possibly zero length)
        """
        data = bytearray()
        sectors = self._get_sectors(cluster)
        if ignore_unallocated and len(sectors) == 0:
            for sector in range(self._to_sector(cluster), self._end_sector(cluster)):
                sectors.append(sector)
        for sector in sectors[:-1]:
            self._seek_to_sector(sector)
            data += self._read_sector()
        return bytes(data)

    def _seek_to_sector(self, sector: int) -> None:
        """
        seeks the current file to the sector requested
        """
        bytes_to_seek = self.boot["bytes_per_sector"]
        self.file.seek(sector * bytes_to_seek)

    def _read(self, size: int) -> bytes:
        return self.file.read(size)

    def _read_sector(self) -> bytes:
        return self._read(self.boot["bytes_per_sector"])

    def _get_first_cluster(self, entry: bytes) -> int:
        """Returns the first cluster of the content of a given directory entry

        This function parses a directory entry to determine the first cluster used to
        store the data. That is, it returns the FAT entry number assoicated with the directory
        entry. Based on Carrier's Table 10.5. This is a little tricky with the shifting etc,
        and so I'm providing the code.

        Expects that self.boot["total_sectors"] and self.boot["sectors_per_cluster"] exist.

        returns:
            int: cluster number
        """
        high_order = int.from_bytes(entry[20:22], "little") << 16
        low_order = int.from_bytes(entry[26:28], "little")
        content_cluster = high_order + low_order
        max_cluster = self.boot["total_sectors"] / self.boot["sectors_per_cluster"]
        # if you send the wrong data to this function, you'll hit this error
        assert content_cluster <= max_cluster, "Error: value exceeds cluster count."

        return content_cluster

    def _get_content(self, cluster: int, filesize: int) -> tuple[str, Optional[str]]:
        """Return initial content of a directory entry and the intial content of its slack data if possible.

        Read the data for a file that begins with the stated cluster. Return the first 128 bytes
        of the file (or up to the filesize, which ever is smaller).

        If the cluster is not unallocated, the slack return is from the last sector of the
        last chain of the cluster chain. Up to 32 bytes of slack is returned.

        If cluster is unallocated, then return the file content (up to 128
        bytes even though it may be the wrong file) and return None for the slack


        returns:
            str: file content (up to 128 bytes)
            str (or None if unallocated cluster): slack content (up to 32 bytes)

        """
        all_file_data = bytearray(self._retrieve_data(cluster))
        if filesize == 0:
            return (all_file_data[: min(128, filesize)], None)
        slack = all_file_data[filesize : filesize + 32]
        return (
            all_file_data[0 : min(128, filesize)],
            slack
        )

    DONT_RECUR = frozenset({".", ".."})

    @classmethod
    def byte_formatting(cls, data: bytes, modulo: int = 32) -> bytes:
        stripped_value = bytearray(data.rstrip(b"\x00"))
        length_still_needed = modulo - (len(stripped_value) % modulo)
        # to get the amount of null bytes we still need to append
        # take the length of what we have stripped, and modulate it with
        # the modulo value.
        # then subtract that from modulo
        stripped_value += bytearray(length_still_needed)
        return bytes(stripped_value)

    def parse_dir(self, cluster: int, parent="") -> list[dict[str, Any]]:
        """Parse a directory cluster, returns a list of dictionaries, one dict per entry.

        This function recursively parses any entry that is itself a directory.

        Each dictionary contains the following keys (7 keys total):
            - parent: parent directory
            - dir_cluster: cluster number of the directory
            - entry_num: entry number of the directory (within its cluster)
            - dir_sectors: sectors associated with the directory (converted from cluster)
            - entry_type: type of entry (vol, lfn, dir, or other)
            - name: name of the entry
            - deleted: whether the entry is marked as deleted

        You can use hw4utils.get_entry_type() to get the type
        YOu can use hw4utils.parse_name() to get the name

        If the entry is a directory, then the following keys are
        also present (8 keys total):
            - content_cluster: the first cluster that contain's this entry's content

        If the entry is not a vol, lfn, or dir, then the following keys are
        also present (12 keys total):
            - filesize: size of the entry
            - content_sectors: the list of sectors associated with the content of this entry
            - content: the first 128 bytes of the entry's content
            - slack: the slack data (up to 32 bytes)

        returns:
            list[dict]: list of dictionaries, one dict per entry
        """
        directory = self._retrieve_data(cluster).rstrip(b"\x00")
        dir_sectors = self._get_sectors(cluster)
        directory_entries = []
        for entry_num, dir_entry in enumerate(
            (directory[n : n + 32] for n in range(0, len(directory), 32))
        ):
            answer = {
                "parent": parent,
                "dir_cluster": cluster,
                "entry_num": entry_num,
                "dir_sectors": dir_sectors,
                "entry_type": hw4utils.get_entry_type(unpack(dir_entry[11:12])),
                "name": hw4utils.parse_name(dir_entry),
                "deleted": dir_entry[0] == 0xE5 or dir_entry[0] == 0x00,
            }
            if answer["entry_type"] == "dir":
                answer |= {"content_cluster": self._get_first_cluster(dir_entry)}
                if answer["name"] not in self.DONT_RECUR:
                    for sub_file in self.parse_dir(
                        answer["content_cluster"], parent + "/" + answer["name"]
                    ):
                        directory_entries.append(sub_file)
            if answer["entry_type"] not in {"vol", "lfn", "dir"}:
                breakpoint()
                answer |= {
                    "filesize": unpack(dir_entry[28:]),
                    "content_sectors": self._get_sectors(
                        self._get_first_cluster(dir_entry)
                    ),
                }
                content, slack = self._get_content(
                    self._get_first_cluster(dir_entry), answer["filesize"]
                )
                answer |= {"content": self.byte_formatting(content), "slack": slack}
            directory_entries.append(answer)
        return directory_entries


def main():
    # Parse command line arguments
    if len(sys.argv) != 2:
        print(f"usage:\n\t {os.path.basename(sys.argv[0])} filename")
        exit()
    filename = sys.argv[1]
    # Parse the file and print results
    fs = Fat(filename)
    fs.info()


if __name__ == "__main__":
    main()
