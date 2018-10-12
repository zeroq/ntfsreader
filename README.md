ntfsreader
==========

ntfsReader is a Python script for parsing NTFS partitions and extracting metainformation from all MFT entries. The script takes a physical drive (e.g. /dev/sda) as an input argument and then finds all NTFS partitions after parsing the Master Boot Record (MBR) and extracts the metainformation from all MFT entries of those partitions. Currently version 0.1 cannot handle extended partitions.

Example Usage:

* To display the partitions on a device
    
        python ntfsReader.py /dev/sda --part

* To display all MFT entries of all NTFS partitions on a device
    
        python ntfsReader.py /dev/sda --mft

* To display all MFT entries of a VMDK file
    
        python ntfsReader.py <path_to_vmdk> --vmdk --mft
