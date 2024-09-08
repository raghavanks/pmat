rule PMATDetectWannaCry {
    
    meta: 
        last_updated = "2024-09-08"
        author = "Raghavan"
        description = "A Yara rule for WannaCry based on strings found during static analysis."
    strings:
        // Fill out identifying strings and other criteria
        $s1 = "iphlpapi.dll" ascii               // match this ascii string
        $s2 = "mssecsvc.exe"                    
	$s3 = "cmd.exe /c"
	$s4 = "icacls . /grant Everyone"
	$s5 = "r.wnry" 
	$s6 = "tasksche.exe" 
	$s7 = "http://" 
        $pe_magic_byte = "MZ"                         // PE magic byte
	$sb64="fd4d9L7LS8S9B/wrEIUITZWAQeOPEtmB9vuq8KgrAP3loQnkmQdvP0QF9j8CIF9EdmNK3KEnH2CBme0Xxbx/WOOCBCDPvvjJYvcvf95egcjZ+dWquiACPOkTFW3JS6M+sLa/pa6uVzjjWOIeBX+V3Pu12C9PjUWOoRfFOAX+SFzVJL4ugpzxsVRvgFvIgqXupq+y6bfWsK90pWeE5qzBSTKcSepm0GPGr/rJg0hJn4aVBbsdnXxM2ZCDorVUsFUsF9vXC2UIJlsx5yEdThqQ5MoEd6tRwRSfYA87dvMJrPfpB8qLIaFHNX684tJJn30Bx0vnkLW3oRcGKuBqZdJ/PI4yIm++QVKkBLVa106S2gpwejplTs510cW0VN+8yVJAuZhPZSij7FLlAE4zS0bjSo6lP098nSduB9h9eziOeLhd1KG16h+g8xP2CV1VsNhr9ao+2cmCeiHYhbceDilST+ASGztHMWarFIlJUL6qlCrptzEJTk+er2j7SfHHT0nNtEa4+JRvPq5C21Kd1pcQ7vKlvZ5flQs1vvXTGZhYZKTv5lrdWNEtVEzGh+KvTFJxqKz5LNvLPT/0yRqcO6deL/nmv3UCt+B0Ut2X6cNonJG76Ut78wcRv4YP2MwApDS9fSz2AGGVxm246qiUiKWWtM6w40aDjuPH7gCQEoDHwhJgvLgmSaibPwjJrDzO0hMGDrp6SxwIFNS1G2oAPcvOn4CL4JDuLCBs08NtDrQysl0WMgCIBM+1O5D8Lue0J0359/4fCzqNCvBoqgyss9YWZb6wy6C/Kz4ak/Qmt74uXsA71fduIs3zEs6CAPpQQlvXMlZYWczpenAS2b+gO6aHHEFZBJmJ6Vy9I4RoLIPH/8Ig1ManJzkgPODvGvcuE/WUDFmiIiwGMlFMFTchBTVUQSPaLFWMUk6FqeO1LTY2/Rc3lSWSuBVeAAtlUNa6kfXqh/9=="
    condition:
        // Fill out the conditions that must be met to identify the binary
        $pe_magic_byte at 0      and                  // PE magic byte at 00
        all of ($s*)                                  // all strings starting with s.
}    
