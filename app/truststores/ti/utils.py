import re

ROOT_FILE_RE = {
    "PROD": re.compile(r'href="(GEM\.RCA\d+\.der)"'),
    "RT": re.compile(r'href="(GEM\.RCA\d+_TEST-ONLY\.der)"'),
    "RU": re.compile(r'href="(GEM\.RCA\d+_TEST-ONLY\.der)"'),
}

SUB_FILE_RE = {
    "PROD": re.compile(r'href="(GEM\.KOMP-CA\d+\.der)"'),
    "RT": re.compile(r'href="(GEM\.KOMP-CA\d+_TEST-ONLY\.der)"'),
    "RU": re.compile(r'href="(GEM\.KOMP-CA\d+_TEST-ONLY\.der)"'),
}