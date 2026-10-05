"""Static, synthetic received-frame samples (hex) for parser tests.

These are fixed byte strings fed to the *receive-side* parser. They contain no
real key material (EAPOL samples carry zeroed fields after Key Information)
and are never transmitted: tests block packet sockets entirely.
"""


def hx(text: str) -> bytes:
    return bytes.fromhex("".join(text.split()))


# radiotap: flags, channel 5180 MHz (5 GHz OFDM), dBm signal -42
RT_5180 = hx("00 00 10 00 2a 00 00 00  00 00 3c 14 40 01 d6 00")
# radiotap with FCS flag set (frame carries 4 trailing FCS bytes), 2437 MHz, -60 dBm
RT_2437_FCS = hx("00 00 10 00 2a 00 00 00  10 00 85 09 a0 00 c4 00")
# radiotap with bad-FCS flag
RT_BADFCS = hx("00 00 10 00 2a 00 00 00  40 00 3c 14 40 01 d6 00")
# radiotap with an extended presence bitmap (TSFT + flags + channel + signal, ext word)
RT_EXT = hx("00 00 20 00 2b 00 00 80  00 00 00 00 00 00 00 00 "
            "01 02 03 04 05 06 07 08  00 00 3c 14 40 01 c0 00")

AP = "aa bb cc dd ee ff"
STA = "10 22 33 44 55 66"
BCAST = "ff ff ff ff ff ff"

# AP -> station deauth, reason 7, seq 100
DEAUTH_UNICAST = hx(f"c0 00 3a 01 {STA} {AP} {AP} 40 06  07 00")
# AP -> broadcast disassoc, reason 3
DISASSOC_BCAST = hx(f"a0 00 00 00 {BCAST} {AP} {AP} 50 06  03 00")
# broadcast deauth protected with BIP (MMIE element 76 appended)
DEAUTH_BCAST_BIP = hx(f"c0 00 00 00 {BCAST} {AP} {AP} 60 06  07 00 "
                      "4c 10 04 00 01 00 00 00 00 00  00 00 00 00 00 00 00 00")
# unicast deauth with Protected Frame bit (body encrypted: CCMP hdr + data + MIC)
DEAUTH_PROTECTED = hx(f"c0 40 3a 01 {STA} {AP} {AP} 70 06 "
                      "01 00 00 20 00 00 00 00  99 99  00 00 00 00 00 00 00 00")
# reserved reason code 200
DEAUTH_BADREASON = hx(f"c0 00 3a 01 {STA} {AP} {AP} 80 06  c8 00")
# retry bit set, same seq as DEAUTH_UNICAST
DEAUTH_RETRY = hx(f"c0 08 3a 01 {STA} {AP} {AP} 40 06  07 00")

_SSID = "00 0b " + "45 78 61 6d 70 6c 65 53 53 49 44"          # "ExampleSSID"
_DS36 = "03 01 24"
_RSN_TRANSITION = ("30 18 01 00 00 0f ac 04 01 00 00 0f ac 04 "
                   "02 00 00 0f ac 02 00 0f ac 08 80 00")         # PSK+SAE, MFPC
_RSN_WPA3 = "30 14 01 00 00 0f ac 04 01 00 00 0f ac 04 01 00 00 0f ac 08 c0 00"  # SAE, MFPR+MFPC
_RSN_WPA2 = "30 14 01 00 00 0f ac 04 01 00 00 0f ac 04 01 00 00 0f ac 02 00 00"  # PSK, no PMF
_RSNXE_H2E = "f4 01 20"
_HT = "2d 1a " + "00 " * 26
_HE = "ff 02 23 00"
_FIXED = "00 00 00 00 00 00 00 00  64 00 11 04"                    # ts, interval 100, ESS+privacy

BEACON_TRANSITION = hx(f"80 00 00 00 {BCAST} {AP} {AP} 10 00 {_FIXED} {_SSID} {_DS36} "
                       f"{_RSN_TRANSITION} {_HT} {_HE}")
BEACON_WPA3 = hx(f"80 00 00 00 {BCAST} {AP} {AP} 20 00 {_FIXED} {_SSID} {_DS36} {_RSN_WPA3} {_RSNXE_H2E}")
PROBE_RESP_WPA2 = hx(f"50 00 3a 01 {STA} 02 13 37 00 00 01 02 13 37 00 00 01 30 00 {_FIXED} "
                     f"{_SSID} 03 01 06 {_RSN_WPA2}")
BEACON_OPEN_HIDDEN = hx(f"80 00 00 00 {BCAST} {AP} {AP} 40 00 "
                        "00 00 00 00 00 00 00 00  64 00 01 00  00 00 03 01 24")
BEACON_WPA1 = hx(f"80 00 00 00 {BCAST} {AP} {AP} 50 00 {_FIXED} {_SSID} "
                 "dd 16 00 50 f2 01 01 00 00 50 f2 02 01 00 00 50 f2 02 01 00 00 50 f2 02")
# RSN element claims 5 pairwise suites but carries one: malformed
BEACON_BAD_RSN = hx(f"80 00 00 00 {BCAST} {AP} {AP} 60 00 {_FIXED} {_SSID} "
                    "30 0c 01 00 00 0f ac 04 05 00 00 0f ac 04")

# EAPOL 4-way handshake metadata samples (QoS data). Only Key Information is
# meaningful; every byte after it is zero.
_LLC = "aa aa 03 00 00 00 88 8e"
_KEY_TAIL = "00 10 " + "00 " * 8
EAPOL_M1 = hx(f"88 02 3a 01 {STA} {AP} {AP} 00 01 07 00 {_LLC} 02 03 00 5f 02 00 8a {_KEY_TAIL}")
EAPOL_M2 = hx(f"88 01 3a 01 {AP} {STA} {AP} 00 02 07 00 {_LLC} 01 03 00 75 02 01 0a {_KEY_TAIL}")
EAPOL_M3 = hx(f"88 02 3a 01 {STA} {AP} {AP} 10 01 07 00 {_LLC} 02 03 00 97 02 13 ca {_KEY_TAIL}")
EAPOL_M4 = hx(f"88 01 3a 01 {AP} {STA} {AP} 10 02 07 00 {_LLC} 01 03 00 5f 02 03 0a {_KEY_TAIL}")
EAPOL_START = hx(f"08 01 3a 01 {AP} {STA} {AP} 20 02 {_LLC} 01 01 00 00")
DATA_ENCRYPTED = hx(f"88 41 3a 01 {AP} {STA} {AP} 30 02 07 00 01 00 00 20 00 00 00 00 de ad be ef")
DATA_PLAIN_IP = hx(f"08 01 3a 01 {AP} {STA} {AP} 40 02 aa aa 03 00 00 00 08 00 45 00")

AUTH_OPEN = hx(f"b0 00 3a 01 {AP} {STA} {AP} 50 02 00 00 01 00 00 00")
AUTH_SAE = hx(f"b0 00 3a 01 {AP} {STA} {AP} 60 02 03 00 01 00 00 00")
ASSOC_REQ = hx(f"00 00 3a 01 {AP} {STA} {AP} 70 02 11 04 0a 00 {_SSID}")
ASSOC_RESP = hx(f"10 00 3a 01 {STA} {AP} {AP} 80 02 11 04 00 00 01 c0")
PROBE_REQ = hx(f"40 00 00 00 {BCAST} {STA} {BCAST} 90 02 {_SSID}")
ACK = hx(f"d4 00 00 00 {STA}")
