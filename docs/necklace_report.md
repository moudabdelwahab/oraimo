# necklace.cfa — Bluetooth Capture Analysis

**File:** `necklace.cfa`: BTSnoop v1, datalink 2001 (Linux Monitor / btmon), 2 586 records, 792 730 bytes
**Capture window:** 2026‑09‑24 15:02:03.154 → 15:03:19.035 (≈76 s)
**Tools used:** btmon 5.72 (`btmon -r … -T`), tshark (Wireshark dissectors), plus a custom Python record parser for raw bytes. hid-tools was used for the HID descriptor.

### Conventions used in this report

* **Frame** is the Wireshark/tshark `frame.number`. It counts every record in the file, including notes.
* **#N** is the btmon packet number. It counts HCI packets only, so Frame = #N + 7 near the start of the capture and grows by a few after the bluetoothd notes.
* **Direction:** `TX` = Host → Headset (`<` in btmon). `RX` = Headset → Host (`>` in btmon).
* **CID** is the L2CAP destination CID that is actually on the wire. RX packets carry the host's CID, and TX packets carry the headset's CID.
* Raw bytes are the L2CAP payload unless marked otherwise. The ACL and L2CAP headers are stripped.
* **[FACT]** means directly observed in the packets. **[HYPOTHESIS]** means an inference that the capture does not prove.

> ⚠️ **Sensitive data:** the capture contains the BR/EDR **link key** for this pairing, in plaintext. It is in *HCI Link Key Request Reply*, Frame 77 / #66 (`cb99…deec`). Anyone who has the file and is within radio range can decrypt or impersonate this link. Don't publish the raw file. Re-pair the headset if the file has already been shared.

---

## 1. Devices involved

| Role | Address | Identity | Evidence |
|---|---|---|---|
| **Host / local controller** (hci0) | `AC:7B:A1:2B:6E:A6` | Intel Corp. controller on USB (Primary), Linux 7.0.0‑29‑generic, BT subsystem 2.22, mgmt 1.23 (bluetoothctl + bluetoothd) | Frames 1–7 (Notes, New Index, Index Info "Intel Corp."). Intel vendor HCI event *PTT Switch Notification (0x26)* at Frame 42 / #34, 15:02:28.090738 |
| **Remote headset** | `28:52:E0:0F:92:0A` | **"oraimo Necklace Lite"** | Remote Name Req Complete, Frame 70 / #60, 15:02:28.136793 |

Only one ACL connection exists: **handle 0x0100 (256)**. No SCO/eSCO, LE or ISO links appear in the capture.

## 2. Vendor / manufacturer [FACT, with sources]

| Layer | Value | Source |
|---|---|---|
| Brand (product name) | **oraimo** ("oraimo Necklace Lite") | Remote name, Frame 70 |
| OUI of BD_ADDR 28:52:E0 | **Layon International Electronic & Telecom Co., Ltd** (OEM/ODM) | IEEE OUI (btmon decode) |
| Chipset / SDK vendor | **Zhuhai Jieli Technology Co., Ltd (JieLi)**, Bluetooth SIG company ID **0x05D6** | PnP/DI record, Frame 264 / #253: VendorIDSource 0x0001 (SIG), VendorID 0x05D6, ProductID 0x000A, Version 0x0240. Every SDP service name uses the JieLi SDK prefix `JL_A2DP`, `JL_HFP`, `JL_HID`, `JL_SPP` |

[HYPOTHESIS] oraimo is a Transsion brand. The product is most likely an ODM design by Layon on a JieLi SoC (an AC69xx/AC70xx-class part). The capture cannot determine the exact SoC part number.

## 3. Remote identity details

* BD_ADDR `28:52:E0:0F:92:0A`, name `oraimo Necklace Lite`.
* LMP features, page 0 (Frame 51 / #41): `bf fe 8d fa c8 2d 79 87`. These include 3/5‑slot, sniff, role switch, EDR ACL **2 Mbps only** (3 Mbps is not set), 3/5‑slot EDR, eSCO EV3, EDR eSCO 2 Mbps, SSP, EIR, pause encryption, non-flushable PBF, **LE Supported (Controller)**, extended features.
* Features page 1 (Frame 54 / #44): `01 00…`, which is SSP host support only. **Secure Connections is not supported.** Encryption is therefore **E0** (Frame 82 / #71 "Enabled with E0"), with a 16‑byte key (Frame 84 / #73).
* The PnP/DI record gives a DI spec of 0x0103 and a firmware/"version" field of 0x0240.
* The HFP AT+XAPL line from the headset uses the placeholder IDs `ABCD-1234-0100` (Frame 235 / #224). These are JieLi SDK defaults, not a real vendor/product ID.

## 4. Profiles and protocols observed

| Protocol / Profile | Seen? | Where |
|---|---|---|
| HCI (cmd/evt/ACL) | ✅ | 13 commands, 1245 events, 1314 ACL frames |
| L2CAP signaling | ✅ | CID 0x0001 |
| SDP | ✅ | PSM 1 |
| RFCOMM → **HFP 1.8** (headset = HF, host = AG) | ✅ | PSM 3, server channel 4 (DLCI 8) |
| AVDTP 1.3 / **A2DP 1.3** (SBC) | ✅ | PSM 25 (signaling + media) |
| AVCTP 1.4 / **AVRCP 1.5** | ✅ | PSM 23 |
| HID (HIDP) | ⚠️ advertised; L2CAP opened but immediately torn down or refused; **no HID reports exchanged** | PSM 17 / PSM 19 |
| SPP ×2 (incl. custom 128‑bit UUID) | ⚠️ **advertised only, never opened** | RFCOMM ch 1 and ch 10 (SDP) |
| AVRCP Browsing (PSM 0x1B) | ❌ never opened, and not listed in SDP | — |
| SCO/eSCO (voice) | ❌ | — |
| Vendor-specific | Apple HFP extensions (`AT+XAPL`, `AT+IPHONEACCEV`); Intel HCI vendor event; JieLi custom SPP UUID (advertised only) | see §13/§14 |

tshark protocol hierarchy: SDP 10 frames, RFCOMM 55 (HFP 43), AVDTP 14, AVCTP/AVRCP 36, A2DP/RTP/SBC 1112. There are also 6 frames from the previous session that tshark could not dissect (§5b). With L2CAP signaling added, these account for all 1314 ACL frames. **Nothing in the capture is undecoded or unexplained.**

### 4a. Headset SDP database (Frames 240, 256, 261 reassembled, plus 73 and 264)

| Record handle | Service | Protocol / params | Profile version | SupportedFeatures (0x0311) | ServiceName (0x0100) |
|---|---|---|---|---|---|
| 0x00010001 | Audio Sink 0x110B | L2CAP PSM 0x0019 / AVDTP 0x0103 | A2DP 0x0103 | 0x0001 (Headphone) | `JL_A2DP` |
| 0x00010002 | A/V Remote Control 0x110E + Controller 0x110F | L2CAP PSM 0x0017 / AVCTP 0x0104 | **AVRCP 0x0105** | **0x0001** (Cat‑1 only; no browsing, no cover art) | — |
| 0x00010005 | A/V Remote Control **Target** 0x110C | L2CAP PSM 0x0017 / AVCTP 0x0104 | AVRCP 0x0105 | **0x0002** (Cat‑2: monitor/amplifier, i.e. absolute volume) | — |
| 0x00010003 | Handsfree 0x111E + Generic Audio | RFCOMM ch **4** | HFP 0x0108 | 0x003F (EC/NR, 3‑way, CLI, VR, remote vol, wide‑band) | `JL_HFP` |
| 0x00010006 | **HID 0x1124** | L2CAP PSM 0x0011 (ctrl) + 0x0013 (intr) | HID 0x0100 | — | `JL_HID`, description `hid key` |
| 0x00010004 | Serial Port 0x1101 | RFCOMM ch **1** | SPP 0x0102 | — | `JL_SPP` |
| 0x00010011 | **Custom UUID `fe010000-1234-5678-abcd-00805f9b34fb`** | RFCOMM ch **10 (0x0a)** | 0x0100 | — | `JL_SPP` |
| 0x0001000A | PnP Information 0x1200 | — | DI 0x0103 | VID 0x05D6 / PID 0x000A / Ver 0x0240 / src SIG | — |

HID record attributes: ParserVersion 0x0111; DeviceSubclass **0x40** (keyboard); CountryCode 0x21; VirtualCable true; **ReconnectInitiate true**; LangID 0x0409; SDPDisable false; BatteryPower true; RemoteWake true; ProfileVersion 0x0100; NormallyConnectable true; BootDevice true.

## 5. L2CAP channels, PSMs, CIDs and handles

All traffic is on **ACL handle 0x0100 (256)**, with the host as central. The host paged the headset with Create Connection at Frame 40 / #32, 15:02:25.205, and Connect Complete arrived at Frame 43 / #35, 15:02:28.094.

### 5a. Session 2 (fully captured)

| PSM | Use | Host CID | Headset CID | Opened by / frame | Rx MTU host / headset | Closed |
|---|---|---|---|---|---|---|
| 0x0001 | SDP | 0x0040 | 0x006B | Host, Frame 60 / #50, 15:02:28.113651 | 672 (default) / 679 | Host, Frame 265 / #254, 15:02:30.752 |
| 0x0003 | RFCOMM (HFP, DLCI 8) | 0x0041 | 0x006C | Host, #74, 15:02:28.222919 | 1021 / 679 | open at end |
| 0x0019 | AVDTP signaling | 0x0042 | 0x006D | Host, Frame 115 / #104, 15:02:28.278930 | 672 / 679 | open at end |
| 0x0019 | AVDTP media | 0x0043 | 0x006E | Host, Frame 158 / #147, 15:02:28.323744 | 1021 / 679 | open at end |
| 0x0011 | HID Control | 0x0044 | 0x006F | Host, Frame 173 / #162 | — / 679 | **Headset** disconnects it at Frame 222 / #211, 15:02:28.367739 (29 ms after opening) |
| 0x0017 | **AVCTP control (AVRCP)** | **0x0045** | **0x0070** | Host, Frame 174 / #163, 15:02:28.339538 | 672 / 679 | open at end |
| 0x0013 | HID Interrupt | 0x0046 | 0x0071 | Host, Frame 194 / #183 | — / 679 | **Headset** disconnects it at Frame 216 / #205, 15:02:28.364561 |
| 0x0011 | HID Control (headset‑initiated) | 0x0040 | 0x0072 | **Headset**, Frame 537 / #525, 15:02:33.355581 | — | Host disconnects it at #553 (bluetoothd: "Refusing input device connect: Operation already in progress") |
| 0x0011 | HID Control (headset‑initiated, 2nd) | 0x0044 | 0x0073 | **Headset**, Frame 541 / #529 | — | Host disconnects it at Frame 556 / #543 |
| 0x0013 | HID Interrupt (headset‑initiated) | 0x0046 | 0x0074 | **Headset**, Frame 559 / #546 | — | Host sends Pending/Authorization-pending, then **Refused – security block** at Frame 2561 / #2547, 15:03:13.644 (≈40 s later) |
| 0x0013 | HID Interrupt (headset‑initiated, 2nd) | 0x0047 | 0x0075 | **Headset**, Frame 563 / #550 | — | Refused – security block, Frame 568 / #554 ("Refusing connection … setup in progress") |

### 5b. Session 1 (teardown only; the capture began mid‑connection)

The CID pairs 0x0045↔0x0067, 0x0043↔0x0065, 0x0041↔0x0063 and 0x0042↔0x0064 were torn down between 15:02:14.235 and 15:02:14.636. The ACL then dropped with reason 0x13 "Remote User Terminated Connection" (Frame 36 / #29, 15:02:14.791168). btmon/tshark cannot name the PSMs because the setup happened before the capture started. I decoded the payloads by hand:

| Frame / # | Time | Dir | CID | Raw | Decode |
|---|---|---|---|---|---|
| 9 / #2 | 15:02:14.235579 | TX | 0x0001 | `06 13 04 00 67 00 45 00` | L2CAP Disconnection Req, dst 0x0067 / src 0x0045. [HYPOTHESIS] this was the AVCTP channel, since BlueZ drops AVRCP first. |
| 12 / #5 | 15:02:14.250031 | TX | 0x0064 | `40 08 04` | AVDTP **CLOSE** cmd, label 4, ACP SEID 1 |
| 13 / #6 | 15:02:14.254355 | TX | 0x0063 | `23 53 01 28` | RFCOMM **DISC** DLCI 8 (HFP) |
| 18 / #11 | 15:02:14.417207 | RX | 0x0042 | `42 08` | AVDTP CLOSE accept |
| 22 / #15 | 15:02:14.422587 | RX | 0x0041 | `23 73 01 02` | RFCOMM UA DLCI 8 |
| 23 / #16 | 15:02:14.422682 | TX | 0x0063 | `03 53 01 fd` | RFCOMM DISC DLCI 0 (multiplexer) |
| 26 / #19 | 15:02:14.427617 | RX | 0x0041 | `03 73 01 d7` | RFCOMM UA DLCI 0 |

In both sessions the host allocated its CIDs in the same order, so the local CID ↔ profile mapping is stable: 0x41 RFCOMM, 0x42 AVDTP‑sig, 0x43 AVDTP‑media, 0x45 AVCTP.

## 6. AVRCP version and capabilities

**Roles [FACT].** Both devices act as CT and TG over a **single AVCTP control channel** (host CID 0x0045 / headset CID 0x0070).

* **Headset CT → Host TG:** play/pause buttons, metadata queries, and play‑status/track registrations.
* **Host CT → Headset TG:** absolute‑volume registration.

**Version.** The headset advertises **AVRCP 1.5 over AVCTP 1.4** (SDP record 0x00010002 and 0x00010005).

* CT features 0x0001: Category 1 only. Browsing, cover art and multiple players are not claimed.
* TG features 0x0002: Category 2 (amplifier). This means absolute‑volume TG.

**Events the headset TG supports.** This is its own GetCapabilities response to the host (Frame 229 / #218, RX, 15:02:28.370569):

```
02 11 0e | 0c 48 00 | 00 19 58 | 10 00 00 05 | 03 03 01 06 0d
                                               │  │  └ events: 0x01 PLAYBACK_STATUS_CHANGED, 0x06 BATT_STATUS_CHANGED, 0x0D VOLUME_CHANGED
                                               │  └ count 3
                                               └ CapabilityID 0x03 (EventsSupported)
```

**Important correction to the premise.** The list containing EVENT_PLAYBACK_STATUS_CHANGED, EVENT_TRACK_CHANGED, **EVENT_TRACK_REACHED_END**, **EVENT_TRACK_REACHED_START**, **EVENT_PLAYER_APPLICATION_SETTING_CHANGED**, AVAILABLE_PLAYERS_CHANGED and ADDRESSED_PLAYER_CHANGED is **not the headset's**. It is **BlueZ's (the Linux host's) TG capability list**, sent *to* the headset in Frame 201 / #190 (TX, 15:02:28.356009):

```
12 11 0e | 0c 48 00 | 00 19 58 | 10 00 00 09 | 03 07 01 02 03 04 08 0a 0b
```

The headset **registered only 0x01 and 0x02** out of that list (Frames 223/224). It never registered 0x03, 0x04, 0x08, 0x0A or 0x0B, and **none of those events was ever reported** in either direction.

## 7–8. Complete AVRCP command/response inventory (all 36 AVCTP frames)

AVCTP header byte = `label<<4 | pkt_type<<2 | C/R<<1 | IPID`. Every frame has PID `11 0e`. The AV/C address byte is `48` = subunit type 9 (**Panel**), ID 0.

| Frame / # | Time | Dir | CID | Raw bytes (AVCTP payload) | Decode |
|---|---|---|---|---|---|
| 199 / #188 | 15:02:28.354856 | RX (HS→Host) | 0x0045 | `10 11 0e 01 48 00 00 19 58 10 00 00 01 03` | Cmd lbl1 STATUS, VendorDep, SIG, **GetCapabilities(Events)** |
| 201 / #190 | 15:02:28.356009 | TX | 0x0070 | `12 11 0e 0c 48 00 00 19 58 10 00 00 09 03 07 01 02 03 04 08 0a 0b` | Rsp lbl1 STABLE: host TG events 01,02,03,04,08,0A,0B |
| 202 / #191 | 15:02:28.356015 | TX (Host→HS) | 0x0070 | `00 11 0e 01 48 00 00 19 58 10 00 00 01 03` | Cmd lbl0 STATUS, **GetCapabilities(Events)** |
| 204 / #193 | 15:02:28.357635 | RX | 0x0045 | `20 11 0e 01 48 00 00 19 58 20 00 00 09 00 00 00 00 00 00 00 00 00` | Cmd lbl2 **GetElementAttributes**, id PLAYING(0), count 0 = all attributes |
| 206 / #195 | 15:02:28.359444 | TX | 0x0070 | `22 11 0e 0c 48 00 00 19 58 20 00 00 12 02 00 00 00 01 00 6a 00 00 00 00 00 07 00 6a 00 01 30` | Rsp lbl2 STABLE: Title="" (UTF‑8), Duration="0" |
| 223 / #212 | 15:02:28.367741 | RX | 0x0045 | `30 11 0e 03 48 00 00 19 58 31 00 00 05 01 00 00 00 00` | Cmd lbl3 NOTIFY **RegisterNotification EVENT_PLAYBACK_STATUS_CHANGED** |
| 224 / #213 | 15:02:28.367741 | RX | 0x0045 | `40 11 0e 03 48 00 00 19 58 31 00 00 05 02 00 00 00 00` | Cmd lbl4 NOTIFY **RegisterNotification EVENT_TRACK_CHANGED** |
| 226 / #215 | 15:02:28.367886 | TX | 0x0070 | `32 11 0e 0f 48 00 00 19 58 31 00 00 02 01 00` | Rsp lbl3 **INTERIM** PlayStatus=STOPPED |
| 228 / #217 | 15:02:28.369720 | TX | 0x0070 | `42 11 0e 0f 48 00 00 19 58 31 00 00 09 02 00 00 00 00 00 00 00 00` | Rsp lbl4 INTERIM TrackUID=0 |
| 229 / #218 | 15:02:28.370569 | RX | 0x0045 | `02 11 0e 0c 48 00 00 19 58 10 00 00 05 03 03 01 06 0d` | Rsp lbl0 STABLE: headset TG events 01,06,0D |
| 232 / #221 | 15:02:28.370719 | TX | 0x0070 | `10 11 0e 03 48 00 00 19 58 31 00 00 05 0d 00 00 00 00` | Cmd lbl1 NOTIFY **Register EVENT_VOLUME_CHANGED** |
| 244 / #233 | 15:02:28.380040 | RX | 0x0045 | `50 11 0e 01 48 00 00 19 58 20 00 00 09 00×8 00` | Cmd lbl5 GetElementAttributes (repeat) |
| 245 / #234 | 15:02:28.380049 | RX | 0x0045 | `12 11 0e 0f 48 00 00 19 58 31 00 00 02 0d 7f` | Rsp lbl1 INTERIM Volume=0x7F (127, 100 %) |
| 246 / #235 | 15:02:28.380655 | TX | 0x0070 | (same as Frame 206 with lbl5) | Rsp STABLE Title="", Duration="0" |
| 2388 / #2374 | 15:03:03.679598 | RX | 0x0045 | `60 11 0e 00 48 7c 44 00` | **PASSTHROUGH PLAY pressed** (lbl6) |
| 2389 / #2375 | 15:03:03.679907 | TX | 0x0070 | `62 11 0e 09 48 7c 44 00` | ACCEPTED |
| 2393 / #2379 | 15:03:03.698658 | RX | 0x0045 | `70 11 0e 00 48 7c c4 00` | **PLAY released** (lbl7) |
| 2394 / #2380 | 15:03:03.698895 | TX | 0x0070 | `72 11 0e 09 48 7c c4 00` | ACCEPTED |
| 2555 / #2541 | 15:03:12.059957 | RX | 0x0045 | `80 11 0e 00 48 7c 44 00` | **PLAY pressed** (lbl8) |
| 2556 / #2542 | 15:03:12.060315 | TX | 0x0070 | `82 11 0e 09 48 7c 44 00` | ACCEPTED |
| 2558 / #2544 | 15:03:12.069599 | RX | 0x0045 | `90 11 0e 00 48 7c c4 00` | **PLAY released** (lbl9) |
| 2559 / #2545 | 15:03:12.070310 | TX | 0x0070 | `92 11 0e 09 48 7c c4 00` | ACCEPTED |
| 2563 / #2549 | 15:03:14.727646 | RX | 0x0045 | `12 11 0e 0d 48 00 00 19 58 31 00 00 02 0d 78` | Rsp lbl1 **CHANGED Volume=0x78 (120, 94.5 %)** |
| 2564 / #2550 | 15:03:14.727829 | TX | 0x0070 | `20 11 0e 03 48 00 00 19 58 31 00 00 05 0d 00 00 00 00` | Cmd lbl2 re‑Register VOLUME_CHANGED |
| 2566 / #2552 | 15:03:14.734612 | RX | 0x0045 | `22 11 0e 0f 48 00 00 19 58 31 00 00 02 0d 78` | INTERIM Volume=120 |
| 2567 / #2553 | 15:03:15.914669 | RX | 0x0045 | `22 11 0e 0d 48 00 00 19 58 31 00 00 02 0d 7f` | **CHANGED Volume=127 (100 %)** |
| 2568 / #2554 | 15:03:15.914989 | TX | 0x0070 | `30 11 0e 03 48 00 00 19 58 31 00 00 05 0d 00 00 00 00` | Cmd lbl3 re‑Register VOLUME_CHANGED |
| 2570 / #2556 | 15:03:15.919511 | RX | 0x0045 | `32 11 0e 0f 48 00 00 19 58 31 00 00 02 0d 7f` | INTERIM Volume=127 |
| 2572 / #2558 | 15:03:17.769711 | RX | 0x0045 | `a0 11 0e 00 48 7c 46 00` | **PAUSE pressed** (lbl10) |
| 2573 / #2559 | 15:03:17.770078 | TX | 0x0070 | `a2 11 0e 09 48 7c 46 00` | ACCEPTED |
| 2578 / #2564 | 15:03:18.270632 | RX | 0x0045 | `b0 11 0e 00 48 7c c6 00` | **PAUSE released** (lbl11) |
| 2579 / #2565 | 15:03:18.271118 | TX | 0x0070 | `b2 11 0e 09 48 7c c6 00` | ACCEPTED |
| 2581 / #2567 | 15:03:19.028703 | RX | 0x0045 | `c0 11 0e 00 48 7c 44 00` | **PLAY pressed** (lbl12) |
| 2582 / #2568 | 15:03:19.029189 | TX | 0x0070 | `c2 11 0e 09 48 7c 44 00` | ACCEPTED |
| 2584 / #2570 | 15:03:19.034605 | RX | 0x0045 | `d0 11 0e 00 48 7c c4 00` | **PLAY released** (lbl13) |
| 2585 / #2571 | 15:03:19.035093 | TX | 0x0070 | `d2 11 0e 09 48 7c c4 00` | ACCEPTED (last packet in the file) |

Summary counts:

* **Headset → host:** 13 commands (8 passthrough, 1 GetCapabilities, 2 GetElementAttributes, 2 RegisterNotification) and 6 responses (the GetCapabilities STABLE, plus 5 volume responses: 3 INTERIM and 2 CHANGED).
* **Host → headset:** 1 GetCapabilities, 3 RegisterNotification(VOLUME), and 13 responses.

**Not present anywhere:** SetAbsoluteVolume (PDU 0x50), GetPlayStatus (0x30), the PlayerApplicationSetting PDUs (0x11–0x16), SetAddressedPlayer, any browsing PDUs, UNIT INFO / SUBUNIT INFO, or VENDOR_UNIQUE passthrough (0x7E).

## 9. Passthrough decode

| Button | Op ID | Press byte | Release byte | Occurrences (press/release frames) | Press→release gap |
|---|---|---|---|---|---|
| PLAY | 0x44 | `44` | `c4` | 2388/2393, 2555/2558, 2581/2584 | 19.1 ms, 9.6 ms, 5.9 ms |
| PAUSE | 0x46 | `46` | `c6` | 2572/2578 | 500.9 ms (see note) |

**Never observed:** STOP 0x45, FORWARD/NEXT 0x4B, BACKWARD/PREVIOUS 0x4C, VOLUME_UP 0x41, VOLUME_DOWN 0x42, MUTE 0x43, FAST_FORWARD 0x49, REWIND 0x48, POWER 0x40, and VENDOR_UNIQUE 0x7E.

**Notes:**

* **[FACT]** The PLAY press→release gaps are 6–19 ms, far shorter than a human press. **[HYPOTHESIS]** The firmware detects the gesture internally and then emits a *synthetic* press+release pair, so AVRCP press duration carries no information about how long you held the button. Long-press or double-press gestures would be resolved inside the headset.
* **[FACT]** The 500 ms PAUSE gap has a different cause. The link went into **sniff mode, 500 ms interval** (Frame 2571 / #2557, 15:03:17.280), and the release was only delivered after the host exited sniff (Mode Change → Active at 15:03:18.268208, Frame 2576). The gap is radio latency, not hold time.
* **[FACT]** The headset registered PLAYBACK_STATUS_CHANGED, and BlueZ answered INTERIM **STOPPED** (Frame 226). BlueZ never sent a CHANGED, although A2DP streamed twice. As far as AVRCP is concerned, the headset always believed the host was stopped.
* **[FACT]** The button sequence was PLAY, PLAY, PAUSE, PLAY. The first PLAY (15:03:03.68) was sent while A2DP was actively streaming, and the host suspended the stream about 1.5 s later (AVDTP Suspend, Frame 2551 / #2537, 15:03:05.156). This does not fit a pure "stream state → PLAY/PAUSE" rule, and it does not fit a strict toggle either. **[HYPOTHESIS]** The choice depends on internal firmware state together with the stale AVRCP status. See experiment H‑3.

## 10–11. Vendor Dependent commands, Company IDs and PIDs

* **Company ID 0x001958** appears in every Vendor Dependent frame (15 of the 36 frames). 0x001958 is the **Bluetooth SIG's own IEEE company ID**, which the AVRCP specification requires for all standard AVRCP metadata PDUs. Its presence means "standard AVRCP", **not a proprietary vendor extension**.
* **PID 0x110E** is the AVCTP Profile Identifier. It is the A/V Remote Control service-class UUID, not a vendor product ID. It is on all 36 frames.
* **AVRCP PDUs observed:** 0x10 GetCapabilities, 0x20 GetElementAttributes, 0x31 RegisterNotification. All three are defined by the AVRCP specification.
* **Result: the capture contains zero proprietary AVRCP commands.** No non‑SIG company ID appears, and no VENDOR_UNIQUE passthrough appears.

## 12. AVRCP events registered or reported

| Event | Registered by | Registered at | Reports |
|---|---|---|---|
| 0x01 PLAYBACK_STATUS_CHANGED | Headset → Host | Frame 223 (lbl3) | INTERIM STOPPED (Frame 226); **no CHANGED ever**; still pending at end of capture |
| 0x02 TRACK_CHANGED | Headset → Host | Frame 224 (lbl4) | INTERIM UID 0 (Frame 228); no CHANGED |
| 0x0D VOLUME_CHANGED | Host → Headset | Frames 232, 2564, 2568 | INTERIM 127 → **CHANGED 120** (15:03:14.73) → INTERIM 120 → **CHANGED 127** (15:03:15.91) → INTERIM 127 |
| 0x03 TRACK_REACHED_END, 0x04 TRACK_REACHED_START, 0x08 PLAYER_APPLICATION_SETTING_CHANGED, 0x0A, 0x0B | — | **only listed** in the host's capability list (Frame 201); never registered | none |
| 0x06 BATT_STATUS_CHANGED | — | **only listed** in the headset's capability list (Frame 229); **the host never registered it** | none |

The volume changes: **[FACT]** the headset TG reported them, and the host sent no SetAbsoluteVolume before either one. The change therefore originated **on the headset**. **[HYPOTHESIS]** You pressed volume‑down and then volume‑up (or used a long‑press gesture) around 15:03:14–15:03:16. If so, **the necklace's volume keys don't produce VOLUME_UP/DOWN passthrough**. It changes volume locally and reports it through absolute volume. One step is 127 → 120 (−7), which is consistent with a 16‑step table (127·15/16 ≈ 119 → 120). That table is also a hypothesis.

## 13. Vendor-specific command sequences

The capture contains no vendor AVRCP, but it does show these vendor-specific items:

1. **Apple HFP extension (the headset acts like an iOS accessory).**
   * Frame 235 / #224 RX: `AT+XAPL=ABCD-1234-0100,10`. Vendor ID ABCD, product ID 1234 and version 0100 are placeholders. Features = 10 = 0b1010, meaning battery reporting (bit 1) and Siri status (bit 3).
   * Frame 237 / #226 TX: `+XAPL=iPhone,2` (the host AG claims battery-reporting support). **[HYPOTHESIS]** This reply format is PipeWire's native HFP backend.
   * **Battery reports** are sent as RFCOMM UIH frames on DLCI 8 (`21 ef 2b …`):

     | Frame / # | Time | AT command | Battery |
     |---|---|---|---|
     | 249 / #238 and 250 / #239 (sent twice, 3 µs apart) | 15:02:28.382 | `AT+IPHONEACCEV=1,1,6` | level 6 (≈70 %) |
     | 941 / #927 | 15:02:44.202667 | `AT+IPHONEACCEV=1,1,5` | ≈60 % |
     | 1371 / #1357 | 15:02:54.218788 | `AT+IPHONEACCEV=1,1,6` | ≈70 % |

     The format is `AT+IPHONEACCEV=<npairs>,<key>,<val>`. Key 1 is battery, value 0–9. The level mapping follows the Apple spec convention (value+1)×10 %.
2. **The JieLi proprietary channel is advertised but was never used.** SPP with the custom UUID `fe010000-1234-5678-abcd-00805f9b34fb` is on RFCOMM ch 10, and there is also a plain SPP on ch 1. **[HYPOTHESIS]** This is the JieLi "RCSP"/app/OTA control channel used by vendor companion apps for EQ, key remapping, device info, firmware update and similar features. **No RFCOMM DLCI 2 or DLCI 20 SABM appears in the capture**, so its protocol is **not observable here**.
3. **The HID "hid key" device** announces a Consumer Control report map (next section). The headset tried to bring HID up but BlueZ refused it, so **no HID reports were exchanged**.
4. **Intel controller vendor event** (Frame 42 / #34): *PTT Switch Notification*, EDR packet-type table. This is host‑side controller housekeeping and has nothing to do with the headset.

### 13a. HID report descriptor (SDP attribute 0x0206, 81 bytes)

```
05 0c 09 01 a1 01 85 02 75 10 95 02 15 01 26 8c 02 19 01 2a 8c 02 81 00 c0
05 0c 09 01 a1 01 85 03 15 00 25 01 75 01 95 0d 0a 23 02 0a 21 02 0a b1 01
09 b8 09 b6 09 cd 09 b5 09 e2 09 ea 09 e9 09 30 0a 07 03 0a 08 03 81 02 95 01
75 0b 81 03 c0
```

* **Report ID 2 (4 bytes):** two 16‑bit Consumer-page usage slots in an array, usage range 0x001–0x28C. This form can send *any* consumer key.
* **Report ID 3 (3 bytes):** a 13‑bit bitmap followed by 11 padding bits. Bit order: 0 AC Home (0x223), 1 AC Search (0x221), 2 AL Screen Saver (0x1B1), 3 Eject (0xB8), 4 Scan Previous (0xB6), 5 Play/Pause (0xCD), 6 Scan Next (0xB5), 7 Mute (0xE2), 8 Volume Down (0xEA), 9 Volume Up (0xE9), 10 Power (0x30), 11 **usage 0x307**, 12 **usage 0x308**. The last two are not defined in hid-tools' HUT tables.

**[HYPOTHESIS]** This is the generic JieLi SDK "HID key" template. Its common use is a *camera-shutter* function, where Volume Up triggers a phone's camera. The descriptor only proves what the device **can** send, not which buttons actually map to which bit.

## 14. Unusual or undocumented findings

1. The headset **accepts and then immediately tears down host‑initiated HID**: Ctrl and Intr are disconnected 25–29 ms after opening (Frames 216, 222). About 5 s later it **initiates its own HID connections** (Frames 537, 541, 559, 563), two per PSM. The HID record sets ReconnectInitiate = true. BlueZ refused them all, one "security block" after about 40 s (Frame 2561).
2. The headset's AVRCP **TG advertises EVENT_BATT_STATUS_CHANGED (0x06)**, which is uncommon on a sink. The host never registered it.
3. The headset TG also lists EVENT_PLAYBACK_STATUS_CHANGED (0x01). A headset TG reporting play status is unusual. It was never registered.
4. The headset sends `AT+CGMI?` (Frame 192 / #181), a *read-form* manufacturer query that HFP does not define. The host answered `+CME ERROR: 1`. **[HYPOTHESIS]** The firmware probes the AG's identity.
5. The headset sends `AT+CHLD=?` and `AT+NREC=0` even though the AG's `+BRSF: 3680` does not advertise 3‑way calling or EC/NR. Both got an error (Frames 151, 190). The firmware ignores AG feature bits.
6. The placeholder XAPL IDs `ABCD-1234-0100`.
7. SDP record‑handle **gaps**: records 0x10001–0x10006, 0x1000A and 0x10011 exist. 0x10007–0x10009 and 0x1000B–0x10010 were not returned by either search. **[HYPOTHESIS]** They are disabled SDK services or records without L2CAP in their protocol list. Worth probing (H‑9).
8. There are **two A2DP sink SEPs** (SEID 1 and SEID 2, Frame 137 / #126 raw `52 01 04 08 08 08`). The host skipped Get(All)Capabilities (BlueZ used cached capabilities) and configured SEID 1 = SBC directly. **The codec of SEID 2 is unknown.** [HYPOTHESIS] It is AAC or a second SBC endpoint.
9. SBC config (Frame 140 / #129 raw `60 03 04 24 01 00 07 06 00 00 11 15 02 26`): 48 kHz, Joint Stereo, 16 blocks, 8 subbands, Loudness, bitpool 2–**38**. Media on CID 0x006E: 1112 × 640‑byte ACL frames, RTP PT 96, SSRC 1, SBC header `9c fd 26`, 7 frames per packet (89‑byte frames), timestamp +896 per packet.
10. The headset requests **sniff at 500 ms** after about 10–12 s idle (Frames 944, 2571). No HCI Sniff Mode command was issued by the host, so sniff was initiated remotely or autonomously by the controller. This is what delays button releases.
11. The link uses **legacy E0 encryption**. The headset lacks Secure Connections.
12. The headset CT asks for all metadata (GetElementAttributes with count 0) twice, but it declares no display features.

## 15. Direction / origin summary

| Originates at headset (RX) | Originates at host (TX) |
|---|---|
| All passthrough (PLAY/PAUSE) commands | Paging / Create Connection, authentication, encryption |
| GetCapabilities #188, GetElementAttributes ×2, RegisterNotification 0x01/0x02 | All SDP requests; all L2CAP connects of session 2 except HID |
| VOLUME_CHANGED interims/changes (the headset is the volume authority) | GetCapabilities #191, RegisterNotification VOLUME ×3 |
| All HFP `AT…` commands (headset = HF) | All HFP `+…`/`OK`/`ERROR` results (host = AG) |
| Battery (`AT+IPHONEACCEV`) | AVDTP Discover/SetConfig/Open/Start/Suspend (host = SRC/INT) and all A2DP media |
| HID L2CAP connects at 15:02:33; HID disconnects at 15:02:28.36 | Session‑1 teardown (15:02:14) |
| ACL disconnect reason 0x13 (15:02:14.791) | |
| Sniff mode entries | Exit sniff commands |

## 16. Chronological reconstruction

| Time | Frame / # | Event |
|---|---|---|
| 15:02:03.154 | 1–7 | btmon starts. hci0 = Intel AC:7B:A1:2B:6E:A6. bluetoothctl and bluetoothd attached to mgmt. |
| 15:02:08.560 | 8 / #1 | Existing link (handle 256) enters sniff at 500 ms. |
| 15:02:14.235–.636 | 9–35 | **Host disconnects** session 1: AVCTP, then AVDTP CLOSE, RFCOMM DISC, and the L2CAP channels. |
| 15:02:14.791 | 36 / #29 | ACL down, reason 0x13 (remote user terminated). |
| 15:02:25.205 | 40 / #32 | **Host reconnects**: Create Connection to 28:52:E0:0F:92:0A. |
| 15:02:28.094 | 43 / #35 | Connected, handle 256, then remote features and name ("oraimo Necklace Lite"). |
| 15:02:28.113–.140 | 60–73 | SDP search for HFP → RFCOMM ch 4. |
| 15:02:28.141–.222 | 74–84 | Authenticate with the stored link key (Frame 77 ⚠️), then E0 encryption with a 16‑byte key. |
| 15:02:28.223–.384 | 85–254 | RFCOMM/HFP SLC: BRSF 671/3680, BAC 1,2, CIND, CMER, BCS mSBC(2), CLIP, CCWA, NREC(err), CGMI?(err), VGS=15, VGM=15, XAPL, IPHONEACCEV battery 6. |
| 15:02:28.279–.324 | 115–158 | AVDTP: Discover (SEID 1, 2 SNK), SetConfig SBC 48k, Open, media channel. |
| 15:02:28.339–.368 | 173–222 | HID Ctrl/Intr opened by host and closed by headset. AVCTP opened. |
| 15:02:28.355–.381 | 199–246 | AVRCP: capability exchange, GetElementAttributes, registrations, volume INTERIM 127. |
| 15:02:28.366–.432 | 219–264 | Full SDP browse (L2CAP UUID) + PnP record. |
| 15:02:30.752 | 265 | SDP channel closed. |
| 15:02:30.822 | 268 / #257 | **AVDTP START**. Streaming until 15:02:36.78. |
| 15:02:33.355–.385 | 537–568 | **Headset‑initiated HID** connects (×4); BlueZ refuses them. |
| 15:02:36.776 | 937 / #923 | AVDTP SUSPEND. |
| 15:02:44.203 | 941 / #927 | Battery → 5. |
| 15:02:46.523 | 944 / #930 | Sniff. |
| 15:02:49.861 | 945 / #931 | **AVDTP START** (2nd stream). |
| 15:02:54.219 | 1371 / #1357 | Battery → 6. |
| 15:03:03.680/.699 | 2388–2394 | **PLAY press/release** (during streaming). |
| 15:03:05.156 | 2551 / #2537 | AVDTP SUSPEND (the host paused). |
| 15:03:12.060/.070 | 2555–2559 | **PLAY press/release**. No AVDTP START follows. |
| 15:03:13.645 | 2561 | Pending HID Intr refused (security block). |
| 15:03:14.728 | 2563 | **Volume CHANGED 127→120** (headset‑originated). |
| 15:03:15.915 | 2567 | **Volume CHANGED 120→127**. |
| 15:03:17.280 | 2571 | Sniff. |
| 15:03:17.770 / 18.271 | 2572–2579 | **PAUSE press / release** (release delayed by sniff). |
| 15:03:19.029/.035 | 2581–2585 | **PLAY press/release**. End of capture. |

## 17. Safe to reproduce for interoperability testing

These are all standard and spec‑conformant, and they appear verbatim in the capture:

* **Host TG responses:** ACCEPTED to passthrough, STABLE to GetCapabilities and GetElementAttributes, INTERIM/CHANGED for events 0x01 and 0x02. Sending a real **CHANGED PLAYING/PAUSED** to the headset is safe and should fix its play/pause decision logic.
* **Host CT commands:** GetCapabilities(0x03 events), RegisterNotification(0x0D).
* **Standard extras not observed but implied by the SDP/feature bits:** GetCapabilities(0x02 CompanyID), RegisterNotification(0x06 battery) and (0x01), and SetAbsoluteVolume (PDU 0x50, 0–127).
* **AVDTP:** Start and Suspend.
* **HFP:** unsolicited `+VGS: n` / `+VGM: n`; answering AT+XAPL and IPHONEACCEV.

## 18. Might control additional functionality

* The **HID Consumer Control** interface (Report IDs 2/3) is **input only**, from device to host. Enabling it may expose more button gestures, such as next/prev/vol/home/search, as keyboard events. The capture shows no evidence of *which* gestures use it.
* **AVRCP TG events 0x06 / 0x01 on the headset** may give battery/status push notifications.
* **SetAbsoluteVolume** can control the headset's volume from the host.
* **SPP RFCOMM ch 10 (custom UUID) and ch 1** are the only plausible path to "hidden" vendor features (EQ, prompts, key remap, firmware). They are *not observable in this capture*. Firmware‑update commands could brick the device, so passive observation should come first.
* A2DP **SEID 2** is an alternate codec endpoint.

## 19. Is there enough for a custom Linux controller?

**For the standard surface: yes.** The capture fully specifies how the necklace delivers PLAY/PAUSE (AVRCP passthrough), volume (absolute‑volume notifications) and battery (HFP IPHONEACCEV). You can build a controller with no raw packet code at all:

* Button events can be read from BlueZ's AVRCP uinput device with `evtest`/evdev (KEY_PLAYCD, KEY_PAUSECD, …). An alternative is to register an MPRIS player (`mpris-proxy` or your own) so BlueZ forwards commands and sends proper PLAYBACK_STATUS CHANGED notifications.
* Volume can be read and set through the `org.bluez.MediaTransport1.Volume` D‑Bus property.
* Battery is available through `org.bluez.Battery1`, which PipeWire populates from IPHONEACCEV.

**For vendor features: no.** The capture contains no proprietary control traffic. The JieLi SPP channel exists, but its protocol is not in the file. You need a capture of the official oraimo app talking to the device, for example an Android HCI snoop log.

## 20. Byte-level templates

```
AVCTP (L2CAP PSM 0x0017, on the existing AVCTP channel)
 byte0      : (label<<4) | (pkt_type 00<<2) | (C/R<<1) | IPID      cmd: L0, rsp: L2
 byte1-2    : 11 0E                                                (PID = AVRCP)
AV/C
 byte3      : ctype/resp  00 CONTROL, 01 STATUS, 03 NOTIFY | 09 ACCEPTED, 0C STABLE, 0D CHANGED, 0F INTERIM
 byte4      : 48  (Panel subunit, id 0)
 byte5      : opcode  7C PASSTHROUGH | 00 VENDOR DEPENDENT

PASSTHROUGH: [hdr] 00 48 7C <state<<7 | op_id> 00
   PLAY  press  L0 11 0E 00 48 7C 44 00      release  … 7C C4 00
   PAUSE press  L0 11 0E 00 48 7C 46 00      release  … 7C C6 00
   (NEXT 4B / PREV 4C / VOL+ 41 / VOL- 42 / STOP 45 : not observed)

VENDOR DEPENDENT: [hdr] <ctype> 48 00  00 19 58  <PDU> 00 <len_hi len_lo> <params>
   GetCapabilities(events):   L0 11 0E 01 48 00 00 19 58 10 00 00 01 03
   GetCapabilities(company):  L0 11 0E 01 48 00 00 19 58 10 00 00 01 02      (not observed)
   RegisterNotification(ev):  L0 11 0E 03 48 00 00 19 58 31 00 00 05 <ev> 00 00 00 00
   Volume INTERIM/CHANGED:    L2 11 0E 0F|0D 48 00 00 19 58 31 00 00 02 0D <vol 0-7F>
   PlayStatus CHANGED (host): L2 11 0E 0D 48 00 00 19 58 31 00 00 02 01 <00 stop|01 play|02 pause>
   SetAbsoluteVolume:         L0 11 0E 00 48 00 00 19 58 50 00 00 01 <vol>    (not observed)

HFP battery (RFCOMM DLCI 8 UIH): 21 EF 2B "AT+IPHONEACCEV=1,1,<0-9>\r" 80
```

---

## A. Device fingerprint

| Field | Value |
|---|---|
| Name | oraimo Necklace Lite |
| BD_ADDR | 28:52:E0:0F:92:0A (OUI Layon International Electronic & Telecom) |
| Chip/SDK | Zhuhai JieLi (PnP VID 0x05D6 src SIG, PID 0x000A, ver 0x0240; `JL_*` service names) |
| BT | BR/EDR 2 Mbps EDR, LE-capable controller, SSP, **no Secure Connections**, E0 |
| Profiles | A2DP 1.3 sink (2 SEPs, SBC ≤ bitpool 38 @ 48 k), AVRCP 1.5 CT (Cat 1) + TG (Cat 2), HFP 1.8 HF (mSBC), HID 1.0 Consumer Control, SPP ×2 (one with custom UUID fe010000‑1234‑5678‑abcd‑00805f9b34fb, ch 10) |
| Quirks | Apple XAPL (ABCD‑1234‑0100), IPHONEACCEV battery, `AT+CGMI?`, headset‑initiated HID, 500 ms sniff |

## B. Bluetooth architecture

```
Linux host (Intel hci0, BlueZ + PipeWire AG)          oraimo Necklace Lite (JieLi)
 ACL handle 0x0100, host = central, E0 encryption
 ├─ PSM 1   SDP            0x0040 ↔ 0x006B  (closed after browse)
 ├─ PSM 3   RFCOMM         0x0041 ↔ 0x006C ── DLCI 8 = HFP (AG ↔ HF), battery via IPHONEACCEV
 ├─ PSM 25  AVDTP sig      0x0042 ↔ 0x006D   SRC(INT SEID 9) → SNK SEID 1
 ├─ PSM 25  AVDTP media    0x0043 ↔ 0x006E   SBC 48k JS bitpool 38 (TX only)
 ├─ PSM 23  AVCTP control  0x0045 ↔ 0x0070   AVRCP both directions (no browsing)
 ├─ PSM 17/19 HID          never established (torn down / refused)
 └─ RFCOMM ch 1 / ch 10 SPP   advertised, never opened
```

## C. AVRCP command inventory

**Headset → Host**

| Command | Occurrences |
|---|---|
| PASSTHROUGH PLAY 0x44/0xC4 | ×3 press/release pairs |
| PASSTHROUGH PAUSE 0x46/0xC6 | ×1 pair |
| GetCapabilities(Events) | ×1 |
| GetElementAttributes(all) | ×2 |
| RegisterNotification 0x01 | ×1 |
| RegisterNotification 0x02 | ×1 |

**Host → Headset**

| Command | Occurrences |
|---|---|
| GetCapabilities(Events) | ×1 |
| RegisterNotification 0x0D | ×3 |

**Responses:** ACCEPTED ×8, STABLE ×4, INTERIM ×5, CHANGED ×2. Total: 17 commands + 19 responses = 36 AVCTP frames.

## D. Vendor-specific inventory

* **AVRCP:** none. Company ID 0x001958 is the Bluetooth SIG.
* **HFP:** Apple `AT+XAPL`, `AT+IPHONEACCEV`.
* **SDP:** JieLi `JL_*` names, the custom SPP UUID on ch 10, and the HID "hid key" descriptor containing usages 0x307/0x308.
* **HCI:** Intel PTT switch vendor event.

## E. Interesting undocumented findings

See §14. The most useful five:

1. The event list you asked about (TRACK_REACHED_END and the others) belongs to BlueZ, not the headset.
2. The headset TG offers BATT_STATUS_CHANGED.
3. Volume keys work through absolute‑volume notifications, not passthrough [hypothesis on cause].
4. A hidden HID Consumer‑Control interface that BlueZ refused.
5. A JieLi custom SPP service on RFCOMM ch 10.

## F. What can realistically be controlled

**Read from the device:**

* PLAY/PAUSE button events
* Volume level (0–127)
* Battery level (0–9 via HFP; possibly via AVRCP event 0x06)
* After enabling HID: consumer keys

**Write to the device:**

* Absolute volume (AVRCP)
* HFP speaker/mic gain
* Stream start/suspend and codec selection
* Playback-status/track notifications that influence the headset's button logic

## G. Not yet determined

* Whether NEXT, PREVIOUS, STOP or VOLUME passthroughs exist. Only single presses of one button were captured.
* What double, triple and long presses do.
* Which HID bits the firmware actually uses, and what usages 0x307/0x308 mean on this device.
* The codec of SEID 2.
* The protocol on SPP ch 10 / ch 1, and whether EQ, ANC, prompts or remapping exist.
* Whether the device advertises BLE/GATT. The controller is LE‑capable, but no LE traffic was captured.
* SDP records 0x10007–0x10009 and 0x1000B–0x10010.
* Exact firmware and SoC version.
* The logic behind the PLAY-vs-PAUSE choice.

## H. Ten experiments on Linux

Run `sudo btmon -w run_N.btsnoop` during each experiment and note wall‑clock times for every physical action.

1. **Button gesture matrix.** Separately perform single, double, triple, long (2 s), very‑long (5 s) and hold‑while‑streaming presses, in both the idle and streaming states. Note any volume‑key presses separately. In parallel, run `sudo evtest` on the AVRCP input device (`grep -A4 -i avrcp /proc/bus/input/devices`). Look for passthrough 0x4B/0x4C/0x41/0x42/0x45 and VOLUME_CHANGED.
2. **Enable the HID interface.** Run `bluetoothctl trust 28:52:E0:0F:92:0A`. Make sure the input plugin allows it: `/etc/bluetooth/input.conf` → `UserspaceHID=true` and, if needed, `ClassicBondedOnly=false`. Reconnect and let the headset open PSM 17/19 itself. Then run `sudo hid-recorder` on the new hidraw device and repeat experiment 1 to map gestures to report IDs 2/3 and bits 0–12 (including 0x307/0x308).
3. **Fix the play-status feedback.** Run `mpris-proxy` (or any MPRIS player) so BlueZ sends real PLAYBACK_STATUS CHANGED to the headset. Repeat the button test and check whether the headset now alternates PLAY/PAUSE deterministically.
4. **Get SEID 2's codec.** Stop bluetoothd, then delete the `[Endpoints]` cache for this device under `/var/lib/bluetooth/AC:7B:A1:2B:6E:A6/cache/28:52:E0:0F:92:0A` (back it up first). Restart and reconnect, then capture AVDTP Get(All)Capabilities.
5. **Absolute volume from the host.** Run `bluetoothctl` → `transport.list` → `transport.volume <path> 64`, or set `MediaTransport1.Volume` over D‑Bus. Confirm that the headset accepts SetAbsoluteVolume (PDU 0x50) and check its step granularity.
6. **Query the headset TG directly.** Run bluetoothd with `-P avrcp` (the avrcp plugin disabled) so you can own PSM 23. With a Python `AF_BLUETOOTH/SOCK_SEQPACKET/BTPROTO_L2CAP` socket to `(addr, 0x17)` (security level medium), send:
   * GetCapabilities(CompanyID): `00 11 0e 01 48 00 00 19 58 10 00 00 01 02`
   * RegisterNotification(0x06 battery): `10 11 0e 03 48 00 00 19 58 31 00 00 05 06 00 00 00 00`
   * RegisterNotification(0x01): `20 11 0e 03 48 00 00 19 58 31 00 00 05 01 00 00 00 00`

   Log the responses.
7. **Probe for undiscovered vendor AVRCP (read-only).** On the same raw channel, send UNIT INFO (`… 01 ff 30 ff ff ff ff ff`) and SUBUNIT INFO (`… 01 ff 31 07 ff ff ff ff`). Then send a GetCapabilities(CompanyID) and check whether any non‑SIG company ID is returned. If one is, send only STATUS‑type vendor frames using it. Avoid CONTROL‑type frames.
8. **Passive SPP observation.** `sdptool browse --raw 28:52:E0:0F:92:0A` and `sdptool records` confirm channels 1 and 10. Then open RFCOMM ch 10 and ch 1, for example with `python3 -c 'import socket;s=socket.socket(31,1,3);s.connect(("28:52:E0:0F:92:0A",10));print(s.recv(1024))'`, and **only listen**. Also capture the official oraimo/JieLi companion app on Android, with *Developer options → Bluetooth HCI snoop log* enabled, while toggling every app setting. That capture is how you get the real vendor command set. Don't send guessed bytes, because an OTA/erase command could brick the device.
9. **Enumerate the missing SDP records.** `sdptool get --raw 0x10007 28:52:E0:0F:92:0A` … through `0x10010` (or a ServiceAttribute request per handle), to see whether hidden services exist.
10. **LE side and version.** Run `sudo btmgmt find -l` / `bluetoothctl scan le` with the necklace in pairing mode and on, to see whether it advertises BLE (JieLi devices often expose a GATT control service). Run `hcitool info 28:52:E0:0F:92:0A` for the LMP version, manufacturer and subversion (firmware fingerprint). Also test HFP: start a call with `pw-cli` or `ofono-phonesim`, and capture which gestures produce `AT+BVRA`, `ATA`, `AT+CHUP` or `AT+BLDN`. Those are extra button functions that only appear in call context.
